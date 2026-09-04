"""Auth-Log und Diagnose (FR-6).

Ziel: Der Helpdesk soll die haeufigsten Faelle ohne ``radiusd -X`` loesen.
Die Hinweise werden aus dem Datenbestand abgeleitet und uebersetzt ausgeliefert.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core import radius_dict
from app.core.dates import from_expiration, utcnow
from app.core.i18n import translate
from app.core.mac import is_mac, matches_format
from app.models.mgr import SubjectType
from app.repositories.mgr.subjects import SubjectRepository
from app.repositories.radius.acct import AccountingRepository
from app.repositories.radius.groups import GroupRepository
from app.repositories.radius.nas import NasRepository
from app.repositories.radius.postauth import ACCEPT_VALUES, AuthLogFilter, PostAuthRepository
from app.repositories.radius.users import UserAttributeRepository
from app.schemas.sessions import AuthLogItem, Diagnosis, DiagnosisHint, SessionItem
from app.services.sessions import extract_ssid
from app.services.settings_service import SettingsService


class AuthLogService:
    def __init__(self, session: AsyncSession) -> None:
        self.repo = PostAuthRepository(session)
        self.attrs = UserAttributeRepository(session)
        self.groups = GroupRepository(session)
        self.acct = AccountingRepository(session)
        self.nas = NasRepository(session)
        self.subjects = SubjectRepository(session)
        self.settings = SettingsService(session)

    async def search(
        self, flt: AuthLogFilter, limit: int | None = None, cursor: str | None = None
    ) -> tuple[list[AuthLogItem], str | None]:
        page = await self.repo.search(flt, limit=limit, cursor=cursor)
        items = []
        for row in page.items:
            item = AuthLogItem.model_validate(row)
            item.accepted = row.reply in ACCEPT_VALUES
            items.append(item)
        return items, page.next_cursor

    async def diagnose(self, subject: str, language: str = "de", attempts: int = 20) -> Diagnosis:
        """Erzeugt Klartext-Hinweise zu einem Benutzer oder einer MAC."""
        own_checks = list(await self.attrs.check_attributes(subject))
        replies = list(await self.attrs.reply_attributes(subject))
        memberships = list(await self.groups.memberships(subject))
        # FreeRADIUS wendet auch die Check-Attribute der Gruppen an: ein
        # ``Auth-Type := Reject`` oder ein abgelaufenes ``Expiration`` dort ist
        # der tatsaechliche Grund fuer den Access-Reject. Ohne sie meldete die
        # Diagnose den Benutzer als aktiv und nannte den Grund nicht (FR-6).
        group_checks = [
            row
            for membership in memberships
            for row in await self.groups.check_attributes(membership.groupname)
        ]
        checks = own_checks + group_checks
        recent = await self.repo.recent_for(subject, limit=attempts)
        meta = await self.subjects.get(subject)

        hints: list[DiagnosisHint] = []
        # Wie in der Statusberechnung: bewertet wird, ob *irgendeine* Zeile
        # zutrifft. Bestandsdaten koennen dasselbe Attribut mehrfach fuehren.
        rejected = any(
            row.attribute.lower() == "auth-type" and row.value == "Reject" for row in checks
        )
        expired_row = next(
            (
                row
                for row in checks
                if row.attribute.lower() == "expiration"
                and (parsed := from_expiration(row.value)) is not None
                and parsed < utcnow()
            ),
            None,
        )
        # Eine reine Gruppenzuordnung zaehlt ebenfalls: solche Bestandsnamen
        # sind sichtbar und aufrufbar, die Diagnose darf sie nicht als
        # unbekannt melden.
        exists = bool(own_checks or replies or meta or memberships)
        status = "unknown"

        if not exists:
            hints.append(
                DiagnosisHint(
                    code="diag.user_unknown",
                    message=translate("diag.user_unknown", language, subject=subject),
                    severity="error",
                )
            )
            status = "missing"
        else:
            # Anmeldedaten stehen beim Benutzer selbst; Gruppen fuehren keine.
            has_password = any(
                radius_dict.is_password_attribute(row.attribute) for row in own_checks
            )
            if rejected:
                status = "disabled"
                hints.append(
                    DiagnosisHint(
                        code="diag.auth_type_reject",
                        message=translate("diag.auth_type_reject", language, subject=subject),
                        severity="error",
                    )
                )
            elif expired_row is not None:
                status = "expired"
                hints.append(
                    DiagnosisHint(
                        code="diag.expired",
                        message=translate(
                            "diag.expired", language, subject=subject, expires=expired_row.value
                        ),
                        severity="error",
                    )
                )
            elif not has_password:
                status = "no_credentials"
                hints.append(
                    DiagnosisHint(
                        code="diag.no_credentials",
                        message=translate("diag.no_credentials", language, subject=subject),
                        severity="error",
                    )
                )
            else:
                status = "active"

            if not memberships:
                hints.append(
                    DiagnosisHint(
                        code="diag.no_group",
                        message=translate("diag.no_group", language, subject=subject),
                        severity="info",
                    )
                )

        vlan = next(
            (r.value for r in replies if r.attribute.lower() == "tunnel-private-group-id"), None
        )
        if vlan is None:
            for membership in memberships:
                group_replies = await self.groups.reply_attributes(membership.groupname)
                vlan = next(
                    (
                        r.value
                        for r in group_replies
                        if r.attribute.lower() == "tunnel-private-group-id"
                    ),
                    None,
                )
                if vlan:
                    break
        if vlan is None:
            hints.append(
                DiagnosisHint(
                    code="diag.no_vlan",
                    message=translate("diag.no_vlan", language),
                    severity="warning",
                )
            )

        if (meta is not None and meta.subject_type is SubjectType.DEVICE) or is_mac(subject):
            fmt = await self.settings.mac_format()
            if not matches_format(subject, fmt):
                hints.append(
                    DiagnosisHint(
                        code="diag.mac_format_mismatch",
                        message=translate("diag.mac_format_mismatch", language, expected=fmt),
                        severity="warning",
                    )
                )

        # Bekanntheit des NAS aus der letzten Session pruefen (FR-6).
        last_session_row = await self.acct.last_session(subject)
        if last_session_row is not None:
            # NAS duerfen als Netz eingetragen sein; ein reiner Namensvergleich
            # meldete solche Eintraege faelschlich als unbekannt (FR-4).
            known_nas = await self.nas.find_for_address(last_session_row.nasipaddress)
            if known_nas is None:
                hints.append(
                    DiagnosisHint(
                        code="diag.nas_unknown",
                        message=translate(
                            "diag.nas_unknown", language, nas=last_session_row.nasipaddress
                        ),
                        severity="warning",
                    )
                )

        if not recent:
            hints.append(
                DiagnosisHint(
                    code="diag.no_attempts",
                    message=translate("diag.no_attempts", language, subject=subject),
                    severity="info",
                )
            )
        else:
            rejects = [r for r in recent if r.reply not in ACCEPT_VALUES]
            if len(rejects) == len(recent):
                hints.append(
                    DiagnosisHint(
                        code="diag.recent_rejects",
                        message=translate(
                            "diag.recent_rejects",
                            language,
                            count=len(rejects),
                            last=rejects[0].authdate.isoformat(sep=" ", timespec="seconds"),
                        ),
                        severity="error",
                    )
                )
            elif recent[0].reply in ACCEPT_VALUES:
                hints.append(
                    DiagnosisHint(
                        code="diag.ok",
                        message=translate(
                            "diag.ok",
                            language,
                            last=recent[0].authdate.isoformat(sep=" ", timespec="seconds"),
                        ),
                        severity="success",
                    )
                )

        last_session = None
        if last_session_row is not None:
            last_session = SessionItem.model_validate(last_session_row)
            last_session.active = last_session_row.acctstoptime is None
            last_session.ssid = extract_ssid(last_session_row.calledstationid)
            # Wie in der Sessionliste: ohne den Kurznamen zeigte die Diagnose
            # als einzige Ansicht nur die rohe Adresse.
            last_session.nas_shortname = known_nas.shortname if known_nas is not None else None

        attempt_items = []
        for row in recent:
            item = AuthLogItem.model_validate(row)
            item.accepted = row.reply in ACCEPT_VALUES
            attempt_items.append(item)

        return Diagnosis(
            subject=subject,
            exists=exists,
            status=status,
            hints=hints,
            attempts=attempt_items,
            last_session=last_session,
            groups=[m.groupname for m in memberships],
            vlan=vlan,
        )
