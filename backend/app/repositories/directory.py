"""Uebergreifende Listenabfragen ueber ``radcheck`` und ``mgr_subject``.

Bewusst ausserhalb von ``repositories/radius`` und ``repositories/mgr``: Die
Listenansichten fuer Benutzer und Geraete brauchen beide Seiten in einer Abfrage,
weil ein Benutzer auch ohne Manager-Metadaten existieren kann (z. B. aus einer
Altinstallation) und umgekehrt Metadaten vor dem Anlegen der Credentials
entstehen koennen.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import ColumnElement, and_, exists, func, or_, select, union
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Subquery

from app.core.errors import ValidationError
from app.models.mgr import MgrSubject, SubjectType
from app.models.radius import RadCheck, RadReply, RadUserGroup

AUTH_TYPE = "Auth-Type"
REJECT = "Reject"


@dataclass(slots=True)
class SubjectFilter:
    search: str | None = None
    group: str | None = None
    subject_type: SubjectType | None = None
    owner: str | None = None
    location: str | None = None
    device_type: str | None = None
    disabled: bool | None = None
    expiring_before: dt.datetime | None = None


@dataclass(slots=True)
class SubjectRow:
    username: str
    subject: MgrSubject | None


class DirectoryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def _base(self, flt: SubjectFilter) -> tuple[Subquery, list[ColumnElement[bool]]]:
        # Ein Bestandsdatensatz kann auch nur Antwortattribute oder eine
        # Gruppenzuordnung besitzen. Wer per Direktaufruf sichtbar ist, muss
        # ebenso in Liste, Export und Sammelaktionen auftauchen.
        names = union(
            select(RadCheck.username.label("username")),
            select(RadReply.username.label("username")),
            select(RadUserGroup.username.label("username")),
            select(MgrSubject.username.label("username")),
        ).subquery("names")

        conditions: list[ColumnElement[bool]] = [names.c.username != ""]

        if flt.subject_type is SubjectType.DEVICE:
            conditions.append(MgrSubject.subject_type == SubjectType.DEVICE)
        elif flt.subject_type is SubjectType.USER:
            conditions.append(
                or_(
                    MgrSubject.subject_type == SubjectType.USER,
                    MgrSubject.id.is_(None),
                )
            )

        if flt.search:
            pattern = f"%{flt.search}%"
            conditions.append(
                or_(
                    names.c.username.like(pattern),
                    MgrSubject.note.like(pattern),
                    MgrSubject.display_name.like(pattern),
                    MgrSubject.owner.like(pattern),
                    MgrSubject.inventory_no.like(pattern),
                    MgrSubject.location.like(pattern),
                )
            )
        if flt.owner:
            conditions.append(MgrSubject.owner == flt.owner)
        if flt.location:
            conditions.append(MgrSubject.location == flt.location)
        if flt.device_type:
            conditions.append(MgrSubject.device_type == flt.device_type)
        if flt.disabled is not None:
            # Massgeblich ist der Zustand in radcheck, nicht die Manager-Notiz:
            # Bestandsbenutzer ohne mgr_subject und direkt in der Datenbank
            # geaenderte Eintraege wuerden sonst falsch einsortiert - und eine
            # Sammelaktion traefe Objekte ausserhalb der angezeigten Menge.
            blocked = exists(
                select(RadCheck.id).where(
                    RadCheck.username == names.c.username,
                    RadCheck.attribute == AUTH_TYPE,
                    RadCheck.value == REJECT,
                )
            )
            conditions.append(blocked if flt.disabled else ~blocked)
        if flt.expiring_before:
            conditions.append(
                and_(
                    MgrSubject.expires_at.is_not(None),
                    MgrSubject.expires_at <= flt.expiring_before,
                )
            )
        if flt.group:
            conditions.append(
                exists(
                    select(RadUserGroup.username).where(
                        RadUserGroup.username == names.c.username,
                        RadUserGroup.groupname == flt.group,
                    )
                )
            )
        return names, conditions

    async def search(
        self, flt: SubjectFilter, limit: int = 50, offset: int = 0
    ) -> tuple[list[SubjectRow], int]:
        names, conditions = self._base(flt)
        join = names.join(MgrSubject, MgrSubject.username == names.c.username, isouter=True)

        stmt = (
            select(names.c.username, MgrSubject)
            .select_from(join)
            .where(*conditions)
            .order_by(names.c.username)
            .limit(limit)
            .offset(offset)
        )
        rows = (await self.session.execute(stmt)).all()

        count_stmt = select(func.count()).select_from(join).where(*conditions)
        total = int(await self.session.scalar(count_stmt) or 0)
        return [SubjectRow(username=str(u), subject=s) for u, s in rows], total

    async def all_usernames(self, flt: SubjectFilter, cap: int = 10_000) -> list[str]:
        """Fuer Bulk-Aktionen und Export auf Basis der aktuellen Filter (FR-8).

        Ueberschreitet die Filtermenge ``cap``, wird abgebrochen statt
        stillschweigend gekuerzt: sonst meldete eine Sammelaktion Erfolg,
        obwohl sie nur einen Teil der bestaetigten Objekte erfasst hat (NFR-4).
        """
        names, conditions = self._base(flt)
        join = names.join(MgrSubject, MgrSubject.username == names.c.username, isouter=True)
        stmt = (
            select(names.c.username)
            .select_from(join)
            .where(*conditions)
            .order_by(names.c.username)
            .limit(cap + 1)
        )
        rows = [str(row) for row in (await self.session.scalars(stmt)).all()]
        if len(rows) > cap:
            raise ValidationError(code="error.selection_too_large", details={"cap": cap})
        return rows

    async def distinct_values(self, column: str) -> list[str]:
        """Filtervorschlaege fuer Standort, Gerätetyp und Verantwortliche."""
        mapping = {
            "owner": MgrSubject.owner,
            "location": MgrSubject.location,
            "device_type": MgrSubject.device_type,
        }
        target = mapping.get(column)
        if target is None:
            return []
        rows = await self.session.scalars(
            select(target).where(target.is_not(None), target != "").distinct().limit(200)
        )
        return sorted(str(r) for r in rows.all())
