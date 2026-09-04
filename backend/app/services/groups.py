"""Gruppen und Attribute (FR-2).

Neben dem Expertenmodus fuer beliebige Tripel gibt es den gefuehrten Weg fuer
die haeufigste Aufgabe: die VLAN-Zuweisung.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.locking import named_lock
from app.core.security import Principal
from app.repositories.mgr.subjects import SubjectRepository
from app.repositories.radius.groups import GroupRepository
from app.repositories.radius.users import UserAttributeRepository
from app.schemas.common import ApiWarning
from app.schemas.groups import (
    GroupCreate,
    GroupDetail,
    GroupListItem,
    GroupUpdate,
    MembershipChange,
)
from app.schemas.users import AttributeIn
from app.services.attributes import validate_triple, vlan_triples
from app.services.audit import AuditService
from app.services.masking import is_masked, mask_attributes

VLAN_ATTRIBUTE = "tunnel-private-group-id"


class GroupService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = GroupRepository(session)
        self.attrs = UserAttributeRepository(session)
        self.subjects = SubjectRepository(session)
        self.audit = AuditService(session)

    async def search(self, query: str | None = None) -> list[GroupListItem]:
        names = await self.repo.group_names()
        if query:
            needle = query.lower()
            names = [n for n in names if needle in n.lower()]
        counts = await self.repo.member_counts()
        replies_by_group = await self.repo.reply_attributes_for(names)
        items: list[GroupListItem] = []
        for name in names:
            vlan = next(
                (
                    r.value
                    for r in replies_by_group.get(name, [])
                    if r.attribute.lower() == VLAN_ATTRIBUTE
                ),
                None,
            )
            items.append(GroupListItem(groupname=name, members=counts.get(name, 0), vlan=vlan))
        return items

    async def get(self, groupname: str) -> GroupDetail:
        if not await self.repo.exists(groupname):
            raise NotFoundError(code="error.not_found", details={"groupname": groupname})
        checks = await self.repo.check_attributes(groupname)
        replies = await self.repo.reply_attributes(groupname)
        vlan = next((r.value for r in replies if r.attribute.lower() == VLAN_ATTRIBUTE), None)
        return GroupDetail(
            groupname=groupname,
            members=await self.repo.member_count(groupname),
            vlan=vlan,
            # Der Expertenmodus laesst auch Passwort-Attribute zu; sie duerfen
            # ebenso wenig im Klartext ausgeliefert werden wie bei Benutzern.
            check_attributes=mask_attributes(checks),
            reply_attributes=mask_attributes(replies),
        )

    async def create(
        self,
        payload: GroupCreate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> GroupDetail:
        # Die RADIUS-Gruppentabellen kennen keine Eindeutigkeit ueber den Namen.
        # Ohne diese benannte Sperre koennten zwei gleichzeitige Anlagen beide
        # die Existenzpruefung passieren und doppelte Attribute hinterlassen.
        async with named_lock(self.session, f"group:{payload.groupname}"):
            return await self._create_locked(
                payload, actor=actor, actor_ip=actor_ip, language=language
            )

    async def _create_locked(
        self,
        payload: GroupCreate,
        *,
        actor: Principal,
        actor_ip: str | None,
        language: str,
    ) -> GroupDetail:
        if await self.repo.exists(payload.groupname):
            raise ConflictError(code="error.group_exists", details={"groupname": payload.groupname})
        if not payload.vlan and not payload.check_attributes and not payload.reply_attributes:
            # Ohne Attribut entstuende keine einzige Zeile in den RADIUS-Tabellen;
            # die Gruppe waere anschliessend nicht auffindbar (das anschliessende
            # get() liefe in ein 404, obwohl der Audit-Eintrag Erfolg meldete).
            raise ValidationError(
                code="error.group_empty", details={"groupname": payload.groupname}
            )
        warnings = await self._write_attributes(
            payload.groupname,
            vlan=payload.vlan,
            clear_vlan=payload.clear_vlan,
            checks=payload.check_attributes,
            replies=payload.reply_attributes,
            language=language,
        )
        await self.audit.log(
            action="group.create",
            object_type="group",
            object_id=payload.groupname,
            actor=actor,
            actor_ip=actor_ip,
            after=payload.model_dump(mode="json"),
        )
        await self.session.commit()
        detail = await self.get(payload.groupname)
        detail.warnings = warnings
        return detail

    async def update(
        self,
        groupname: str,
        payload: GroupUpdate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> GroupDetail:
        if payload.groupname and payload.groupname != groupname:
            # Die Sperre umschliesst Pruefung *und* Commit: gaebe man sie vorher
            # frei, saehe die naechste Anfrage den noch nicht festgeschriebenen
            # Zielnamen nicht und schriebe ihn ein zweites Mal.
            async with named_lock(self.session, f"group:{payload.groupname}"):
                return await self._update_locked(
                    groupname, payload, actor=actor, actor_ip=actor_ip, language=language
                )
        return await self._update_locked(
            groupname, payload, actor=actor, actor_ip=actor_ip, language=language
        )

    async def _update_locked(
        self,
        groupname: str,
        payload: GroupUpdate,
        *,
        actor: Principal,
        actor_ip: str | None,
        language: str,
    ) -> GroupDetail:
        before = await self.get(groupname)
        if payload.groupname and payload.groupname != groupname:
            if await self.repo.exists(payload.groupname):
                raise ConflictError(
                    code="error.group_exists", details={"groupname": payload.groupname}
                )
            await self.repo.rename_group(groupname, payload.groupname)
            groupname = payload.groupname

        # Jede Sammlung wird einzeln betrachtet: eine ausgelassene bleibt
        # unveraendert, statt beim Setzen der anderen mitgeloescht zu werden.
        warnings = await self._write_attributes(
            groupname,
            vlan=payload.vlan,
            clear_vlan=payload.clear_vlan,
            checks=payload.check_attributes,
            replies=payload.reply_attributes,
            language=language,
        )
        await self.audit.log(
            action="group.update",
            object_type="group",
            object_id=groupname,
            actor=actor,
            actor_ip=actor_ip,
            before=before.model_dump(mode="json"),
            after=payload.model_dump(mode="json", exclude_unset=True),
        )
        await self.session.commit()
        detail = await self.get(groupname)
        detail.warnings = warnings
        return detail

    async def delete(
        self, groupname: str, *, actor: Principal, actor_ip: str | None = None, force: bool = False
    ) -> int:
        if not await self.repo.exists(groupname):
            # Sonst meldete ein veralteter Aufruf Erfolg und schriebe einen
            # Audit-Eintrag fuer ein Objekt, das es nie gab.
            raise NotFoundError(code="error.not_found", details={"groupname": groupname})
        members = await self.repo.member_count(groupname)
        if members and not force:
            raise ValidationError(
                code="error.validation",
                details={"groupname": groupname, "members": members, "hint": "force"},
            )
        # Vollstaendiger Zustand vor dem Loeschen; danach waere die geloeschte
        # Konfiguration nicht mehr rekonstruierbar (FR-9).
        before = (await self.get(groupname)).model_dump(mode="json")
        await self.repo.delete_group(groupname)
        await self.audit.log(
            action="group.delete",
            object_type="group",
            object_id=groupname,
            actor=actor,
            actor_ip=actor_ip,
            before=before,
        )
        await self.session.commit()
        return members

    async def members(self, groupname: str, limit: int = 50, offset: int = 0) -> list[str]:
        return await self.repo.members(groupname, limit=limit, offset=offset)

    async def change_membership(
        self,
        groupname: str,
        payload: MembershipChange,
        *,
        actor: Principal,
        actor_ip: str | None = None,
    ) -> int:
        if payload.action == "add":
            # Die Sperre umschliesst Pruefung *und* Commit: sonst saehe die
            # naechste Anfrage die noch nicht festgeschriebene Zeile nicht und
            # legte eine zweite an (radusergroup kennt keine Eindeutigkeit).
            async with named_lock(self.session, f"members:{groupname}"):
                return await self._change_membership_locked(
                    groupname, payload, actor=actor, actor_ip=actor_ip
                )
        return await self._change_membership_locked(
            groupname, payload, actor=actor, actor_ip=actor_ip
        )

    async def _change_membership_locked(
        self,
        groupname: str,
        payload: MembershipChange,
        *,
        actor: Principal,
        actor_ip: str | None,
    ) -> int:
        if payload.action == "add" and not await self.repo.exists(groupname):
            raise NotFoundError(code="error.not_found", details={"groupname": groupname})

        changed = 0
        for username in payload.usernames:
            if payload.action == "add":
                # Das RADIUS-Schema kennt keine Fremdschluessel: ohne diese
                # Pruefung entstuende aus einem Tippfehler ein Phantom-Benutzer,
                # der anschliessend in allen Listen auftaucht.
                if not await self.attrs.exists_anywhere(username) and not await self.subjects.get(
                    username
                ):
                    raise NotFoundError(code="error.not_found", details={"username": username})
                changed += int(
                    await self.repo.add_membership(username, groupname, payload.priority)
                )
            else:
                changed += await self.repo.remove_membership(username, groupname)
        await self.audit.log(
            action=f"group.member_{payload.action}",
            object_type="group",
            object_id=groupname,
            actor=actor,
            actor_ip=actor_ip,
            after={"usernames": payload.usernames, "changed": changed},
        )
        await self.session.commit()
        return changed

    async def _write_attributes(
        self,
        groupname: str,
        *,
        vlan: str | None,
        clear_vlan: bool,
        checks: list[AttributeIn] | None,
        replies: list[AttributeIn] | None,
        language: str = "de",
    ) -> list[ApiWarning]:
        """Schreibt Check- und Reply-Attribute einer Gruppe.

        ``None`` bedeutet "nicht angefasst" und erhaelt den Bestand; eine leere
        Liste loescht die jeweilige Sammlung bewusst.
        """
        warnings: list[ApiWarning] = []

        def convert(
            items: list[AttributeIn],
            table: str,
            existing: dict[tuple[str, str], str],
        ) -> list[tuple[str, str, str]]:
            rows: list[tuple[str, str, str]] = []
            for item in items:
                if is_masked(item.attribute, item.value):
                    # Der Client hat den maskierten Wert unveraendert
                    # zurueckgeschickt: bestehenden Wert beibehalten.
                    kept = existing.get((item.attribute.lower(), item.op))
                    if kept is None:
                        kept = next(
                            (
                                value
                                for (name, _op), value in existing.items()
                                if name == item.attribute.lower()
                            ),
                            None,
                        )
                    if kept is not None:
                        rows.append((item.attribute, item.op, kept))
                        continue
                for w in validate_triple(
                    item.attribute, item.op, item.value, table=table, language=language
                ):
                    warnings.append(
                        ApiWarning(code=w.code, message=w.message, attribute=w.attribute)
                    )
                rows.append((item.attribute, item.op, item.value))
            return rows

        stored_checks = {
            (r.attribute.lower(), r.op): r.value
            for r in await self.repo.check_attributes(groupname)
        }
        stored_replies = {
            (r.attribute.lower(), r.op): r.value
            for r in await self.repo.reply_attributes(groupname)
        }

        if checks is None:
            check_rows = [
                (r.attribute, r.op, r.value) for r in await self.repo.check_attributes(groupname)
            ]
        else:
            check_rows = convert(checks, "radgroupcheck", stored_checks)

        if replies is None:
            reply_rows = [
                (r.attribute, r.op, r.value) for r in await self.repo.reply_attributes(groupname)
            ]
        else:
            reply_rows = convert(replies, "radgroupreply", stored_replies)

        vlan_names = {"tunnel-type", "tunnel-medium-type", VLAN_ATTRIBUTE}
        if vlan is not None or clear_vlan:
            reply_rows = [r for r in reply_rows if r[0].lower() not in vlan_names]
        if vlan:
            reply_rows.extend((t.attribute, t.op, t.value) for t in vlan_triples(vlan))

        if not check_rows and not reply_rows and not await self.repo.member_count(groupname):
            # Ohne Attribut und ohne Mitglied bliebe keine Zeile uebrig - die
            # Gruppe waere geloescht, obwohl der Aufrufer nur bearbeiten wollte.
            raise ValidationError(code="error.group_empty", details={"groupname": groupname})

        await self.repo.replace_attributes(groupname, check_rows, reply_rows)
        return warnings
