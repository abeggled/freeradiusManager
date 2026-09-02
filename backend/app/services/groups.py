"""Gruppen und Attribute (FR-2).

Neben dem Expertenmodus fuer beliebige Tripel gibt es den gefuehrten Weg fuer
die haeufigste Aufgabe: die VLAN-Zuweisung.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.repositories.radius.groups import GroupRepository
from app.schemas.common import ApiWarning
from app.schemas.groups import (
    GroupCreate,
    GroupDetail,
    GroupListItem,
    GroupUpdate,
    MembershipChange,
)
from app.schemas.users import AttributeOut
from app.services.attributes import validate_triple, vlan_triples
from app.services.audit import AuditService

VLAN_ATTRIBUTE = "tunnel-private-group-id"


class GroupService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = GroupRepository(session)
        self.audit = AuditService(session)

    async def search(self, query: str | None = None) -> list[GroupListItem]:
        names = await self.repo.group_names()
        if query:
            needle = query.lower()
            names = [n for n in names if needle in n.lower()]
        counts = await self.repo.member_counts()
        items: list[GroupListItem] = []
        for name in names:
            replies = await self.repo.reply_attributes(name)
            vlan = next((r.value for r in replies if r.attribute.lower() == VLAN_ATTRIBUTE), None)
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
            check_attributes=[AttributeOut.model_validate(r) for r in checks],
            reply_attributes=[AttributeOut.model_validate(r) for r in replies],
        )

    async def create(
        self,
        payload: GroupCreate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> GroupDetail:
        if await self.repo.exists(payload.groupname):
            raise ConflictError(code="error.group_exists", details={"groupname": payload.groupname})
        warnings = await self._write_attributes(payload, language=language)
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
        before = await self.get(groupname)
        if payload.groupname and payload.groupname != groupname:
            if await self.repo.exists(payload.groupname):
                raise ConflictError(
                    code="error.group_exists", details={"groupname": payload.groupname}
                )
            await self.repo.rename_group(groupname, payload.groupname)
            groupname = payload.groupname

        warnings = await self._write_attributes(
            GroupCreate(
                groupname=groupname,
                vlan=payload.vlan,
                clear_vlan=payload.clear_vlan,
                check_attributes=payload.check_attributes or [],
                reply_attributes=payload.reply_attributes or [],
            ),
            keep_existing=payload.check_attributes is None and payload.reply_attributes is None,
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
        members = await self.repo.member_count(groupname)
        if members and not force:
            raise ValidationError(
                code="error.validation",
                details={"groupname": groupname, "members": members, "hint": "force"},
            )
        await self.repo.delete_group(groupname)
        await self.audit.log(
            action="group.delete",
            object_type="group",
            object_id=groupname,
            actor=actor,
            actor_ip=actor_ip,
            before={"groupname": groupname, "members": members},
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
        changed = 0
        for username in payload.usernames:
            if payload.action == "add":
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
        self, payload: GroupCreate, *, keep_existing: bool = False, language: str = "de"
    ) -> list[ApiWarning]:
        warnings: list[ApiWarning] = []
        if keep_existing:
            checks = [
                (r.attribute, r.op, r.value)
                for r in await self.repo.check_attributes(payload.groupname)
            ]
            replies = [
                (r.attribute, r.op, r.value)
                for r in await self.repo.reply_attributes(payload.groupname)
            ]
        else:
            checks = []
            replies = []
            for item in payload.check_attributes:
                for w in validate_triple(
                    item.attribute, item.op, item.value, table="radgroupcheck", language=language
                ):
                    warnings.append(
                        ApiWarning(code=w.code, message=w.message, attribute=w.attribute)
                    )
                checks.append((item.attribute, item.op, item.value))
            for item in payload.reply_attributes:
                for w in validate_triple(
                    item.attribute, item.op, item.value, table="radgroupreply", language=language
                ):
                    warnings.append(
                        ApiWarning(code=w.code, message=w.message, attribute=w.attribute)
                    )
                replies.append((item.attribute, item.op, item.value))

        vlan_names = {"tunnel-type", "tunnel-medium-type", VLAN_ATTRIBUTE}
        if payload.vlan is not None or payload.clear_vlan:
            replies = [r for r in replies if r[0].lower() not in vlan_names]
        if payload.vlan:
            replies.extend((t.attribute, t.op, t.value) for t in vlan_triples(payload.vlan))

        await self.repo.replace_attributes(payload.groupname, checks, replies)
        return warnings
