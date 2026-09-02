"""Manager-Benutzerkonten (``mgr_account``)."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mgr import MgrAccount, Role


class AccountRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, account_id: int) -> MgrAccount | None:
        return await self.session.get(MgrAccount, account_id)

    async def get_by_username(self, username: str) -> MgrAccount | None:
        stmt = select(MgrAccount).where(MgrAccount.username == username)
        return await self.session.scalar(stmt)

    async def get_by_oidc_subject(self, subject: str) -> MgrAccount | None:
        stmt = select(MgrAccount).where(MgrAccount.oidc_subject == subject)
        return await self.session.scalar(stmt)

    async def search(
        self, search: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[Sequence[MgrAccount], int]:
        stmt = select(MgrAccount)
        count_stmt = select(func.count()).select_from(MgrAccount)
        if search:
            pattern = f"%{search}%"
            condition = or_(
                MgrAccount.username.like(pattern),
                MgrAccount.email.like(pattern),
                MgrAccount.display_name.like(pattern),
            )
            stmt = stmt.where(condition)
            count_stmt = count_stmt.where(condition)
        stmt = stmt.order_by(MgrAccount.username).limit(limit).offset(offset)
        return (await self.session.scalars(stmt)).all(), int(
            await self.session.scalar(count_stmt) or 0
        )

    async def count_active_administrators(self, exclude_id: int | None = None) -> int:
        stmt = (
            select(func.count())
            .select_from(MgrAccount)
            .where(MgrAccount.role == Role.ADMINISTRATOR, MgrAccount.is_active.is_(True))
        )
        if exclude_id is not None:
            stmt = stmt.where(MgrAccount.id != exclude_id)
        return int(await self.session.scalar(stmt) or 0)

    async def add(self, account: MgrAccount) -> MgrAccount:
        self.session.add(account)
        await self.session.flush()
        return account

    async def delete(self, account: MgrAccount) -> None:
        await self.session.delete(account)
