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

    async def get_by_username(self, username: str, *, lock: bool = False) -> MgrAccount | None:
        """Konto nach Benutzername.

        ``lock=True`` sperrt die Zeile bis zum Ende der Transaktion. Ohne diese
        Sperre koennten gleichzeitige Fehlversuche denselben Zaehlerstand lesen
        und schreiben - die Kontosperre waere nie erreichbar.
        """
        stmt = select(MgrAccount).where(MgrAccount.username == username)
        if lock:
            # Wie in ``get_for_update``: mit dem Sperren auch neu einlesen.
            stmt = stmt.with_for_update().execution_options(populate_existing=True)
        return await self.session.scalar(stmt)

    async def get_for_update(self, account_id: int) -> MgrAccount | None:
        """Sperrt die Zeile und liest sie dabei frisch ein.

        ``populate_existing`` ist noetig: liegt das Objekt bereits in der
        Identity Map - etwa weil ``account_from_challenge`` es zuvor geladen hat -
        gaebe SQLAlchemy den alten Stand zurueck. Der Wartende saehe dann weder
        den fortgeschriebenen Fehlerzaehler noch die Wiedereinsatz-Marke des
        anderen Vorgangs.
        """
        stmt = (
            select(MgrAccount)
            .where(MgrAccount.id == account_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
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

    async def count_active_administrators(
        self, exclude_id: int | None = None, *, lock: bool = False
    ) -> int:
        """Anzahl aktiver Administratoren.

        Mit ``lock=True`` werden die betroffenen Zeilen bis zum Ende der
        Transaktion gesperrt. Zwei gleichzeitige Herabstufungen saehen sonst
        beide noch den jeweils anderen Administrator und die Instanz bliebe
        ohne einen einzigen zurueck.
        """
        stmt = select(MgrAccount.id).where(
            MgrAccount.role == Role.ADMINISTRATOR, MgrAccount.is_active.is_(True)
        )
        if exclude_id is not None:
            stmt = stmt.where(MgrAccount.id != exclude_id)
        if lock:
            stmt = stmt.with_for_update()
        rows = (await self.session.scalars(stmt)).all()
        return len(rows)

    async def add(self, account: MgrAccount) -> MgrAccount:
        self.session.add(account)
        await self.session.flush()
        return account

    async def delete(self, account: MgrAccount) -> None:
        await self.session.delete(account)
