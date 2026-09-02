"""Import/Export und Bulk (FR-8) sowie Audit-Log (FR-9)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.mgr import MgrAudit
from app.models.radius import RadCheck, RadUserGroup
from app.repositories.directory import SubjectFilter
from app.schemas.users import BulkAction, UserCreate
from app.services.importexport import ImportExportService
from app.services.users import UserService

pytestmark = pytest.mark.asyncio

USER_CSV = """username,password,groups,vlan,note
anna,geheim123,mitarbeiter,20,Aussendienst
bruno,geheim456,"mitarbeiter,gaeste",,Empfang
,leer,,,
"""

DEVICE_CSV = """mac,device_type,location,vlan
AA-BB-CC-DD-EE-FF,Drucker,Empfang,30
keine-mac,Kamera,Flur,
"""


async def test_dry_run_does_not_write(session, admin_principal) -> None:
    service = ImportExportService(session)
    report = await service.import_csv(USER_CSV, kind="user", dry_run=True, actor=admin_principal)
    assert report.dry_run is True
    assert report.total == 3
    assert report.to_create == 2
    assert report.errors == 1
    assert not (await session.scalars(select(RadCheck))).all()


async def test_import_creates_users_with_groups_and_vlan(session, admin_principal) -> None:
    service = ImportExportService(session)
    report = await service.import_csv(USER_CSV, kind="user", dry_run=False, actor=admin_principal)
    assert report.errors == 1

    detail = await UserService(session).get("anna")
    assert detail.vlan == "20"
    assert detail.groups == ["mitarbeiter"]

    memberships = (
        await session.scalars(select(RadUserGroup).where(RadUserGroup.username == "bruno"))
    ).all()
    assert sorted(m.groupname for m in memberships) == ["gaeste", "mitarbeiter"]


async def test_device_import_reports_invalid_mac(session, admin_principal) -> None:
    report = await ImportExportService(session).import_csv(
        DEVICE_CSV, kind="device", dry_run=False, actor=admin_principal
    )
    assert report.to_create == 1
    assert report.errors == 1
    error_row = next(r for r in report.rows if r.action == "error")
    assert "invalid_mac" in (error_row.message or "")


async def test_export_contains_no_passwords(session, admin_principal) -> None:
    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_principal
    )
    csv_text = await ImportExportService(session).export(SubjectFilter())
    assert "anna" in csv_text
    assert "geheim123" not in csv_text
    assert csv_text.splitlines()[0].startswith("username,subject_type,status")


async def test_bulk_disable_over_filter(session, admin_principal) -> None:
    users = UserService(session)
    for name in ("anna", "bruno", "carla"):
        await users.create(UserCreate(username=name, password="geheim123"), actor=admin_principal)

    requested, succeeded, errors = await ImportExportService(session).bulk(
        BulkAction(action="disable", filter_all=True),
        SubjectFilter(),
        actor=admin_principal,
    )
    assert (requested, succeeded, errors) == (3, 3, [])
    for name in ("anna", "bruno", "carla"):
        assert (await users.get(name)).status == "disabled"


async def test_bulk_assign_group_reports_partial_failures(session, admin_principal) -> None:
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)

    requested, succeeded, errors = await ImportExportService(session).bulk(
        BulkAction(action="delete", usernames=["anna", "gibtsnicht"]),
        SubjectFilter(),
        actor=admin_principal,
    )
    assert requested == 2
    assert succeeded == 1
    assert errors[0]["username"] == "gibtsnicht"


async def test_audit_records_writes_without_secrets(session, admin_principal) -> None:
    await UserService(session).create(
        UserCreate(username="anna", password="streng-geheim"), actor=admin_principal
    )
    entries = (await session.scalars(select(MgrAudit))).all()
    actions = {e.action for e in entries}
    assert "user.create" in actions
    payload = " ".join(e.after_json or "" for e in entries)
    assert "streng-geheim" not in payload
    assert "<geaendert>" in payload


async def test_audit_retention_purge(session, admin_principal) -> None:
    import datetime as dt

    from app.services.audit import AuditService

    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_principal
    )
    entry = (await session.scalars(select(MgrAudit))).first()
    entry.ts = dt.datetime.now() - dt.timedelta(days=1000)
    await session.commit()

    removed = await AuditService(session).purge(retention_days=730)
    await session.commit()
    assert removed == 1
