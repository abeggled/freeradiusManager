"""Regressionstests zur zweiten Review-Runde."""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select, text

from app.core.errors import AuthenticationError, ValidationError
from app.models.mgr import MgrAudit
from app.models.radius import RadAcct, RadCheck, RadGroupCheck, RadReply, RadUserGroup
from app.repositories.directory import SubjectFilter
from app.schemas.groups import GroupCreate, GroupUpdate
from app.schemas.nas import CoARequest, NasCreate
from app.schemas.users import AttributeIn, DeviceCreate, UserCreate
from app.services.accounts import AccountService
from app.services.devices import DeviceService
from app.services.groups import GroupService
from app.services.importexport import ImportExportService
from app.services.nas import NasService
from app.services.sessions import SessionService
from app.services.settings_service import KEY_MAB_WARNING, SettingsService
from app.services.users import UserService

pytestmark = pytest.mark.asyncio


# --- Schema-Treue ----------------------------------------------------------


async def test_radusergroup_needs_no_id_column(engine) -> None:
    """Das offizielle Schema kennt hier keine id-Spalte."""
    async with engine.connect() as connection:
        rows = (await connection.execute(text("SHOW COLUMNS FROM radusergroup"))).all()
    assert {str(r[0]).lower() for r in rows} == {"username", "groupname", "priority"}


async def test_membership_operations_work_without_id(session, admin_principal) -> None:
    service = UserService(session)
    await service.create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[{"groupname": "mitarbeiter", "priority": 1}],
        ),
        actor=admin_principal,
    )
    detail = await service.get("anna")
    assert detail.groups == ["mitarbeiter"]

    filtered, total = await service.search(SubjectFilter(group="mitarbeiter"))
    assert total == 1 and filtered[0].username == "anna"


# --- Anmeldung -------------------------------------------------------------


async def test_challenge_is_rejected_while_account_locked(session) -> None:
    """Nach der Sperre darf dieselbe Challenge nicht weiter benutzbar sein."""
    import pyotp

    from app.core.config import settings as app_settings
    from app.core.crypto import SecretBox, hash_password
    from app.models.mgr import MgrAccount, Role

    secret = pyotp.random_base32()
    account = MgrAccount(
        username="admin",
        role=Role.ADMINISTRATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
        totp_enabled=True,
        totp_secret_enc=SecretBox(app_settings.coa_secret_key or app_settings.secret_key).encrypt(
            secret
        ),
    )
    session.add(account)
    await session.commit()

    service = AccountService(session)
    challenge = service.challenge_for(account)
    account.locked_until = dt.datetime.now() + dt.timedelta(minutes=10)
    await session.commit()

    with pytest.raises(AuthenticationError) as excinfo:
        await service.account_from_challenge(challenge)
    assert excinfo.value.code == "error.account_locked"


# --- Maskierung ------------------------------------------------------------


async def test_masked_group_password_is_not_written_back(session, admin_principal) -> None:
    """Ein unverändert zurückgesendeter Platzhalter darf das Passwort nicht ersetzen."""
    service = GroupService(session)
    await service.create(
        GroupCreate(
            groupname="g1",
            check_attributes=[
                AttributeIn(attribute="Cleartext-Password", op=":=", value="streng-geheim"),
                AttributeIn(attribute="Simultaneous-Use", op=":=", value="1"),
            ],
        ),
        actor=admin_principal,
    )
    detail = await service.get("g1")

    # Genau das, was die Oberfläche zurückschickt: maskierter Wert inklusive.
    await service.update(
        "g1",
        GroupUpdate(
            check_attributes=[
                AttributeIn(attribute=a.attribute, op=a.op, value=a.value)
                for a in detail.check_attributes
            ]
        ),
        actor=admin_principal,
    )
    row = await session.scalar(
        select(RadGroupCheck).where(RadGroupCheck.attribute == "Cleartext-Password")
    )
    assert row.value == "streng-geheim"


async def test_audit_redacts_user_password_attribute(session, admin_principal) -> None:
    """Auch weniger übliche Passwortattribute dürfen nicht ins Audit-Log."""
    await GroupService(session).create(
        GroupCreate(
            groupname="g1",
            check_attributes=[
                AttributeIn(attribute="User-Password", op=":=", value="streng-geheim")
            ],
        ),
        actor=admin_principal,
    )
    entries = (await session.scalars(select(MgrAudit))).all()
    payload = " ".join((e.after_json or "") + (e.before_json or "") for e in entries)
    assert "streng-geheim" not in payload
    assert "<geaendert>" in payload


# --- Gruppen ---------------------------------------------------------------


async def test_update_cannot_empty_a_group(session, admin_principal) -> None:
    service = GroupService(session)
    await service.create(
        GroupCreate(
            groupname="g1",
            check_attributes=[AttributeIn(attribute="Simultaneous-Use", op=":=", value="1")],
        ),
        actor=admin_principal,
    )
    with pytest.raises(ValidationError) as excinfo:
        await service.update("g1", GroupUpdate(check_attributes=[]), actor=admin_principal)
    assert excinfo.value.code == "error.group_empty"
    assert (await service.get("g1")).check_attributes  # unverändert vorhanden


# --- Verzeichnis -----------------------------------------------------------


async def test_listing_includes_reply_only_subjects(session) -> None:
    """Wer per Direktaufruf sichtbar ist, muss auch in der Liste erscheinen."""
    session.add(RadReply(username="nur-reply", attribute="Filter-Id", op=":=", value="x"))
    session.add(RadUserGroup(username="nur-gruppe", groupname="g1", priority=1))
    await session.commit()

    items, total = await UserService(session).search(SubjectFilter())
    assert {i.username for i in items} == {"nur-reply", "nur-gruppe"}
    assert total == 2


async def test_selection_above_cap_is_rejected(session, admin_principal) -> None:
    """Eine gekappte Sammelaktion würde weniger treffen als bestätigt."""
    service = UserService(session)
    for index in range(5):
        await service.create(
            UserCreate(username=f"user{index}", password="geheim123"), actor=admin_principal
        )
    with pytest.raises(ValidationError) as excinfo:
        await service.directory.all_usernames(SubjectFilter(), cap=3)
    assert excinfo.value.code == "error.selection_too_large"
    assert await service.directory.all_usernames(SubjectFilter(), cap=10) != []


# --- Import ----------------------------------------------------------------


async def test_import_update_keeps_absent_metadata(session, admin_principal) -> None:
    """Ein Import ohne Metadaten-Spalten darf vorhandene Angaben nicht löschen."""
    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna",
            password="alt",
            meta={"note": "Aussendienst", "owner": "it@example.org", "location": "Zürich"},
        ),
        actor=admin_principal,
    )
    await ImportExportService(session).import_csv(
        "username,password\nanna,neu-geheim\n",
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    detail = await users.get("anna")
    assert detail.note == "Aussendienst"
    assert detail.owner == "it@example.org"
    assert detail.location == "Zürich"


# --- CoA und Sessions ------------------------------------------------------


async def test_pyrad_timeout_maps_to_timeout_code(session, admin_principal, monkeypatch) -> None:
    """pyrad wirft eine eigene Timeout-Klasse, keine eingebaute."""
    from pyrad.client import Timeout as PyradTimeout

    from app.core.errors import CoAError
    from app.services import coa as coa_module
    from app.services.coa import CoAService

    await NasService(session).create(
        NasCreate(nasname="10.0.0.1", secret="s", coa_enabled=True, coa_secret="coa-geheim"),
        actor=admin_principal,
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="10.0.0.1",
            acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    def raise_pyrad_timeout(*args, **kwargs):
        raise PyradTimeout("no response")

    monkeypatch.setattr(coa_module, "_send_blocking", raise_pyrad_timeout)
    with pytest.raises(CoAError) as excinfo:
        await CoAService(session).execute(CoARequest(acctuniqueid="u1"), actor=admin_principal)
    assert excinfo.value.code == "error.coa_timeout"


async def test_session_decoration_uses_one_nas_query(session, admin_principal) -> None:
    await NasService(session).create(
        NasCreate(nasname="10.0.0.1", shortname="sw01", secret="s"), actor=admin_principal
    )
    for index in range(3):
        session.add(
            RadAcct(
                acctsessionid=f"s{index}",
                acctuniqueid=f"u{index}",
                username=f"user{index}",
                nasipaddress="10.0.0.1",
                acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
                callingstationid="AA-BB-CC-DD-EE-FF",
            )
        )
    await session.commit()

    from app.repositories.radius.acct import SessionFilter

    items, _, _ = await SessionService(session).search(SessionFilter())
    assert len(items) == 3
    assert all(item.nas_shortname == "sw01" for item in items)


# --- Einstellungen ---------------------------------------------------------


async def test_mab_warning_can_be_switched_off(session, admin_principal) -> None:
    devices = DeviceService(session)
    detail = await devices.create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal)
    assert any(w.code == "warn.mab_not_authentication" for w in detail.warnings)

    await SettingsService(session).update({KEY_MAB_WARNING: False})
    await session.commit()

    quiet = await devices.get("aa:bb:cc:dd:ee:ff")
    assert not any(w.code == "warn.mab_not_authentication" for w in quiet.warnings)


async def test_device_password_still_written(session, admin_principal) -> None:
    """Absicherung: die Warnungsänderung fasst das Credential nicht an."""
    await DeviceService(session).create(
        DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal
    )
    row = await session.scalar(select(RadCheck).where(RadCheck.attribute == "Cleartext-Password"))
    assert row.value == "aa:bb:cc:dd:ee:ff"
