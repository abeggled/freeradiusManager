"""Krypto-Bausteine: NT-Hash, Argon2id, AES-GCM."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from app.core.crypto import SecretBox, hash_password, nt_hash, verify_password


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("password", "8846F7EAEE8FB117AD06BDD830B7586C"),
        ("", "31D6CFE0D16AE931B73C59D7E0C089C0"),
        ("test", "0CB6948805F797BF2A82807973B89537"),
    ],
)
def test_nt_hash_known_vectors(password: str, expected: str) -> None:
    """Vergleich gegen die bekannten NT-Hash-Testvektoren."""
    assert nt_hash(password) == expected


def test_nt_hash_is_utf16_based() -> None:
    """Umlaute muessen als UTF-16LE gehasht werden, sonst passt MSCHAPv2 nicht."""
    assert nt_hash("äöü") != nt_hash("aou")
    assert nt_hash("äöü") == nt_hash("äöü")


def test_password_hash_roundtrip() -> None:
    hashed = hash_password("ein-langes-passwort")
    assert hashed.startswith("$argon2id$")
    assert verify_password("ein-langes-passwort", hashed)
    assert not verify_password("falsch", hashed)
    assert not verify_password("egal", None)


def test_secret_box_roundtrip() -> None:
    box = SecretBox(SecretBox.generate_key())
    token = box.encrypt("coa-secret")
    assert "coa-secret" not in token
    assert box.decrypt(token) == "coa-secret"


def test_secret_box_rejects_foreign_key() -> None:
    token = SecretBox(SecretBox.generate_key()).encrypt("geheim")
    with pytest.raises(InvalidTag):
        SecretBox(SecretBox.generate_key()).decrypt(token)
