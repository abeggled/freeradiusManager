"""Krypto-Bausteine.

* Argon2id fuer Manager-Passwoerter (FR-10).
* AES-GCM fuer CoA-Secrets und TOTP-Secrets (NFR-1) -- diese Werte liest nur der
  Manager, daher ist anwendungsseitige Verschluesselung moeglich.
* NT-Hash fuer PEAP/MSCHAPv2 (FR-1). MD4 ist in OpenSSL 3 nicht mehr
  standardmaessig verfuegbar, deshalb eine eigene, kompakte Implementierung.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import struct

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4, hash_len=32)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


_hash_slots: asyncio.Semaphore | None = None


def _slots() -> asyncio.Semaphore:
    """Begrenzt die gleichzeitigen Argon2-Berechnungen.

    Erst beim ersten Gebrauch angelegt: eine ``Semaphore`` bindet sich an die
    laufende Ereignisschleife.
    """
    global _hash_slots
    if _hash_slots is None:
        _hash_slots = asyncio.Semaphore(settings.password_hash_concurrency)
    return _hash_slots


async def hash_password_async(password: str) -> str:
    """Argon2id in einem Worker-Thread.

    Der Algorithmus ist absichtlich rechen- und speicherintensiv. Direkt im
    Ereignisschleifen-Thread ausgefuehrt blockierte jede Anmeldung den ganzen
    Prozess - auch Health-Checks und fremde Anfragen (NFR-2). ``to_thread``
    verwendet den beschraenkten Standard-Executor.
    """
    async with _slots():
        return await asyncio.to_thread(hash_password, password)


async def verify_password_async(password: str, password_hash: str | None) -> bool:
    """Siehe ``hash_password_async``."""
    async with _slots():
        return await asyncio.to_thread(verify_password, password, password_hash)


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, ValueError):
        return True


# --------------------------------------------------------------------------
# MD4 / NT-Hash
# --------------------------------------------------------------------------


def _md4(data: bytes) -> bytes:
    """Minimale MD4-Implementierung (RFC 1320) fuer den NT-Hash."""

    def lrot(value: int, count: int) -> int:
        value &= 0xFFFFFFFF
        return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF

    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]

    for offset in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[offset : offset + 64]))
        a, b, c, d = h

        for i in range(16):
            k, s = i, [3, 7, 11, 19][i % 4]
            f = (b & c) | (~b & d)
            a, b, c, d = d, lrot(a + f + x[k], s), b, c

        for i in range(16):
            k, s = order2[i], [3, 5, 9, 13][i % 4]
            f = (b & c) | (b & d) | (c & d)
            a, b, c, d = d, lrot(a + f + x[k] + 0x5A827999, s), b, c

        for i in range(16):
            k, s = order3[i], [3, 9, 11, 15][i % 4]
            f = b ^ c ^ d
            a, b, c, d = d, lrot(a + f + x[k] + 0x6ED9EBA1, s), b, c

        h = [(v + n) & 0xFFFFFFFF for v, n in zip(h, [a, b, c, d], strict=True)]

    return struct.pack("<4I", *h)


def nt_hash(password: str) -> str:
    """NT-Password als Grossbuchstaben-Hexstring, wie FreeRADIUS ihn erwartet."""
    return _md4(password.encode("utf-16-le")).hex().upper()


# --------------------------------------------------------------------------
# AES-GCM
# --------------------------------------------------------------------------

_PREFIX = "gcm1"


class SecretBox:
    """Symmetrische Verschluesselung mit Schluessel aus der Umgebung."""

    def __init__(self, key: str) -> None:
        self._key = self._decode_key(key)

    @staticmethod
    def _decode_key(key: str) -> bytes:
        if not key:
            raise ValueError("FRM_COA_SECRET_KEY ist nicht gesetzt")
        try:
            raw = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        except Exception:  # noqa: BLE001 - beliebige Base64-Fehler
            raw = b""
        if len(raw) not in (16, 24, 32):
            raw = hashlib.sha256(key.encode("utf-8")).digest()
        return raw

    @staticmethod
    def generate_key() -> str:
        return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return f"{_PREFIX}:{base64.urlsafe_b64encode(nonce + ct).decode('ascii')}"

    def decrypt(self, token: str) -> str:
        prefix, _, payload = token.partition(":")
        if prefix != _PREFIX or not payload:
            raise ValueError("Unbekanntes Secret-Format")
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        return AESGCM(self._key).decrypt(raw[:12], raw[12:], None).decode("utf-8")
