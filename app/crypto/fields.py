"""Enkripsi tingkat kolom untuk data pribadi di database.

Nilai disimpan sebagai ``enc:v1:<base64(nonce || ciphertext)>`` memakai
AES-256-GCM. Kunci diturunkan dari master key aplikasi dengan HKDF, memakai
salt dan info berbeda dari kunci penyimpanan file, sehingga kebocoran satu
kunci tidak otomatis membuka yang lain.

Nilai lama yang belum berawalan ``enc:v1:`` dikembalikan apa adanya agar
database pengembangan lama tetap bisa dibaca.
"""

from __future__ import annotations

import base64
import os
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app, has_app_context
from sqlalchemy.types import Text, TypeDecorator

from .keys import get_master_key

PREFIX = "enc:v1:"
_SALT = b"secure-rt/db-field/v1"
_INFO = b"aes-256-gcm-field"
_NONCE_SIZE = 12


@lru_cache(maxsize=4)
def _derive_key(master_key: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        info=_INFO,
    ).derive(master_key)


def _field_key() -> bytes:
    config = current_app.config if has_app_context() else None
    return _derive_key(get_master_key(config))


class EncryptedText(TypeDecorator):
    """Kolom teks yang dienkripsi AES-256-GCM secara transparan."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, str):
            value = str(value)
        nonce = os.urandom(_NONCE_SIZE)
        blob = AESGCM(_field_key()).encrypt(nonce, value.encode("utf-8"), b"")
        return PREFIX + base64.b64encode(nonce + blob).decode("ascii")

    def process_result_value(self, value, dialect):
        if value is None or not isinstance(value, str) or not value.startswith(PREFIX):
            return value
        raw = base64.b64decode(value[len(PREFIX):], validate=True)
        try:
            return AESGCM(_field_key()).decrypt(
                raw[:_NONCE_SIZE], raw[_NONCE_SIZE:], b""
            ).decode("utf-8")
        except InvalidTag:
            raise ValueError("data terenkripsi rusak atau kunci berbeda") from None
