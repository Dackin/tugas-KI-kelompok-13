"""INSECURE/ACADEMIC ONLY: RC4 with per-file keys and HMAC integrity."""

import hashlib
import hmac
import os
from typing import Any

from Crypto.Cipher import ARC4
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._utils import (
    authenticated_ciphertext,
    decode_b64,
    encode_b64,
    require_bytes,
    require_master_key,
)
from .errors import CryptoError

ALGORITHM = "RC4-HMAC-SHA256"
VERSION = 1
SALT_SIZE = 16
TAG_SIZE = 32
_DOMAIN = b"secure-rt/rc4-hmac/v1\x00"
_KDF_INFO = b"secure-rt/rc4-hmac/keys/v1"
_METADATA_FIELDS = frozenset(
    {
        "version",
        "algorithm",
        "kdf",
        "salt_b64",
        "mac",
        "tag_b64",
        "insecure_academic_only",
    }
)


def _derive_keys(master_key: bytes, salt: bytes) -> tuple[bytes, bytes]:
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=32 + 32,
        salt=salt,
        info=_KDF_INFO,
    ).derive(master_key)
    return material[:32], material[32:]


def _header(salt: bytes) -> dict[str, Any]:
    return {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "kdf": "HKDF-SHA256",
        "salt_b64": encode_b64(salt),
        "mac": "HMAC-SHA256",
        "insecure_academic_only": True,
    }


def encrypt(
    plaintext: bytes,
    key: bytes,
    *,
    aad: bytes = b"",
) -> tuple[bytes, dict[str, Any]]:
    """Encrypt dummy data with a unique derived RC4 key and HMAC-SHA256."""
    plaintext = require_bytes(plaintext, "plaintext")
    key = require_master_key(key)
    require_bytes(aad, "aad")

    salt = os.urandom(SALT_SIZE)
    encryption_key, mac_key = _derive_keys(key, salt)
    header = _header(salt)
    ciphertext = ARC4.new(encryption_key).encrypt(plaintext)
    tag = hmac.new(
        mac_key,
        authenticated_ciphertext(_DOMAIN, header, aad, ciphertext),
        hashlib.sha256,
    ).digest()
    return ciphertext, {**header, "tag_b64": encode_b64(tag)}


def decrypt(
    ciphertext: bytes,
    key: bytes,
    metadata: dict[str, Any],
    *,
    aad: bytes = b"",
) -> bytes:
    """Verify HMAC before decrypting academic RC4 ciphertext."""
    ciphertext = require_bytes(ciphertext, "ciphertext")
    key = require_master_key(key)
    require_bytes(aad, "aad")

    if not isinstance(metadata, dict) or set(metadata) != _METADATA_FIELDS:
        raise CryptoError("decryption failed")
    expected_values = {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "kdf": "HKDF-SHA256",
        "mac": "HMAC-SHA256",
        "insecure_academic_only": True,
    }
    if any(metadata.get(name) != value for name, value in expected_values.items()):
        raise CryptoError("decryption failed")

    salt = decode_b64(metadata.get("salt_b64"), expected_length=SALT_SIZE)
    supplied_tag = decode_b64(metadata.get("tag_b64"), expected_length=TAG_SIZE)
    encryption_key, mac_key = _derive_keys(key, salt)
    header = {name: metadata[name] for name in metadata if name != "tag_b64"}
    expected_tag = hmac.new(
        mac_key,
        authenticated_ciphertext(_DOMAIN, header, aad, ciphertext),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise CryptoError("decryption failed")

    try:
        return ARC4.new(encryption_key).decrypt(ciphertext)
    except ValueError:
        raise CryptoError("decryption failed") from None
