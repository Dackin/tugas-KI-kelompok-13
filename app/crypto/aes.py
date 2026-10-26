"""AES-256-GCM encryption for application file storage."""

import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._utils import (
    authenticated_data,
    decode_b64,
    encode_b64,
    require_bytes,
    require_master_key,
)
from .errors import CryptoError

ALGORITHM = "AES-256-GCM"
VERSION = 1
NONCE_SIZE = 12
TAG_SIZE = 16
_DOMAIN = b"secure-rt/aes-gcm/v1\x00"
_METADATA_FIELDS = frozenset({"version", "algorithm", "nonce_b64", "tag_b64"})


def encrypt(
    plaintext: bytes,
    key: bytes,
    *,
    aad: bytes = b"",
) -> tuple[bytes, dict[str, Any]]:
    """Encrypt bytes and return ciphertext separately from JSON-safe metadata."""
    plaintext = require_bytes(plaintext, "plaintext")
    key = require_master_key(key)
    require_bytes(aad, "aad")

    nonce = os.urandom(NONCE_SIZE)
    header = {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "nonce_b64": encode_b64(nonce),
    }
    encrypted = AESGCM(key).encrypt(
        nonce,
        plaintext,
        authenticated_data(_DOMAIN, header, aad),
    )
    ciphertext, tag = encrypted[:-TAG_SIZE], encrypted[-TAG_SIZE:]
    return ciphertext, {**header, "tag_b64": encode_b64(tag)}


def decrypt(
    ciphertext: bytes,
    key: bytes,
    metadata: dict[str, Any],
    *,
    aad: bytes = b"",
) -> bytes:
    """Authenticate metadata and ciphertext before returning plaintext."""
    ciphertext = require_bytes(ciphertext, "ciphertext")
    key = require_master_key(key)
    require_bytes(aad, "aad")

    if not isinstance(metadata, dict) or set(metadata) != _METADATA_FIELDS:
        raise CryptoError("decryption failed")
    if metadata.get("version") != VERSION or metadata.get("algorithm") != ALGORITHM:
        raise CryptoError("decryption failed")

    nonce = decode_b64(metadata.get("nonce_b64"), expected_length=NONCE_SIZE)
    tag = decode_b64(metadata.get("tag_b64"), expected_length=TAG_SIZE)
    header = {
        "version": metadata["version"],
        "algorithm": metadata["algorithm"],
        "nonce_b64": metadata["nonce_b64"],
    }
    try:
        return AESGCM(key).decrypt(
            nonce,
            ciphertext + tag,
            authenticated_data(_DOMAIN, header, aad),
        )
    except (InvalidTag, ValueError):
        raise CryptoError("decryption failed") from None
