"""Internal helpers for authenticated crypto metadata."""

import base64
import binascii
import json
import struct
from typing import Any

from .errors import CryptoError


def require_bytes(value: object, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def require_master_key(key: object) -> bytes:
    key_bytes = require_bytes(key, "key")
    if len(key_bytes) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return key_bytes


def encode_b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_b64(value: Any, *, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise CryptoError("decryption failed")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise CryptoError("decryption failed") from None
    if expected_length is not None and len(decoded) != expected_length:
        raise CryptoError("decryption failed")
    return decoded


def canonical_json(metadata: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise CryptoError("decryption failed") from None


def authenticated_data(
    domain: bytes,
    metadata_without_tag: dict[str, Any],
    aad: bytes,
) -> bytes:
    """Encode authenticated fields without concatenation ambiguity."""
    require_bytes(aad, "aad")
    header = canonical_json(metadata_without_tag)
    return b"".join(
        (
            domain,
            struct.pack(">Q", len(header)),
            header,
            struct.pack(">Q", len(aad)),
            aad,
        )
    )


def authenticated_ciphertext(
    domain: bytes,
    metadata_without_tag: dict[str, Any],
    aad: bytes,
    ciphertext: bytes,
) -> bytes:
    require_bytes(ciphertext, "ciphertext")
    return b"".join(
        (
            authenticated_data(domain, metadata_without_tag, aad),
            struct.pack(">Q", len(ciphertext)),
            ciphertext,
        )
    )
