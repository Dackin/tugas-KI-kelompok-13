"""Load the encryption master key without hard-coding or persisting it."""

import base64
import binascii
import os
from collections.abc import Mapping
from typing import Any

MASTER_KEY_ENV = "CRYPTO_MASTER_KEY_B64"
MASTER_KEY_SIZE = 32


class KeyConfigurationError(RuntimeError):
    """Raised when the server encryption key is missing or invalid."""


def decode_master_key(encoded_key: object) -> bytes:
    """Strictly decode a Base64-encoded 256-bit master key."""
    if not isinstance(encoded_key, str) or not encoded_key:
        raise KeyConfigurationError(f"{MASTER_KEY_ENV} is not configured")
    try:
        key = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError):
        raise KeyConfigurationError(
            f"{MASTER_KEY_ENV} must be valid Base64"
        ) from None
    if len(key) != MASTER_KEY_SIZE:
        raise KeyConfigurationError(
            f"{MASTER_KEY_ENV} must decode to exactly {MASTER_KEY_SIZE} bytes"
        )
    return key


def get_master_key(config: Mapping[str, Any] | None = None) -> bytes:
    """Read and validate the key from Flask config or the process environment.

    Loading is intentionally lazy: application startup and non-crypto commands do
    not require a key, but every upload/download operation fails closed when the
    key is absent or malformed.
    """
    encoded_key = (
        config.get(MASTER_KEY_ENV)
        if config is not None
        else os.getenv(MASTER_KEY_ENV)
    )
    return decode_master_key(encoded_key)
