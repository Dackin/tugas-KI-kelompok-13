"""Private, authenticated ciphertext storage."""

import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from . import aes, des, rc4
from ._utils import canonical_json, require_bytes, require_master_key
from .errors import CryptoError

_AAD_DOMAIN = b"secure-rt/document-context/v1\x00"
_CONTEXT_FIELDS = frozenset(
    {"ticket_id", "uploaded_by_user_id", "original_filename"}
)


class _CipherModule(Protocol):
    ALGORITHM: str

    @staticmethod
    def encrypt(
        plaintext: bytes, key: bytes, *, aad: bytes = b""
    ) -> tuple[bytes, dict[str, Any]]: ...

    @staticmethod
    def decrypt(
        ciphertext: bytes,
        key: bytes,
        metadata: dict[str, Any],
        *,
        aad: bytes = b"",
    ) -> bytes: ...


_ALGORITHMS: dict[str, _CipherModule] = {
    aes.ALGORITHM: aes,
    des.ALGORITHM: des,
    rc4.ALGORITHM: rc4,
}


@dataclass(frozen=True)
class StoredFile:
    """Values ready to persist in the matching Document model columns."""

    ciphertext_path: str
    algorithm: str
    crypto_metadata_json: str

    @property
    def metadata(self) -> dict[str, Any]:
        return json.loads(self.crypto_metadata_json)


def _document_aad(context: Mapping[str, Any]) -> bytes:
    if not isinstance(context, Mapping) or set(context) != _CONTEXT_FIELDS:
        raise ValueError(
            "context must contain ticket_id, uploaded_by_user_id, and original_filename"
        )
    for field in ("ticket_id", "uploaded_by_user_id"):
        value = context[field]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{field} must be a positive integer")
    filename = context["original_filename"]
    if not isinstance(filename, str) or not filename or "\x00" in filename:
        raise ValueError("original_filename must be a non-empty string")

    normalized = {
        "version": 1,
        "ticket_id": context["ticket_id"],
        "uploaded_by_user_id": context["uploaded_by_user_id"],
        "original_filename": filename,
    }
    return _AAD_DOMAIN + canonical_json(normalized)


def _storage_root(
    storage_root: str | os.PathLike[str], *, create: bool = False
) -> Path:
    if not isinstance(storage_root, (str, os.PathLike)):
        raise TypeError("storage_root must be a path")
    root = Path(storage_root).resolve()
    if create:
        root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        raise ValueError("storage_root must be a directory")
    return root


def _cipher_module(algorithm: str) -> _CipherModule:
    try:
        return _ALGORITHMS[algorithm]
    except (KeyError, TypeError):
        raise ValueError("unsupported encryption algorithm") from None


def encrypt_file(
    plaintext: bytes,
    *,
    storage_root: str | os.PathLike[str],
    key: bytes,
    context: Mapping[str, Any],
    algorithm: str = aes.ALGORITHM,
) -> StoredFile:
    """Encrypt bytes before atomically placing ciphertext in private storage."""
    plaintext = require_bytes(plaintext, "plaintext")
    key = require_master_key(key)
    module = _cipher_module(algorithm)
    aad = _document_aad(context)
    ciphertext, metadata = module.encrypt(plaintext, key, aad=aad)
    root = _storage_root(storage_root, create=True)

    filename = f"{uuid.uuid4().hex}.bin"
    destination = root / filename
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=root,
            prefix=".encrypted-upload-",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(ciphertext)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return StoredFile(
        ciphertext_path=filename,
        algorithm=module.ALGORITHM,
        crypto_metadata_json=json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ),
    )


def delete_file(
    *,
    ciphertext_path: str,
    storage_root: str | os.PathLike[str],
) -> None:
    """Hapus ciphertext dengan validasi path yang sama seperti dekripsi."""
    root = _storage_root(storage_root)
    relative_path = Path(ciphertext_path)
    if (
        relative_path.is_absolute()
        or len(relative_path.parts) != 1
        or relative_path.suffix != ".bin"
    ):
        raise CryptoError("decryption failed")
    resolved_path = (root / relative_path).resolve()
    if not resolved_path.is_relative_to(root):
        raise CryptoError("decryption failed")
    resolved_path.unlink(missing_ok=True)


def decrypt_file(
    *,
    ciphertext_path: str,
    storage_root: str | os.PathLike[str],
    key: bytes,
    context: Mapping[str, Any],
    algorithm: str,
    metadata: Mapping[str, Any] | str,
) -> bytes:
    """Read private ciphertext, authenticate it, and return original bytes."""
    key = require_master_key(key)
    try:
        module = _cipher_module(algorithm)
        if isinstance(metadata, str):
            parsed_metadata = json.loads(metadata)
        elif isinstance(metadata, Mapping):
            parsed_metadata = dict(metadata)
        else:
            raise CryptoError("decryption failed")
        if not isinstance(parsed_metadata, dict):
            raise CryptoError("decryption failed")
        if parsed_metadata.get("algorithm") != algorithm:
            raise CryptoError("decryption failed")

        root = _storage_root(storage_root)
        relative_path = Path(ciphertext_path)
        if (
            relative_path.is_absolute()
            or len(relative_path.parts) != 1
            or relative_path.suffix != ".bin"
        ):
            raise CryptoError("decryption failed")
        resolved_path = (root / relative_path).resolve()
        if not resolved_path.is_relative_to(root) or not resolved_path.is_file():
            raise CryptoError("decryption failed")

        ciphertext = resolved_path.read_bytes()
        aad = _document_aad(context)
        return module.decrypt(ciphertext, key, parsed_metadata, aad=aad)
    except CryptoError:
        raise
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        raise CryptoError("decryption failed") from None
