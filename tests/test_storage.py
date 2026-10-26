"""Unit tests for private encrypted file storage.

Protected download route tests remain the responsibility of the integration owner.
"""

import json
from hashlib import sha256

import pytest

from app.crypto import CryptoError
from app.crypto import aes, des, rc4
from app.crypto import storage


TEST_KEY = bytes(range(32))
CONTEXT = {
    "ticket_id": 11,
    "uploaded_by_user_id": 7,
    "original_filename": "surat-dummy.pdf",
}
ALGORITHMS = (aes.ALGORITHM, des.ALGORITHM, rc4.ALGORITHM)


def _decrypt(stored, storage_root, *, context=CONTEXT, algorithm=None, metadata=None):
    return storage.decrypt_file(
        ciphertext_path=stored.ciphertext_path,
        storage_root=storage_root,
        key=TEST_KEY,
        context=context,
        algorithm=algorithm or stored.algorithm,
        metadata=metadata or stored.crypto_metadata_json,
    )


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("plaintext", [b"", bytes(range(256)), b"file" * 2049])
def test_stored_file_decrypts_identically(tmp_path, algorithm, plaintext):
    stored = storage.encrypt_file(
        plaintext,
        storage_root=tmp_path,
        key=TEST_KEY,
        context=CONTEXT,
        algorithm=algorithm,
    )

    decrypted = _decrypt(stored, tmp_path)

    assert decrypted == plaintext
    assert sha256(decrypted).digest() == sha256(plaintext).digest()
    assert stored.algorithm == algorithm
    assert json.loads(stored.crypto_metadata_json)["algorithm"] == algorithm


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_storage_writes_only_ciphertext_under_random_name(tmp_path, algorithm):
    plaintext = b"dummy resident document"
    malicious_context = {
        **CONTEXT,
        "original_filename": "../../outside-secret.pdf",
    }

    stored = storage.encrypt_file(
        plaintext,
        storage_root=tmp_path,
        key=TEST_KEY,
        context=malicious_context,
        algorithm=algorithm,
    )

    physical_path = tmp_path / stored.ciphertext_path
    assert physical_path.parent == tmp_path
    assert physical_path.suffix == ".bin"
    assert len(physical_path.stem) == 32
    assert stored.ciphertext_path != malicious_context["original_filename"]
    assert physical_path.read_bytes() != plaintext
    assert not (tmp_path.parent / "outside-secret.pdf").exists()


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_storage_never_reuses_physical_name(tmp_path, algorithm):
    first = storage.encrypt_file(
        b"same", storage_root=tmp_path, key=TEST_KEY, context=CONTEXT, algorithm=algorithm
    )
    second = storage.encrypt_file(
        b"same", storage_root=tmp_path, key=TEST_KEY, context=CONTEXT, algorithm=algorithm
    )

    assert first.ciphertext_path != second.ciphertext_path
    assert (tmp_path / first.ciphertext_path).read_bytes() != (
        tmp_path / second.ciphertext_path
    ).read_bytes()


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_storage_rejects_modified_ciphertext(tmp_path, algorithm):
    stored = storage.encrypt_file(
        b"dummy document",
        storage_root=tmp_path,
        key=TEST_KEY,
        context=CONTEXT,
        algorithm=algorithm,
    )
    physical_path = tmp_path / stored.ciphertext_path
    ciphertext = physical_path.read_bytes()
    physical_path.write_bytes(bytes([ciphertext[0] ^ 1]) + ciphertext[1:])

    with pytest.raises(CryptoError, match="decryption failed"):
        _decrypt(stored, tmp_path)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_storage_authenticates_document_context(tmp_path, algorithm):
    stored = storage.encrypt_file(
        b"dummy document",
        storage_root=tmp_path,
        key=TEST_KEY,
        context=CONTEXT,
        algorithm=algorithm,
    )
    wrong_context = {**CONTEXT, "ticket_id": CONTEXT["ticket_id"] + 1}

    with pytest.raises(CryptoError, match="decryption failed"):
        _decrypt(stored, tmp_path, context=wrong_context)


def test_storage_rejects_algorithm_metadata_mismatch(tmp_path):
    stored = storage.encrypt_file(
        b"dummy document",
        storage_root=tmp_path,
        key=TEST_KEY,
        context=CONTEXT,
    )

    with pytest.raises(CryptoError, match="decryption failed"):
        _decrypt(stored, tmp_path, algorithm=des.ALGORITHM)


@pytest.mark.parametrize("unsafe_path", ["../secret.bin", "nested/secret.bin"])
def test_storage_rejects_path_traversal(tmp_path, unsafe_path):
    stored = storage.encrypt_file(
        b"dummy document",
        storage_root=tmp_path,
        key=TEST_KEY,
        context=CONTEXT,
    )

    with pytest.raises(CryptoError, match="decryption failed"):
        storage.decrypt_file(
            ciphertext_path=unsafe_path,
            storage_root=tmp_path,
            key=TEST_KEY,
            context=CONTEXT,
            algorithm=stored.algorithm,
            metadata=stored.crypto_metadata_json,
        )


def test_storage_rejects_missing_file_and_invalid_metadata(tmp_path):
    stored = storage.encrypt_file(
        b"dummy document",
        storage_root=tmp_path,
        key=TEST_KEY,
        context=CONTEXT,
    )

    with pytest.raises(CryptoError, match="decryption failed"):
        _decrypt(stored, tmp_path, metadata="not-json")

    (tmp_path / stored.ciphertext_path).unlink()
    with pytest.raises(CryptoError, match="decryption failed"):
        _decrypt(stored, tmp_path)


def test_storage_removes_temporary_file_after_atomic_write_failure(tmp_path, monkeypatch):
    def fail_replace(source, destination):
        raise OSError("simulated write failure")

    monkeypatch.setattr(storage.os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated write failure"):
        storage.encrypt_file(
            b"dummy document",
            storage_root=tmp_path,
            key=TEST_KEY,
            context=CONTEXT,
        )

    assert list(tmp_path.iterdir()) == []
