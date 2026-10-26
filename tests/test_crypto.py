"""Correctness and integrity tests for encryption algorithms."""

from copy import deepcopy
from hashlib import sha256

import pytest

from app.crypto import CryptoError
from app.crypto import aes


TEST_KEY = bytes(range(32))
TEST_AAD = b'{"ticket_id":17,"uploaded_by_user_id":4}'


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"short file",
        bytes(range(256)),
        b"\x00\xff\xfe\x80non-utf8",
        b"A" * 4097,
    ],
)
def test_aes_round_trip_is_identical(plaintext):
    ciphertext, metadata = aes.encrypt(plaintext, TEST_KEY, aad=TEST_AAD)

    decrypted = aes.decrypt(ciphertext, TEST_KEY, metadata, aad=TEST_AAD)

    assert decrypted == plaintext
    assert sha256(decrypted).digest() == sha256(plaintext).digest()
    assert metadata["algorithm"] == "AES-256-GCM"
    assert metadata.get("mode") != "ECB"


def test_aes_uses_unique_nonce_for_same_plaintext():
    first_ciphertext, first_metadata = aes.encrypt(b"same", TEST_KEY)
    second_ciphertext, second_metadata = aes.encrypt(b"same", TEST_KEY)

    assert first_metadata["nonce_b64"] != second_metadata["nonce_b64"]
    assert (first_ciphertext, first_metadata["tag_b64"]) != (
        second_ciphertext,
        second_metadata["tag_b64"],
    )


def test_aes_rejects_modified_ciphertext():
    ciphertext, metadata = aes.encrypt(b"sensitive document", TEST_KEY)
    tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    with pytest.raises(CryptoError, match="decryption failed"):
        aes.decrypt(tampered, TEST_KEY, metadata)


def test_aes_rejects_modified_tag():
    ciphertext, metadata = aes.encrypt(b"sensitive document", TEST_KEY)
    tampered_metadata = deepcopy(metadata)
    tampered_metadata["tag_b64"] = "A" * 24

    with pytest.raises(CryptoError, match="decryption failed"):
        aes.decrypt(ciphertext, TEST_KEY, tampered_metadata)


@pytest.mark.parametrize("field", ["version", "algorithm", "nonce_b64"])
def test_aes_rejects_modified_metadata(field):
    ciphertext, metadata = aes.encrypt(b"sensitive document", TEST_KEY)
    tampered_metadata = deepcopy(metadata)
    tampered_metadata[field] = "changed"

    with pytest.raises(CryptoError, match="decryption failed"):
        aes.decrypt(ciphertext, TEST_KEY, tampered_metadata)


def test_aes_rejects_wrong_key_and_aad():
    ciphertext, metadata = aes.encrypt(b"sensitive document", TEST_KEY, aad=TEST_AAD)

    with pytest.raises(CryptoError, match="decryption failed"):
        aes.decrypt(ciphertext, b"X" * 32, metadata, aad=TEST_AAD)
    with pytest.raises(CryptoError, match="decryption failed"):
        aes.decrypt(ciphertext, TEST_KEY, metadata, aad=b"wrong context")


@pytest.mark.parametrize("invalid_key", [b"", b"short", b"X" * 31, b"X" * 33])
def test_aes_rejects_invalid_key_length(invalid_key):
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        aes.encrypt(b"data", invalid_key)
