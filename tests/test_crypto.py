"""Correctness and integrity tests for encryption algorithms."""

import base64
from copy import deepcopy
from hashlib import sha256

import pytest

from app.crypto import CryptoError
from app.crypto import aes, des


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


def _flip_first_b64_byte(value):
    decoded = base64.b64decode(value, validate=True)
    return base64.b64encode(bytes([decoded[0] ^ 1]) + decoded[1:]).decode("ascii")


@pytest.mark.parametrize(
    "plaintext",
    [b"", b"1234567", b"12345678", b"123456789", bytes(range(256)), b"D" * 4097],
)
def test_des_round_trip_is_identical(plaintext):
    ciphertext, metadata = des.encrypt(plaintext, TEST_KEY, aad=TEST_AAD)

    decrypted = des.decrypt(ciphertext, TEST_KEY, metadata, aad=TEST_AAD)

    assert decrypted == plaintext
    assert sha256(decrypted).digest() == sha256(plaintext).digest()
    assert metadata["algorithm"] == "DES-CBC-HMAC-SHA256"
    assert metadata["mode"] == "CBC"
    assert metadata["mode"] != "ECB"
    assert metadata["insecure_academic_only"] is True


def test_des_uses_unique_salt_and_iv_for_same_plaintext():
    first_ciphertext, first_metadata = des.encrypt(b"same", TEST_KEY)
    second_ciphertext, second_metadata = des.encrypt(b"same", TEST_KEY)

    assert first_metadata["salt_b64"] != second_metadata["salt_b64"]
    assert first_metadata["iv_b64"] != second_metadata["iv_b64"]
    assert first_ciphertext != second_ciphertext


def test_des_rejects_modified_ciphertext():
    ciphertext, metadata = des.encrypt(b"sensitive document", TEST_KEY)
    tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    with pytest.raises(CryptoError, match="decryption failed"):
        des.decrypt(tampered, TEST_KEY, metadata)


def test_des_rejects_modified_tag():
    ciphertext, metadata = des.encrypt(b"sensitive document", TEST_KEY)
    tampered_metadata = deepcopy(metadata)
    tampered_metadata["tag_b64"] = _flip_first_b64_byte(metadata["tag_b64"])

    with pytest.raises(CryptoError, match="decryption failed"):
        des.decrypt(ciphertext, TEST_KEY, tampered_metadata)


@pytest.mark.parametrize("field", ["salt_b64", "iv_b64"])
def test_des_rejects_modified_random_metadata(field):
    ciphertext, metadata = des.encrypt(b"sensitive document", TEST_KEY)
    tampered_metadata = deepcopy(metadata)
    tampered_metadata[field] = _flip_first_b64_byte(metadata[field])

    with pytest.raises(CryptoError, match="decryption failed"):
        des.decrypt(ciphertext, TEST_KEY, tampered_metadata)


@pytest.mark.parametrize("field", ["version", "algorithm", "mode", "padding", "mac"])
def test_des_rejects_modified_descriptor_metadata(field):
    ciphertext, metadata = des.encrypt(b"sensitive document", TEST_KEY)
    tampered_metadata = deepcopy(metadata)
    tampered_metadata[field] = "changed"

    with pytest.raises(CryptoError, match="decryption failed"):
        des.decrypt(ciphertext, TEST_KEY, tampered_metadata)


def test_des_rejects_wrong_key_and_aad():
    ciphertext, metadata = des.encrypt(b"sensitive document", TEST_KEY, aad=TEST_AAD)

    with pytest.raises(CryptoError, match="decryption failed"):
        des.decrypt(ciphertext, b"X" * 32, metadata, aad=TEST_AAD)
    with pytest.raises(CryptoError, match="decryption failed"):
        des.decrypt(ciphertext, TEST_KEY, metadata, aad=b"wrong context")
