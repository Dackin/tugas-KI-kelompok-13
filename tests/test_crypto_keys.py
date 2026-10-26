"""Master-key configuration tests."""

import base64

import pytest

from app.crypto import KeyConfigurationError, get_master_key
from app.crypto.keys import decode_master_key


TEST_KEY = bytes(range(32))
TEST_KEY_B64 = base64.b64encode(TEST_KEY).decode("ascii")


def test_decode_master_key_returns_exact_original_bytes():
    assert decode_master_key(TEST_KEY_B64) == TEST_KEY


def test_get_master_key_reads_flask_style_config():
    assert get_master_key({"CRYPTO_MASTER_KEY_B64": TEST_KEY_B64}) == TEST_KEY


def test_get_master_key_reads_environment(monkeypatch):
    monkeypatch.setenv("CRYPTO_MASTER_KEY_B64", TEST_KEY_B64)

    assert get_master_key() == TEST_KEY


def test_get_master_key_rejects_missing_configuration(monkeypatch):
    monkeypatch.delenv("CRYPTO_MASTER_KEY_B64", raising=False)

    with pytest.raises(KeyConfigurationError, match="is not configured"):
        get_master_key()


@pytest.mark.parametrize("encoded_key", ["not base64!", "YWJjZA===", object()])
def test_decode_master_key_rejects_invalid_base64(encoded_key):
    with pytest.raises(KeyConfigurationError):
        decode_master_key(encoded_key)


@pytest.mark.parametrize("key", [b"short", b"X" * 31, b"X" * 33])
def test_decode_master_key_rejects_wrong_length(key):
    encoded_key = base64.b64encode(key).decode("ascii")

    with pytest.raises(KeyConfigurationError, match="exactly 32 bytes"):
        decode_master_key(encoded_key)
