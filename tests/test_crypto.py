"""Cryptographic behavior tests. Require the actual PyNaCl package."""

import pytest

pytest.importorskip("nacl")

from simple_argon2id_encryption.crypto import (
    ARGON2_MEMLIMIT, ARGON2_OPSLIMIT, ARGON2_VERSION, PROFILE_ID,
    DecryptionError, decrypt_text, derive_key, encrypt_text,
)
from simple_argon2id_encryption.encoding import HEADER_BYTES, SALT_OFFSET, NONCE_OFFSET, build_header, format_hex, parse_hex

PASSWORD = b"test password -- not a production credential"
SALT = bytes(range(16))


@pytest.mark.parametrize("text", [
    "", "Hello!", "Several words, with punctuation: !@#$%^&*",
    "Привет, мир!", "caf\u00e9 / \U0001f680", "line one\nline two",
    "A" * 4096, "\u00e9" * 2048,
])
def test_encrypt_decrypt_round_trip(text: str) -> None:
    encoded = encrypt_text(text, PASSWORD)
    assert encoded.startswith("SAE1:")
    assert decrypt_text(encoded, PASSWORD) == text


def test_distinct_salt_nonce_and_ciphertext() -> None:
    a = parse_hex(encrypt_text("same message", PASSWORD))
    b = parse_hex(encrypt_text("same message", PASSWORD))
    assert a != b
    assert a[SALT_OFFSET:NONCE_OFFSET] != b[SALT_OFFSET:NONCE_OFFSET]
    assert a[NONCE_OFFSET:HEADER_BYTES] != b[NONCE_OFFSET:HEADER_BYTES]


def test_wrong_password_fails() -> None:
    encoded = encrypt_text("confidential", PASSWORD)
    with pytest.raises(DecryptionError):
        decrypt_text(encoded, b"wrong password")


def test_tampering_fails() -> None:
    packet = bytearray(parse_hex(encrypt_text("hello", PASSWORD)))
    for position in (SALT_OFFSET, NONCE_OFFSET, HEADER_BYTES, len(packet)-1):
        corrupt = bytearray(packet)
        corrupt[position] ^= 1
        with pytest.raises(DecryptionError):
            decrypt_text(format_hex(bytes(corrupt)), PASSWORD)


def test_unknown_profile_rejected_before_kdf(monkeypatch) -> None:
    from simple_argon2id_encryption import crypto
    packet = bytearray(parse_hex(encrypt_text("abc", PASSWORD)))
    packet[1] = 2
    def forbidden(*args, **kwargs):
        raise AssertionError("KDF must not run")
    monkeypatch.setattr(crypto, "derive_key", forbidden)
    with pytest.raises(ValueError, match="unsupported"):
        decrypt_text(format_hex(bytes(packet)), PASSWORD)


def test_corrupt_format_rejected_before_kdf(monkeypatch) -> None:
    from simple_argon2id_encryption import crypto
    def forbidden(*args, **kwargs):
        raise AssertionError("KDF must not run")
    monkeypatch.setattr(crypto, "derive_key", forbidden)
    with pytest.raises(ValueError):
        decrypt_text("SAE1:13BAD", PASSWORD)


def test_kdf_repeatability_and_salt_separation() -> None:
    x = derive_key(PASSWORD, SALT)
    assert len(x) == 32
    assert x == derive_key(PASSWORD, SALT)
    assert x != derive_key(PASSWORD, bytes([1]) + SALT[1:])
    assert x != derive_key(b"another password", SALT)


def test_parameters_and_version_are_explicit() -> None:
    assert ARGON2_VERSION == 0x13
    assert ARGON2_OPSLIMIT == 3
    assert ARGON2_MEMLIMIT == 268435456
    assert PROFILE_ID == 1


@pytest.mark.parametrize("password", [b"", b"a"*4097, "str-not-bytes"])
def test_invalid_password_rejected(password) -> None:
    with pytest.raises((TypeError, ValueError)):
        derive_key(password, SALT)


def test_invalid_salt_profile_and_oversize() -> None:
    with pytest.raises(ValueError):
        derive_key(PASSWORD, b"short")
    with pytest.raises(ValueError):
        derive_key(PASSWORD, SALT, profile=2)
    with pytest.raises(ValueError):
        encrypt_text("x"*4097, PASSWORD)
    with pytest.raises(ValueError):
        encrypt_text("\u00e9"*2049, PASSWORD)


def test_native_libsodium_reference_vector() -> None:
    """Synthetic KDF vector and updated SAE1 AEAD vector, checked via libsodium C API."""
    key = derive_key(PASSWORD, SALT)
    assert key.hex() == "242ca46400dfeda631429e8208b31d1ac782957a0e84288085b2c4e50d497243"
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
    nonce = bytes(range(24))
    header = build_header(SALT, nonce, len(b"test text SAE1"))
    actual = crypto_aead_xchacha20poly1305_ietf_encrypt(
        b"test text SAE1", b"SAE1:" + header, nonce, key
    )
    assert actual.hex() == "cb8e4baff7732f9b399e3b0583dba8fe0ae6eb1ac1c10c1b399285779412"
