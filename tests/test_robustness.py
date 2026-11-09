"""Synthetic boundary, transcription and parameter rejection cases."""

import json
from pathlib import Path
import random
import textwrap

import pytest

from simple_argon2id_encryption import crypto
from simple_argon2id_encryption.encoding import (
    HEADER_BYTES, NONCE_OFFSET, SALT_OFFSET, format_hex, parse_hex,
)

VECTOR = next(v for v in json.loads(
    (Path(__file__).parent / "vectors" / "sae1.json").read_text()
)["vectors"] if v["name"] == "ascii-reference")
PACKET = bytes.fromhex(VECTOR["header_hex"] + VECTOR["ciphertext_hex"] + VECTOR["tag_hex"])
PASSWORD = bytes.fromhex(VECTOR["password_hex"])
TEXT = bytes.fromhex(VECTOR["plaintext_utf8_hex"]).decode("utf-8")


@pytest.fixture
def fixed_native_key(monkeypatch):
    # These mutation tests isolate native AEAD from repeated 256-MiB KDF calls.
    # End-to-end tests elsewhere always use actual Argon2id, including vectors.
    key = crypto.derive_key(PASSWORD, PACKET[SALT_OFFSET:NONCE_OFFSET])
    monkeypatch.setattr(crypto, "derive_key", lambda *args, **kwargs: key)
    return key


def forbid_kdf(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Invalid structure must be rejected before KDF")
    monkeypatch.setattr(crypto, "derive_key", forbidden)


@pytest.mark.parametrize("text", [
    "".join(chr(i) for i in range(128)),
    "Синтетическая строка: Ёё Йй Ъъ Ьь №123",
    "e\u0301 / é / 日本語 / العربية / 🚀",
    "one\ntwo\r\nthree\rfour\t\x00end\n",
    "A" * 4095,
    "🚀" * 1023 + "abc",
    "🚀" * 1024,
], ids=["all-ascii", "cyrillic", "unicode", "multiline-controls", "4095-ascii", "4095-utf8", "4096-utf8"])
def test_additional_native_round_trips(text):
    encoded = crypto.encrypt_text(text, PASSWORD)
    assert crypto.decrypt_text(encoded, PASSWORD) == text


@pytest.mark.parametrize("text", ["A" * 4097, "🚀" * 1024 + "x", "\ud800"])
def test_invalid_plaintext_before_kdf(monkeypatch, text):
    forbid_kdf(monkeypatch)
    with pytest.raises(ValueError):
        crypto.encrypt_text(text, PASSWORD)


@pytest.mark.parametrize("password", [b"\x00", b"P" * 4096])
def test_password_boundaries_with_native_kdf(password):
    encoded = crypto.encrypt_text("synthetic password boundary", password)
    assert crypto.decrypt_text(encoded, password) == "synthetic password boundary"


@pytest.mark.parametrize("salt_delta,nonce_delta", [(1, 0), (0, 1)], ids=["salt-only", "nonce-only"])
def test_salt_and_nonce_separately_change_output(monkeypatch, salt_delta, nonce_delta):
    salt, nonce = bytes(range(16)), bytes(range(24))
    changed_salt = bytes([salt[0] ^ salt_delta]) + salt[1:]
    changed_nonce = bytes([nonce[0] ^ nonce_delta]) + nonce[1:]
    values = iter((salt, nonce, changed_salt, changed_nonce))
    def source(size):
        value = next(values)
        assert len(value) == size
        return value
    monkeypatch.setattr(crypto.secrets, "token_bytes", source)
    a = parse_hex(crypto.encrypt_text(TEXT, PASSWORD))
    b = parse_hex(crypto.encrypt_text(TEXT, PASSWORD))
    assert (a[SALT_OFFSET:NONCE_OFFSET] != b[SALT_OFFSET:NONCE_OFFSET]) == bool(salt_delta)
    assert (a[NONCE_OFFSET:HEADER_BYTES] != b[NONCE_OFFSET:HEADER_BYTES]) == bool(nonce_delta)
    assert a[HEADER_BYTES:] != b[HEADER_BYTES:]
    assert crypto.decrypt_text(format_hex(a), PASSWORD) == TEXT
    assert crypto.decrypt_text(format_hex(b), PASSWORD) == TEXT


def test_each_individual_hex_digit_mutation_fails(fixed_native_key):
    raw = PACKET.hex().upper()
    alphabet = "0123456789ABCDEF"
    for position, old in enumerate(raw):
        new = alphabet[(alphabet.index(old) + 1) % 16]
        damaged = "SAE1:" + raw[:position] + new + raw[position + 1:]
        with pytest.raises(ValueError):
            crypto.decrypt_text(damaged, PASSWORD)


def test_every_hex_truncation_rejected_before_kdf(monkeypatch):
    forbid_kdf(monkeypatch)
    raw = PACKET.hex()
    for length in range(len(raw)):
        with pytest.raises(ValueError):
            crypto.decrypt_text("SAE1:" + raw[:length], PASSWORD)


@pytest.mark.parametrize("offset,size,value", [
    (0, 1, 0), (0, 1, 2), (0, 1, 255),
    (2, 1, 0), (2, 1, 2), (3, 1, 0), (3, 1, 2),
    (4, 1, 0x10), (4, 1, 0x12), (4, 1, 0x14),
    (5, 4, 0), (5, 4, 1), (5, 4, 2), (5, 4, 4), (5, 4, 0xFFFFFFFF),
    (9, 4, 0), (9, 4, 64 * 1024 * 1024),
    (9, 4, 268435455), (9, 4, 268435457), (9, 4, 0xFFFFFFFF),
    (13, 1, 0), (13, 1, 2), (13, 1, 255),
    (14, 1, 16), (14, 1, 64), (15, 1, 0), (15, 1, 32),
    (16, 1, 12), (16, 1, 255), (17, 1, 0), (17, 1, 8), (17, 1, 255),
])
def test_unsupported_parameters_rejected_before_kdf(monkeypatch, offset, size, value):
    forbid_kdf(monkeypatch)
    damaged = bytearray(PACKET)
    damaged[offset:offset + size] = value.to_bytes(size, "big")
    with pytest.raises(ValueError, match="unsupported"):
        crypto.decrypt_text(format_hex(bytes(damaged)), PASSWORD)


@pytest.mark.parametrize("marker", ["SAE0:", "SAE2:", "SAE01:", "sae1:", "SAE1", "SAE1 :"])
def test_incorrect_version_marker_before_kdf(monkeypatch, marker):
    forbid_kdf(monkeypatch)
    with pytest.raises(ValueError):
        crypto.decrypt_text(marker + PACKET.hex(), PASSWORD)


@pytest.mark.parametrize("extra", [b"\x00", b"\xff" * 16, PACKET])
def test_extra_bytes_rejected_before_kdf(monkeypatch, extra):
    forbid_kdf(monkeypatch)
    with pytest.raises(ValueError, match="length"):
        crypto.decrypt_text("SAE1:" + (PACKET + extra).hex(), PASSWORD)


@pytest.mark.parametrize("indices", [(10, 11), (30, 31), (38, 39)], ids=["salt-groups", "ciphertext-groups", "tag-groups"])
def test_reordered_groups_fail_authentication(fixed_native_key, indices):
    groups = textwrap.wrap(PACKET.hex(), 4)
    first, second = indices
    assert groups[first] != groups[second]
    groups[first], groups[second] = groups[second], groups[first]
    encoded = "SAE1:\n" + " ".join(groups)
    assert parse_hex(encoded) != PACKET
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_text(encoded, PASSWORD)


@pytest.mark.parametrize("width", [1, 3, 4, 7, 16, 31, 32, 33, 64, 256])
def test_line_rewrapping_preserves_packet_and_plaintext(fixed_native_key, width):
    raw = PACKET.hex()
    encoded = "SAE1:\r\n" + "\r\n\t".join(textwrap.wrap(raw, width)) + "\n"
    assert parse_hex(encoded) == PACKET
    assert crypto.decrypt_text(encoded, PASSWORD) == TEXT


def test_random_ascii_whitespace_and_case_preserve_input(fixed_native_key):
    rng = random.Random(20261109)
    for _ in range(30):
        digits = []
        for digit in PACKET.hex():
            digits.append(digit.upper() if rng.randrange(2) else digit)
            digits.append(rng.choice(("", " ", "\r\n", "\t", "\v", "\f")))
        encoded = "SAE1:" + "".join(digits)
        assert parse_hex(encoded) == PACKET
        assert crypto.decrypt_text(encoded, PASSWORD) == TEXT


def test_no_unicode_normalization(monkeypatch):
    # Same fixed test randomness exposes any accidental NFC normalization.
    def source(size):
        return bytes(range(size))
    monkeypatch.setattr(crypto.secrets, "token_bytes", source)
    composed, decomposed = "é", "e\u0301"
    a = crypto.encrypt_text(composed, PASSWORD)
    b = crypto.encrypt_text(decomposed, PASSWORD)
    assert a != b
    assert crypto.decrypt_text(a, PASSWORD) == composed
    assert crypto.decrypt_text(b, PASSWORD) == decomposed


def test_authenticated_non_utf8_is_not_returned(fixed_native_key):
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
    from simple_argon2id_encryption.encoding import build_header
    salt = PACKET[SALT_OFFSET:NONCE_OFFSET]
    nonce = PACKET[NONCE_OFFSET:HEADER_BYTES]
    header = build_header(salt, nonce, 1)
    encrypted = crypto_aead_xchacha20poly1305_ietf_encrypt(
        b"\xff", b"SAE1:" + header, nonce, fixed_native_key,
    )
    with pytest.raises(crypto.DecryptionError, match="not valid UTF-8"):
        crypto.decrypt_text(format_hex(header + encrypted), PASSWORD)


@pytest.mark.parametrize("value", [None, b"bytes-not-text", 123, bytearray(b"test")])
def test_plaintext_type_rejected_before_kdf(monkeypatch, value):
    forbid_kdf(monkeypatch)
    with pytest.raises(TypeError):
        crypto.encrypt_text(value, PASSWORD)


@pytest.mark.parametrize("password", [None, "str-not-bytes", bytearray(b"test"), b"", b"x" * 4097])
def test_invalid_password_for_both_operations(monkeypatch, password):
    forbid_kdf(monkeypatch)
    with pytest.raises((TypeError, ValueError)):
        crypto.encrypt_text(TEXT, password)
    with pytest.raises((TypeError, ValueError)):
        crypto.decrypt_text(format_hex(PACKET), password)


@pytest.mark.parametrize("profile", [True, 1.0, None, "1", 0, 2, 255])
def test_kdf_rejects_non_exact_profile(monkeypatch, profile):
    def forbidden(*args, **kwargs):
        pytest.fail("Unsupported profile reached native KDF")
    monkeypatch.setattr(crypto.argon2id, "kdf", forbidden)
    with pytest.raises(ValueError, match="unsupported"):
        crypto.derive_key(PASSWORD, PACKET[SALT_OFFSET:NONCE_OFFSET], profile=profile)
