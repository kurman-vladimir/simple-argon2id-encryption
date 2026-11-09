"""Frozen SAE1/KDF contract and review regression cases; synthetic data only."""

import inspect
import json
from pathlib import Path
import traceback

import pytest
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

from simple_argon2id_encryption import crypto, encoding

VECTOR_PATH = Path(__file__).parent / "vectors" / "sae1.json"
VECTOR = next(v for v in json.loads(VECTOR_PATH.read_text())["vectors"] if v["name"] == "ascii-reference")
PASSWORD = bytes.fromhex(VECTOR["password_hex"])
KEY = bytes.fromhex(VECTOR["key_hex"])
SALT = bytes.fromhex(VECTOR["salt_hex"])
NONCE = bytes.fromhex(VECTOR["nonce_hex"])


def test_frozen_derive_key_signature():
    signature = inspect.signature(crypto.derive_key)
    assert list(signature.parameters) == ["password_bytes", "salt", "profile"]
    assert signature.parameters["password_bytes"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert signature.parameters["salt"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert signature.parameters["profile"].kind is inspect.Parameter.KEYWORD_ONLY
    assert type(signature.parameters["profile"].default) is int
    assert signature.parameters["profile"].default == 1
    assert crypto.derive_key(PASSWORD, SALT) == KEY
    assert crypto.derive_key(password_bytes=PASSWORD, salt=SALT, profile=1) == KEY
    with pytest.raises(TypeError):
        crypto.derive_key(PASSWORD, SALT, 1)
    with pytest.raises(TypeError):
        crypto.derive_key(PASSWORD, SALT, opslimit=1)


def test_frozen_wire_constants_and_header():
    assert (encoding.VERSION, encoding.PROFILE_ID, encoding.KDF_ID, encoding.AEAD_ID) == (1, 1, 1, 1)
    assert (encoding.ARGON2_VERSION, encoding.ARGON2_OPSLIMIT, encoding.ARGON2_MEMLIMIT, encoding.ARGON2_LANES) == (0x13, 3, 268435456, 1)
    assert (encoding.HEADER_BYTES, encoding.MIN_PACKET_BYTES, encoding.MAX_PACKET_BYTES) == (60, 76, 4172)
    assert (encoding.SALT_OFFSET, encoding.NONCE_OFFSET, encoding.LENGTH_OFFSET) == (20, 36, 18)
    expected = bytes.fromhex("010101011300000003100000000120101810000e") + SALT + NONCE
    assert encoding.build_header(SALT, NONCE, 14) == expected
    assert encoding.PREFIX == "SAE1:"
    assert encoding.MAX_FORMATTED_LENGTH == 16384


def test_synthetic_vector_artifact_is_frozen():
    import hashlib
    assert hashlib.sha256(VECTOR_PATH.read_text(encoding="utf-8").encode("utf-8")).hexdigest() == "f2a3b62677dd59eafa224174d02e5b120a63af9828b5f74069d5ac0e3659e12a"


def test_oversize_rejected_before_utf8_allocation(monkeypatch):
    class Oversize(str):
        def encode(self, *args, **kwargs):
            pytest.fail("Oversized plaintext reached UTF-8 encoding")
    with pytest.raises(ValueError, match="exceeds"):
        crypto.encrypt_text(Oversize("x" * 4097), PASSWORD)


def test_utf8_encoding_error_does_not_chain_original_data():
    try:
        crypto.encrypt_text("synthetic\ud800", PASSWORD)
    except ValueError as exc:
        assert exc.__cause__ is None
        assert exc.__context__ is None
        diagnostic = "".join(traceback.format_exception(exc))
        assert "UnicodeEncodeError" not in diagnostic
        assert "surrogates not allowed" not in diagnostic
    else:
        pytest.fail("Invalid Unicode accepted")


def test_authenticated_utf8_error_does_not_chain_original_data(monkeypatch):
    monkeypatch.setattr(crypto, "derive_key", lambda *args, **kwargs: KEY)
    header = encoding.build_header(SALT, NONCE, 1)
    encrypted = crypto_aead_xchacha20poly1305_ietf_encrypt(b"\xff", b"SAE1:" + header, NONCE, KEY)
    with pytest.raises(crypto.DecryptionError) as error:
        crypto.decrypt_text(encoding.format_hex(header + encrypted), PASSWORD)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    diagnostic = "".join(traceback.format_exception(error.value))
    assert "UnicodeDecodeError" not in diagnostic
    assert "byte 0xff" not in diagnostic


def test_authentication_error_does_not_chain_native_traceback(monkeypatch):
    monkeypatch.setattr(crypto, "derive_key", lambda *args, **kwargs: KEY)
    packet = bytes.fromhex(VECTOR["header_hex"] + VECTOR["ciphertext_hex"] + VECTOR["tag_hex"])
    packet = packet[:-1] + bytes([packet[-1] ^ 1])
    with pytest.raises(crypto.DecryptionError) as error:
        crypto.decrypt_text(encoding.format_hex(packet), PASSWORD)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_both_operations_call_public_derive_key(monkeypatch):
    calls = []
    def derive(password_bytes, salt, *, profile=1):
        calls.append((password_bytes, salt, profile))
        return KEY
    monkeypatch.setattr(crypto, "derive_key", derive)
    values = iter((SALT, NONCE))
    monkeypatch.setattr(crypto.secrets, "token_bytes", lambda size: next(values))
    encoded = crypto.encrypt_text("test text SAE1", PASSWORD)
    assert crypto.decrypt_text(encoded, PASSWORD) == "test text SAE1"
    assert calls == [(PASSWORD, SALT, 1), (PASSWORD, SALT, 1)]


@pytest.mark.parametrize("failure", [MemoryError, RuntimeError])
def test_kdf_resource_failure_never_falls_back(monkeypatch, failure):
    calls = []
    def failing(size, password, salt, *, opslimit, memlimit):
        calls.append((size, opslimit, memlimit))
        raise failure("synthetic resource failure")
    monkeypatch.setattr(crypto.argon2id, "kdf", failing)
    with pytest.raises(failure):
        crypto.derive_key(PASSWORD, SALT)
    assert calls == [(32, 3, 268435456)]


@pytest.mark.parametrize("aad_kind", ["empty", "header-only", "wrong-version", "short-header"])
def test_wrong_associated_data_cannot_authenticate(monkeypatch, aad_kind):
    monkeypatch.setattr(crypto, "derive_key", lambda *args, **kwargs: KEY)
    message = b"synthetic associated data check"
    header = encoding.build_header(SALT, NONCE, len(message))
    bad_aad = {
        "empty": b"",
        "header-only": header,
        "wrong-version": b"SAE2:" + header,
        "short-header": b"SAE1:" + header[:-1],
    }[aad_kind]
    encrypted = crypto_aead_xchacha20poly1305_ietf_encrypt(message, bad_aad, NONCE, KEY)
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_text(encoding.format_hex(header + encrypted), PASSWORD)


def test_random_source_failure_never_falls_back(monkeypatch):
    def unavailable(size):
        raise OSError("synthetic random source failure")
    def forbidden(*args, **kwargs):
        pytest.fail("KDF ran after random source failure")
    monkeypatch.setattr(crypto.secrets, "token_bytes", unavailable)
    monkeypatch.setattr(crypto, "derive_key", forbidden)
    with pytest.raises(OSError):
        crypto.encrypt_text("synthetic random failure", PASSWORD)


def test_incompatible_native_algorithm_is_rejected(monkeypatch):
    monkeypatch.setattr(crypto.argon2id, "ALG", -1)
    def forbidden(*args, **kwargs):
        pytest.fail("Incompatible algorithm reached KDF")
    monkeypatch.setattr(crypto.argon2id, "kdf", forbidden)
    with pytest.raises(RuntimeError, match="v1.3"):
        crypto.derive_key(PASSWORD, SALT)
