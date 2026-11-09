"""Fixed external vectors and fresh-process interoperability (synthetic only)."""

import ctypes.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from simple_argon2id_encryption import crypto
from simple_argon2id_encryption.encoding import format_hex, parse_hex

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((Path(__file__).parent / "vectors" / "sae1.json").read_text())["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_external_vector(vector, monkeypatch):
    password = bytes.fromhex(vector["password_hex"])
    text = bytes.fromhex(vector["plaintext_utf8_hex"]).decode("utf-8")
    salt = bytes.fromhex(vector["salt_hex"])
    nonce = bytes.fromhex(vector["nonce_hex"])
    expected = bytes.fromhex(vector["header_hex"] + vector["ciphertext_hex"] + vector["tag_hex"])
    assert crypto.derive_key(password, salt).hex() == vector["key_hex"]
    random_inputs = iter((salt, nonce))
    def fixed_random(size):
        value = next(random_inputs)
        assert len(value) == size
        return value
    monkeypatch.setattr(crypto.secrets, "token_bytes", fixed_random)
    encoded = crypto.encrypt_text(text, password)
    assert parse_hex(encoded) == expected
    assert crypto.decrypt_text(encoded, password) == text
    assert next(random_inputs, None) is None
    if "encoded" in vector:
        assert encoded == vector["encoded"]


def test_reproduce_vectors_without_project_or_pynacl(tmp_path):
    if not ctypes.util.find_library("argon2") or not ctypes.util.find_library("sodium"):
        pytest.skip("system libargon2 and libsodium are required to regenerate vectors")
    # -I -S excludes PYTHONPATH and site packages, including PyNaCl.
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(ROOT / "tests" / "generate_vectors.py"), "--check"],
        cwd=tmp_path, capture_output=True, text=True, timeout=90,
    )
    assert result.returncode == 0, result.stderr
    assert "5 vectors reproduced" in result.stdout


# Password/plaintext test values travel over stdin, never argv or environment.
CHILD = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "src"))
from simple_argon2id_encryption.crypto import encrypt_text, decrypt_text
request = json.load(sys.stdin)
password = bytes.fromhex(request["password_hex"])
if request["operation"] == "encrypt":
    response = encrypt_text(request["text"], password)
else:
    response = decrypt_text(request["encoded"], password)
json.dump(response, sys.stdout)
'''


def child_request(request, cwd):
    result = subprocess.run(
        [sys.executable, "-I", "-c", CHILD, str(ROOT)],
        input=json.dumps(request), capture_output=True, text=True, cwd=cwd, timeout=30,
    )
    assert result.returncode == 0, "Child operation failed"
    assert result.stderr == ""
    return json.loads(result.stdout)


def test_encrypt_then_decrypt_in_separate_processes(tmp_path):
    password = b"synthetic subprocess password"
    text = "Synthetic / Синтетика / 🚀\nsecond line\r\n\x00"
    encoded = child_request({"operation": "encrypt", "text": text, "password_hex": password.hex()}, tmp_path)
    parse_hex(encoded)
    restored = child_request({"operation": "decrypt", "encoded": encoded, "password_hex": password.hex()}, tmp_path)
    assert restored == text
    assert crypto.decrypt_text(encoded, password) == text


def test_external_packet_decrypts_in_fresh_process(tmp_path):
    vector = next(v for v in VECTORS if v["name"] == "unicode-multiline")
    packet = bytes.fromhex(vector["header_hex"] + vector["ciphertext_hex"] + vector["tag_hex"])
    restored = child_request({
        "operation": "decrypt", "encoded": format_hex(packet),
        "password_hex": vector["password_hex"],
    }, tmp_path)
    assert restored.encode("utf-8").hex() == vector["plaintext_utf8_hex"]
