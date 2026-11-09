"""Reproduce synthetic SAE1 vectors without importing project code or PyNaCl.

Requires system libargon2 and libsodium. Run from any directory:
    python tests/generate_vectors.py > tests/vectors/sae1.json
    python tests/generate_vectors.py --check
Fixed salts/nonces and visible inputs are exclusively for testing.
"""

import ctypes as c
import ctypes.util
import json
from pathlib import Path
import sys
import textwrap


def generate_vectors():
    argon_path = ctypes.util.find_library("argon2")
    sodium_path = ctypes.util.find_library("sodium")
    if not argon_path or not sodium_path:
        raise RuntimeError("system libargon2 and libsodium are required")
    argon = c.CDLL(argon_path)
    sodium = c.CDLL(sodium_path)
    sodium.sodium_init.restype = c.c_int
    if sodium.sodium_init() < 0:
        raise RuntimeError("libsodium initialization failed")
    argon.argon2_hash.argtypes = [
        c.c_uint32, c.c_uint32, c.c_uint32, c.c_void_p, c.c_size_t,
        c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t,
        c.c_void_p, c.c_size_t, c.c_int, c.c_uint32,
    ]
    argon.argon2_hash.restype = c.c_int
    sodium.crypto_pwhash.argtypes = [
        c.c_void_p, c.c_ulonglong, c.c_void_p, c.c_ulonglong,
        c.c_void_p, c.c_ulonglong, c.c_size_t, c.c_int,
    ]
    sodium.crypto_pwhash.restype = c.c_int
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = [
        c.c_void_p, c.POINTER(c.c_ulonglong), c.c_void_p, c.c_ulonglong,
        c.c_void_p, c.c_ulonglong, c.c_void_p, c.c_void_p, c.c_void_p,
    ]
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt.restype = c.c_int
    cases = [
        ("empty", ""),
        ("ascii-reference", "test text SAE1"),
        ("unicode-multiline", "Синтетика: café / 🚀\nline two\r\n\t!@#$%^&*()\\\"'\x00"),
        ("max-ascii", "A" * 4096),
        ("max-unicode", "🚀" * 1024),
    ]
    vectors = []
    for index, (name, text) in enumerate(cases):
        password = b"test password -- not a production credential"
        if name == "unicode-multiline":
            password = "Синтетический пароль".encode("utf-8") + b"\x00test"
        # Preserve the existing ascii-reference input exactly.
        seed = 0 if name == "ascii-reference" else index + 1
        salt = bytes((seed + i) % 256 for i in range(16))
        nonce = bytes((seed + i) % 256 for i in range(24))
        message = text.encode("utf-8")
        key = c.create_string_buffer(32)
        # Reference Argon2 implementation: t=3, m=262144 KiB, p=1,
        # type=2 (Argon2id), version=0x13. No project constants are used.
        if argon.argon2_hash(3, 262144, 1, password, len(password), salt,
                            len(salt), key, 32, None, 0, 2, 0x13) != 0:
            raise RuntimeError("reference Argon2id failed")
        sodium_key = c.create_string_buffer(32)
        if sodium.crypto_pwhash(sodium_key, 32, password, len(password),
                                salt, 3, 268435456, 2) != 0:
            raise RuntimeError("libsodium Argon2id failed")
        if key.raw != sodium_key.raw:
            raise RuntimeError("independent Argon2 implementations disagree")
        # Literal encoding of the FORMAT.md field table, not build_header().
        header = bytes.fromhex("010101011300000003100000000120101810")
        header += len(message).to_bytes(2, "big") + salt + nonce
        aad = b"SAE1:" + header
        ciphertext = c.create_string_buffer(len(message) + 16)
        length = c.c_ulonglong()
        if sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, c.byref(length), message, len(message), aad, len(aad),
            None, nonce, key,
        ) != 0:
            raise RuntimeError("reference AEAD encryption failed")
        if length.value != len(message) + 16:
            raise RuntimeError("unexpected AEAD output length")
        vector = {
            "name": name,
            "password_hex": password.hex(),
            "plaintext_utf8_hex": message.hex(),
            "salt_hex": salt.hex(),
            "nonce_hex": nonce.hex(),
            "key_hex": key.raw.hex(),
            "header_hex": header.hex(),
            "ciphertext_hex": ciphertext.raw[:-16].hex(),
            "tag_hex": ciphertext.raw[-16:].hex(),
        }
        if name == "ascii-reference":
            raw = (header + ciphertext.raw).hex().upper()
            vector["encoded"] = "SAE1:\n" + "\n".join(
                " ".join(textwrap.wrap(line, 4)) for line in textwrap.wrap(raw, 32)
            )
        vectors.append(vector)
    return {
        "schema": "SAE1 synthetic vectors, 60-byte header",
        "reference": "libargon2 argon2_hash + libsodium C API; no project/PyNaCl imports",
        "vectors": vectors,
    }


if __name__ == "__main__":
    result = generate_vectors()
    if sys.argv[1:] == ["--check"]:
        expected = json.loads((Path(__file__).parent / "vectors" / "sae1.json").read_text())
        if result != expected:
            raise SystemExit("Reference vectors differ")
        print("5 vectors reproduced; libargon2 and libsodium KDF outputs agree")
    elif not sys.argv[1:]:
        print(json.dumps(result, ensure_ascii=True, indent=2))
    else:
        raise SystemExit("usage: generate_vectors.py [--check]")
