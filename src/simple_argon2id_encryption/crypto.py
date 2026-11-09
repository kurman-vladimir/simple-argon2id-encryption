"""Password-based authenticated encryption of short UTF-8 text.

SAE1 is a fixed, versioned format.  Cryptographic operations use PyNaCl,
which delegates to libsodium; no cryptographic primitives are reimplemented.
"""

from __future__ import annotations

import secrets

import nacl.bindings
from nacl.exceptions import CryptoError
from nacl.pwhash import argon2id

from .encoding import (
    ARGON2_MEMLIMIT, ARGON2_OPSLIMIT, ARGON2_VERSION as ARGON2_VERSION, HEADER_BYTES,
    KEY_BYTES, MAX_PLAINTEXT_BYTES, NONCE_BYTES, NONCE_OFFSET, PREFIX,
    PROFILE_ID, SALT_BYTES, SALT_OFFSET, TAG_BYTES,
    build_header, format_hex, parse_hex,
)

MAX_PASSWORD_BYTES = 4096

# Literal prefix and header are authenticated as AEAD associated data.
_AAD_PREFIX = PREFIX.encode("ascii")
_HEADER_BYTES = HEADER_BYTES


class DecryptionError(ValueError):
    """Authentication failed, input was corrupted, or the password is wrong."""


def _encode_plaintext(plaintext: str) -> bytes:
    # Reject obviously oversized strings before allocating their UTF-8 copy.
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ValueError("plaintext exceeds 4096 UTF-8 bytes")
    try:
        message = plaintext.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        pass
    else:
        if len(message) > MAX_PLAINTEXT_BYTES:
            raise ValueError("plaintext exceeds 4096 UTF-8 bytes")
        return message
    # Raise outside the handler: Unicode exceptions retain the original data
    # and may display portions of it when a caller formats a traceback.
    raise ValueError("plaintext is not valid UTF-8")


def _decode_plaintext(message: bytes) -> str:
    try:
        return message.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass
    raise DecryptionError("authenticated content is not valid UTF-8")


def _check_password(password_bytes: bytes) -> None:
    if not isinstance(password_bytes, bytes):
        raise TypeError("password_bytes must be bytes")
    if not 1 <= len(password_bytes) <= MAX_PASSWORD_BYTES:
        raise ValueError("password length must be between 1 and 4096 bytes")


def derive_key(password_bytes: bytes, salt: bytes, *, profile: int = PROFILE_ID) -> bytes:
    """Return a 32-byte SAE1 key using Argon2id v1.3 (libsodium).

    Identical inputs produce the same key.  Salt MUST be random on encryption.
    No caller-provided custom KDF parameters are accepted by the SAE1 profile.
    """
    _check_password(password_bytes)
    if type(profile) is not int or profile != PROFILE_ID:
        raise ValueError("unsupported cryptographic profile")
    if not isinstance(salt, bytes) or len(salt) != SALT_BYTES:
        raise ValueError("salt must be exactly 16 bytes")
    if argon2id.ALG != nacl.bindings.crypto_pwhash_ALG_ARGON2ID13:
        raise RuntimeError("Argon2id v1.3 support is required")
    if (
        nacl.bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES != KEY_BYTES
        or nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES != NONCE_BYTES
        or nacl.bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES != TAG_BYTES
        or argon2id.SALTBYTES != SALT_BYTES
    ):
        raise RuntimeError("incompatible PyNaCl/libsodium constants")
    return argon2id.kdf(
        KEY_BYTES,
        password_bytes,
        salt,
        opslimit=ARGON2_OPSLIMIT,
        memlimit=ARGON2_MEMLIMIT,
    )


def encrypt_text(plaintext: str, password_bytes: bytes) -> str:
    """Encrypt at most 4096 UTF-8 bytes; return printable SAE1 HEX."""
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be str")
    _check_password(password_bytes)
    message = _encode_plaintext(plaintext)

    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    header = build_header(salt, nonce, len(message))
    key = derive_key(password_bytes, salt, profile=PROFILE_ID)
    ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        message, _AAD_PREFIX + header, nonce, key
    )
    return format_hex(header + ciphertext)


def decrypt_text(encoded: str, password_bytes: bytes) -> str:
    """Decrypt SAE1 HEX after authentication; reject invalid/corrupt input."""
    _check_password(password_bytes)
    packet = parse_hex(encoded)  # strict parsing and size checks before Argon2id
    salt = packet[SALT_OFFSET:NONCE_OFFSET]
    nonce = packet[NONCE_OFFSET:_HEADER_BYTES]
    ciphertext = packet[_HEADER_BYTES:]
    key = derive_key(password_bytes, salt, profile=PROFILE_ID)
    try:
        message = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, _AAD_PREFIX + packet[:_HEADER_BYTES], nonce, key
        )
    except CryptoError:
        pass
    else:
        return _decode_plaintext(message)
    raise DecryptionError("wrong password or corrupted encrypted text")
