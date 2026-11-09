"""Strict, printable SAE1 hexadecimal serialization."""

from __future__ import annotations

import struct

MAX_PLAINTEXT_BYTES = 4096
PROFILE_ID = 0x01
VERSION = 1
KDF_ID = 1  # Argon2id
AEAD_ID = 1  # XChaCha20-Poly1305-IETF
ARGON2_VERSION = 0x13
ARGON2_OPSLIMIT = 3
ARGON2_MEMLIMIT = 256 * 1024 * 1024
ARGON2_LANES = 1
KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 24
TAG_BYTES = 16
# Big-endian fixed fields, followed by a uint16 ciphertext length.
_FIXED_FIELDS = struct.pack(
    ">BBBBBIIBBBBB", VERSION, PROFILE_ID, KDF_ID, AEAD_ID, ARGON2_VERSION,
    ARGON2_OPSLIMIT, ARGON2_MEMLIMIT, ARGON2_LANES, KEY_BYTES,
    SALT_BYTES, NONCE_BYTES, TAG_BYTES,
)
LENGTH_OFFSET = len(_FIXED_FIELDS)
SALT_OFFSET = LENGTH_OFFSET + 2
NONCE_OFFSET = SALT_OFFSET + SALT_BYTES
HEADER_BYTES = NONCE_OFFSET + NONCE_BYTES
MIN_PACKET_BYTES = HEADER_BYTES + TAG_BYTES
MAX_PACKET_BYTES = MIN_PACKET_BYTES + MAX_PLAINTEXT_BYTES
# The 4096-byte input formats to fewer than 11,000 characters.
MAX_FORMATTED_LENGTH = 16384
PREFIX = "SAE1:"
_HEX = frozenset("0123456789ABCDEFabcdef")
_WHITESPACE = frozenset(" \t\r\n\v\f")


def build_header(salt: bytes, nonce: bytes, ciphertext_length: int) -> bytes:
    """Build the fixed SAE1 header; ciphertext length excludes the tag."""
    if not isinstance(salt, bytes) or len(salt) != SALT_BYTES:
        raise ValueError("salt must be exactly 16 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
        raise ValueError("nonce must be exactly 24 bytes")
    if type(ciphertext_length) is not int or not 0 <= ciphertext_length <= MAX_PLAINTEXT_BYTES:
        raise ValueError("invalid ciphertext length")
    return _FIXED_FIELDS + ciphertext_length.to_bytes(2, "big") + salt + nonce


def format_hex(payload: bytes) -> str:
    """Render a complete SAE1 packet as uppercase HEX grouped for printing."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not MIN_PACKET_BYTES <= len(payload) <= MAX_PACKET_BYTES:
        raise ValueError("invalid SAE1 packet size")
    raw = payload.hex().upper()
    # 4 hex characters per group, 8 groups (32 characters) per printed line.
    lines = [" ".join(raw[i + j:i + j + 4] for j in range(0, min(32, len(raw) - i), 4))
             for i in range(0, len(raw), 32)]
    return PREFIX + "\n" + "\n".join(lines)


def parse_hex(encoded: str) -> bytes:
    """Decode SAE1 text, permitting only ASCII whitespace between HEX digits."""
    if not isinstance(encoded, str):
        raise TypeError("encoded must be str")
    if len(encoded) > MAX_FORMATTED_LENGTH:
        raise ValueError("encoded text is too long")
    if not encoded.startswith(PREFIX):
        raise ValueError("missing or unsupported SAE1 version marker")
    body = encoded[len(PREFIX):]
    if any(c not in _HEX and c not in _WHITESPACE for c in body):
        raise ValueError("encoded data must contain only hexadecimal digits and ASCII whitespace")
    raw = "".join(c for c in body if c not in _WHITESPACE)
    if len(raw) % 2:
        raise ValueError("odd number of HEX digits")
    if not 2 * MIN_PACKET_BYTES <= len(raw) <= 2 * MAX_PACKET_BYTES:
        raise ValueError("invalid SAE1 packet length")
    packet = bytes.fromhex(raw)
    if packet[:LENGTH_OFFSET] != _FIXED_FIELDS:
        raise ValueError("unsupported SAE1 version, algorithms or parameters")
    length = int.from_bytes(packet[LENGTH_OFFSET:SALT_OFFSET], "big")
    if length > MAX_PLAINTEXT_BYTES or len(packet) != HEADER_BYTES + length + TAG_BYTES:
        raise ValueError("invalid SAE1 ciphertext length or trailing bytes")
    return packet
