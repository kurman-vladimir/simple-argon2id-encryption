"""SAE1 header, transcription and authenticated corruption tests."""

import pytest

from simple_argon2id_encryption.encoding import (
    HEADER_BYTES, SALT_OFFSET, NONCE_OFFSET, LENGTH_OFFSET,
    MAX_FORMATTED_LENGTH, MAX_PACKET_BYTES, MIN_PACKET_BYTES, build_header,
    format_hex, parse_hex,
)

# Synthetic packet from the new header and native libsodium reference vector.
PACKET = bytes.fromhex(
    '010101011300000003100000000120101810000e'
    '000102030405060708090a0b0c0d0e0f'
    '000102030405060708090a0b0c0d0e0f1011121314151617'
    'cb8e4baff7732f9b399e3b0583dba8fe0ae6eb1ac1c10c1b399285779412'
)
PASSWORD = b'test password -- not a production credential'


@pytest.mark.parametrize('size', [MIN_PACKET_BYTES, MIN_PACKET_BYTES + 1, MAX_PACKET_BYTES])
def test_canonical_layout(size):
    length = size - MIN_PACKET_BYTES
    packet = build_header(bytes(16), bytes(24), length) + bytes(length + 16)
    encoded = format_hex(packet)
    marker, *lines = encoded.splitlines()
    assert marker == 'SAE1:'
    assert all(len(line) == 39 for line in lines[:-1])
    groups = ' '.join(lines).split(' ')
    assert all(len(group) == 4 for group in groups[:-1])
    assert len(groups[-1]) in (2, 4)
    assert ''.join(groups) == packet.hex().upper()
    assert not encoded.endswith('\n')
    assert parse_hex(encoded) == packet


@pytest.mark.parametrize('space', [' ', '\t', '\r', '\n', '\v', '\f', ' \t\r\n\v\f'])
def test_whitespace_between_individual_digits(space):
    assert parse_hex('SAE1:' + space + space.join(PACKET.hex()) + space) == PACKET


def test_total_input_bound():
    compact = 'SAE1:' + PACKET.hex()
    encoded = compact + ' ' * (MAX_FORMATTED_LENGTH - len(compact))
    assert parse_hex(encoded) == PACKET
    with pytest.raises(ValueError, match='too long'):
        parse_hex(encoded + ' ')


@pytest.mark.parametrize('bad', [
    'sae1:' + PACKET.hex(), ' SAE1:' + PACKET.hex(),
    'SAE2:' + PACKET.hex(), 'SAE1:' + PACKET.hex() + 'SAE1:',
    'SAE1:' + PACKET.hex() + '0',
    *('SAE1:' + char + PACKET.hex() for char in ('O', 'I', '-', ':', '\x00', '\u00a0', '\u200b', '\uff10')),
])
def test_no_repair_or_extra_syntax(bad):
    with pytest.raises(ValueError):
        parse_hex(bad)


@pytest.mark.parametrize('size', [0, MIN_PACKET_BYTES - 1, MAX_PACKET_BYTES + 1])
def test_binary_size_bounds(size):
    with pytest.raises(ValueError):
        format_hex(b'\x01' * size)
    with pytest.raises(ValueError):
        parse_hex('SAE1:' + '01' * size)


@pytest.mark.parametrize('value', [None, b'SAE1:', 123])
def test_parser_types(value):
    with pytest.raises(TypeError):
        parse_hex(value)


def test_complete_native_vector(monkeypatch):
    pytest.importorskip('nacl')
    from simple_argon2id_encryption import crypto
    generated = iter([bytes(range(16)), bytes(range(24))])
    monkeypatch.setattr(crypto.secrets, 'token_bytes', lambda size: next(generated))
    assert crypto.encrypt_text('test text SAE1', PASSWORD) == format_hex(PACKET)
    assert crypto.decrypt_text(format_hex(PACKET), PASSWORD) == 'test text SAE1'


@pytest.mark.parametrize('bad', [
    'SAE1:0', 'SAE1:' + '01' * (MIN_PACKET_BYTES - 1), 'SAE1:' + '01' * (MAX_PACKET_BYTES + 1),
    'SAE1:' + ' ' * MAX_FORMATTED_LENGTH,
    'SAE1:' + '02' + PACKET[1:].hex(),
])
def test_reject_before_kdf(monkeypatch, bad):
    pytest.importorskip('nacl')
    from simple_argon2id_encryption import crypto
    def forbidden(*args, **kwargs):
        pytest.fail('KDF executed for invalid input')
    monkeypatch.setattr(crypto, 'derive_key', forbidden)
    with pytest.raises(ValueError):
        crypto.decrypt_text(bad, PASSWORD)


def test_all_packet_bytes_and_trailing_bytes_are_authenticated(monkeypatch):
    pytest.importorskip('nacl')
    from simple_argon2id_encryption import crypto
    # Derive once with native Argon2id; retain native AEAD for each mutation.
    key = crypto.derive_key(PASSWORD, PACKET[SALT_OFFSET:NONCE_OFFSET])
    monkeypatch.setattr(crypto, 'derive_key', lambda *args, **kwargs: key)
    for position in range(HEADER_BYTES, len(PACKET)):
        corrupt = bytearray(PACKET)
        corrupt[position] ^= 1
        with pytest.raises(crypto.DecryptionError):
            crypto.decrypt_text(format_hex(bytes(corrupt)), PASSWORD)
    for corrupt in (PACKET[:-1], PACKET + b'\x00', PACKET + PACKET):
        with pytest.raises(ValueError, match="length"):
            crypto.decrypt_text(format_hex(corrupt), PASSWORD)


def test_all_unknown_profiles_rejected_before_kdf(monkeypatch):
    pytest.importorskip('nacl')
    from simple_argon2id_encryption import crypto
    def forbidden(*args, **kwargs):
        pytest.fail('KDF executed for unsupported profile')
    monkeypatch.setattr(crypto, 'derive_key', forbidden)
    for profile in range(256):
        if profile == 1:
            continue
        encoded = 'SAE1:' + (PACKET[:1] + bytes([profile]) + PACKET[2:]).hex()
        with pytest.raises(ValueError, match='unsupported'):
            parse_hex(encoded)
        with pytest.raises(ValueError, match='unsupported'):
            crypto.decrypt_text(encoded, PASSWORD)


def test_profile_uses_explicit_frozen_kdf_parameters(monkeypatch):
    pytest.importorskip('nacl')
    from simple_argon2id_encryption import crypto
    calls = []
    def kdf(size, password, salt, *, opslimit, memlimit):
        calls.append((size, password, salt, opslimit, memlimit))
        return b'\0' * size
    monkeypatch.setattr(crypto.argon2id, 'kdf', kdf)
    assert crypto.derive_key(PASSWORD, PACKET[SALT_OFFSET:NONCE_OFFSET]) == b'\0' * 32
    assert calls == [(32, PASSWORD, PACKET[SALT_OFFSET:NONCE_OFFSET], 3, 268435456)]


def test_every_header_field_rejected_before_kdf(monkeypatch):
    pytest.importorskip('nacl')
    from simple_argon2id_encryption import crypto
    def forbidden(*args, **kwargs):
        pytest.fail('KDF executed for invalid header')
    monkeypatch.setattr(crypto, 'derive_key', forbidden)
    for offset in range(SALT_OFFSET):
        damaged = bytearray(PACKET)
        damaged[offset] ^= 1
        with pytest.raises(ValueError):
            crypto.decrypt_text(format_hex(bytes(damaged)), PASSWORD)


def test_salt_and_nonce_authenticated_as_aad(monkeypatch):
    pytest.importorskip('nacl')
    from simple_argon2id_encryption import crypto
    key = crypto.derive_key(PASSWORD, PACKET[SALT_OFFSET:NONCE_OFFSET])
    monkeypatch.setattr(crypto, 'derive_key', lambda *args, **kwargs: key)
    for offset in range(SALT_OFFSET, HEADER_BYTES):
        damaged = bytearray(PACKET)
        damaged[offset] ^= 1
        with pytest.raises(crypto.DecryptionError):
            crypto.decrypt_text(format_hex(bytes(damaged)), PASSWORD)


@pytest.mark.parametrize('length', [4097, 65535])
def test_excessive_declared_length(length):
    damaged = bytearray(PACKET)
    damaged[LENGTH_OFFSET:SALT_OFFSET] = length.to_bytes(2, 'big')
    with pytest.raises(ValueError, match='length'):
        parse_hex(format_hex(bytes(damaged)))


def test_obsolete_draft_rejected():
    old = bytes.fromhex('01') + bytes(range(16)) + bytes(range(24)) + bytes(29)
    with pytest.raises(ValueError):
        parse_hex('SAE1:' + old.hex())


@pytest.mark.parametrize('length', [-1, 4097, True, '13'])
def test_header_builder_rejects_invalid_length(length):
    with pytest.raises(ValueError):
        build_header(bytes(16), bytes(24), length)


def test_trailing_and_truncated_bytes_rejected_before_kdf(monkeypatch):
    pytest.importorskip('nacl')
    from simple_argon2id_encryption import crypto
    def forbidden(*args, **kwargs):
        pytest.fail('KDF executed for incorrect packet length')
    monkeypatch.setattr(crypto, 'derive_key', forbidden)
    for packet in (PACKET[:-1], PACKET + b'\x00', PACKET + PACKET):
        with pytest.raises(ValueError, match='length'):
            crypto.decrypt_text(format_hex(packet), PASSWORD)


def test_matching_forged_length_still_fails_authentication(monkeypatch):
    pytest.importorskip('nacl')
    from simple_argon2id_encryption import crypto
    key = crypto.derive_key(PASSWORD, PACKET[SALT_OFFSET:NONCE_OFFSET])
    monkeypatch.setattr(crypto, 'derive_key', lambda *args, **kwargs: key)
    for delta in (-1, 1):
        packet = bytearray(PACKET[:-1] if delta == -1 else PACKET + b'\x00')
        length = len(packet) - MIN_PACKET_BYTES
        packet[LENGTH_OFFSET:SALT_OFFSET] = length.to_bytes(2, 'big')
        encoded = format_hex(bytes(packet))
        assert parse_hex(encoded) == bytes(packet)
        with pytest.raises(crypto.DecryptionError):
            crypto.decrypt_text(encoded, PASSWORD)


@pytest.mark.parametrize('salt,nonce', [(bytes(15), bytes(24)), (bytes(16), bytes(23)), ('salt', bytes(24)), (bytes(16), None)])
def test_header_builder_rejects_invalid_salt_or_nonce(salt, nonce):
    with pytest.raises(ValueError):
        build_header(salt, nonce, 0)
