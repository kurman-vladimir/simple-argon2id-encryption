"""Pure Python tests for the strict printable SAE1 format."""

import pytest

from simple_argon2id_encryption.encoding import (
    MAX_PACKET_BYTES, MIN_PACKET_BYTES, build_header, format_hex, parse_hex,
)


def test_formatted_packet_round_trip() -> None:
    packet = build_header(bytes(range(16)), bytes(range(24)), 0) + bytes(16)
    printed = format_hex(packet)
    assert printed.startswith("SAE1:\n")
    assert parse_hex(printed) == packet
    assert parse_hex("SAE1:" + packet.hex().lower()) == packet


def test_input_whitespace_is_ignored() -> None:
    packet = build_header(bytes(range(16)), bytes(range(24)), 0) + bytes(16)
    raw = packet.hex().upper()
    assert parse_hex("SAE1:\n" + "\t".join(raw[i:i+4] for i in range(0,len(raw),4))) == packet


@pytest.mark.parametrize("bad", [
    "", "SAE0:", "SAE1:XX", "SAE1:0", "SAE1:\u2003" + "00"*MIN_PACKET_BYTES,
    "SAE1:" + "00"*(MIN_PACKET_BYTES - 1), "SAE1:" + "00"*(MAX_PACKET_BYTES + 1), "SAE1:" + "00"*MIN_PACKET_BYTES + "!",
    "SAE1:" + " "*17000,
])
def test_invalid_text_is_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_hex(bad)
