# SAE1: encrypted text format (version 1)

This document freezes SAE1 version 1, profile 0x01, with a 60-byte header.
The layout, algorithm suite, resource limits, AAD, canonical formatting,
input bounds and reference vectors below are permanent compatibility
requirements. This is a project format, not a third-party standard.
Freezing the format does not assert that the implementation is audited.

The earlier unreleased 41-byte-header draft is unsupported. Its replacement
was approved before the format freeze. No further incompatible changes may
reuse the `SAE1:` marker; use a new marker and separate specification.
Existing SAE1 packets must retain their interpretation and decodability.
See [API.md](API.md) for the frozen `derive_key` contract.

## Version, algorithms and parameters

The exact ASCII marker `SAE1:` and binary version byte `0x01` identify
serialization version 1. Profile `0x01` permits only the values below.
Algorithms and costs are also stored explicitly in the header. IDs are
SAE1-specific, not the numeric constants of a particular library.

| Property | Required value |
|---|---|
| KDF ID | 0x01: Argon2id |
| Argon2 version | 0x13: v1.3, libsodium `ALG_ARGON2ID13` |
| Operations | 3 |
| Memory | 268435456 bytes (256 MiB) |
| Parallelism | 1 lane, libsodium `crypto_pwhash` interface |
| Derived key | 32 bytes |
| Salt | 16 uniformly random bytes, fresh for each encryption |
| AEAD ID | 0x01: `crypto_aead_xchacha20poly1305_ietf` |
| Nonce | 24 uniformly random bytes, fresh for each encryption |
| Authentication tag | 16 bytes |

No defaults, algorithm negotiation or attacker-selected resource costs are
permitted. Every serialized parameter must match exactly before KDF runs.

Passwords are arbitrary nonempty bytes, at most 4096 bytes. No Unicode
normalization is applied. Plaintext is strict UTF-8, from 0 through 4096
bytes; the limit is on encoded bytes, not characters.

Unknown versions, profiles, algorithms and unsupported parameters MUST be
rejected. SAE1 permits only profile 0x01. Incompatible algorithm, cost,
layout or interpretation changes require a new version marker; they must
not silently change this profile or reuse SAE1.

## Binary packet and authentication

All multibyte integers are unsigned, big-endian. Lengths are in bytes.

| Offset | Field | Size | Required value |
|---|---|---|---|
| 0 | Binary version | 1 | 0x01 |
| 1 | Profile | 1 | 0x01 |
| 2 | KDF identifier | 1 | 0x01 |
| 3 | AEAD identifier | 1 | 0x01 |
| 4 | Argon2 version | 1 | 0x13 |
| 5 | Argon2 operations | 4 | 3 |
| 9 | Argon2 memory | 4 | 268435456 |
| 13 | Argon2 lanes | 1 | 1 |
| 14 | Key size | 1 | 32 |
| 15 | Salt size | 1 | 16 |
| 16 | Nonce size | 1 | 24 |
| 17 | Tag size | 1 | 16 |
| 18 | Ciphertext size N, excluding tag | 2 | 0 through 4096 |
| 20 | Salt | 16 | Random |
| 36 | Nonce | 24 | Random |
| 60 | Ciphertext | N | AEAD output |
| 60 + N | AEAD tag | 16 | AEAD output |

The packet contains exactly these fields, without padding or extensions.
Its size MUST equal `60 + N + 16`, from 76 through 4172 bytes. The tag is
the last 16 bytes of libsodium's combined AEAD output. Declared sizes never
control offsets or KDF resource allocation: unsupported values are rejected.

Associated data is exactly `b"SAE1:" + packet[:60]` (65 bytes), binding
the marker and every header field, including ciphertext length.
Encryption and decryption use the same public `derive_key` function with
profile 0x01 and explicit fixed costs.

No plaintext may be returned before successful AEAD authentication and
strict UTF-8 decoding. Wrong passwords, modified headers, ciphertext or
tags MUST fail. The decoder MUST NOT ignore trailing bytes or try alternate
packet boundaries, profiles, passwords or repairs.

Appended or truncated bytes are rejected by exact length validation before
Argon2id. If an attacker also alters the declared length to match the
modified packet, AEAD authentication still fails. The decoder consumes
one complete packet and never silently ignores extra bytes.

## Canonical printable representation

The marker `SAE1:` occupies its own line. The packet is uppercase HEX,
with four HEX digits per group, eight groups per line, one ASCII space
between groups and LF between lines. Full data lines are 39 characters
(32 HEX digits and seven spaces). The final line may be shorter, and its
final group may contain two digits. There is no padding and no final LF.

The maximum canonical representation is 10435 characters. Encryption
always emits this canonical representation.

## Manual input and strict validation

The decoder accepts lowercase HEX and arbitrary combinations of ASCII
space, tab, CR, LF, VT and FF after the marker, including between individual
HEX digits and at the start or end of the body. The exact marker must be
at the start of input; it is case-sensitive and cannot contain whitespace.

The implementation accepts at most 16384 input characters, including the
marker and whitespace. Arbitrary whitespace placement is permitted within
this resource bound, not unlimited whitespace volume.

Before running Argon2id, the decoder MUST:

1. Require a string and enforce the total input bound.
2. Require the exact marker.
3. Reject every body character except ASCII HEX and the six allowed
   whitespace characters; Unicode whitespace and lookalike digits fail.
4. Remove only allowed whitespace and require an even number of HEX digits.
5. Require 152 through 8344 HEX digits (76 through 4172 decoded bytes).
6. Decode HEX and require the exact fixed header values in the field table.
7. Require N at most 4096 and exactly `60 + N + 16` decoded bytes.

`parse_hex` performs these structural checks, not authentication.
`format_hex` checks byte type and packet size and renders bytes; it does
not authenticate a packet. Only successful `decrypt_text` validates the
complete encrypted message. In particular, syntactically valid HEX is
not evidence of integrity.

Punctuation, comments, checksums, repeated markers, odd digits and unknown
profiles are rejected. Never substitute `O` for `0`, insert missing digits,
truncate extra bytes or otherwise repair input automatically. No diagnostic
should include password or plaintext content.

## Optional transcription worksheet (proposal)

For manual recording, a separate worksheet may list a one-based line
number and an eight-digit uppercase CRC32 for each canonical data line.
This is not an extension to SAE1 and is not currently parsed or generated
by the package. Keep the worksheet separate from the text to decrypt.

To make such a worksheet interoperable, use CRC-32/ISO-HDLC, as provided by
Python's `zlib.crc32`, over:

`b"SAE1:" + line_number.to_bytes(4, "big") + bytes.fromhex(data_line)`

Start line numbering at 1 after the marker. Record the total number of
data lines and each line's HEX digit count as well. Reconstruct canonical
32-digit lines before checking a copy entered with different whitespace.
The index helps detect a line copied to the wrong position; counts help
identify missing lines. A mismatch requires rechecking the original,
never automatic correction.

CRC32 is unkeyed, has collisions and can be recomputed by an attacker.
It only helps locate accidental transcription errors. A matching worksheet
never replaces AEAD verification or proves authenticity. Adding checksum
syntax to the actual SAE1 text would require a separately versioned text
wrapper.

## Fixed synthetic reference vector

All values here are synthetic. HEX below is ungrouped for reference.

- Password bytes: `b"test password -- not a production credential"`
- Salt: `000102030405060708090A0B0C0D0E0F`
- Nonce: `000102030405060708090A0B0C0D0E0F1011121314151617`
- Plaintext bytes: `b"test text SAE1"`
- Key: `242CA46400DFEDA631429E8208B31D1AC782957A0E84288085B2C4E50D497243`
- Combined ciphertext and tag:
  `CB8E4BAFF7732F9B399E3B0583DBA8FE0AE6EB1AC1C10C1B399285779412`

- Fixed fields and ciphertext length (first 20 bytes):
  `010101011300000003100000000120101810000E`

The binary packet is these 20 bytes, salt, nonce and combined ciphertext/tag,
in that order. The key matches the earlier draft; the tag changes because
the authenticated header changes. This AEAD vector was reproduced through
the system libsodium C API. Never use fixed salts or nonces for ordinary
encryption.

## Limitations

Argon2id slows but does not prevent offline guessing of weak passwords.
The packet reveals the exact UTF-8 plaintext byte length. SAE1 does not
protect against compromised hosts, memory inspection or terminal/session
logging. It cannot recover damaged or lost data. The project has not
received an independent security audit.
