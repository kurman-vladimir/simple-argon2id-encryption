# Synthetic test suite

Run from the repository root with the actual PyNaCl dependency installed:

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

All passwords and plaintext values in this directory are synthetic.
Fixed salts and nonces are exclusively test inputs and must never be used
for ordinary encryption. Tests do not alter the production random source
outside individual monkeypatch scopes.

## Coverage

| Area | Tests |
|---|---|
| Empty, ASCII, Unicode, Cyrillic, punctuation, multiline and control characters | `test_crypto.py`, `test_robustness.py`, `test_vectors.py` |
| 4095/4096 UTF-8 bytes, one byte over, multibyte boundaries | `test_crypto.py`, `test_robustness.py`, `test_vectors.py` |
| Password limits, wrong passwords, exact Unicode preservation | `test_crypto.py`, `test_robustness.py` |
| Salt-only and nonce-only changes, independent random draws | `test_crypto.py`, `test_robustness.py` |
| Every HEX digit changed to another valid HEX digit; every truncation | `test_robustness.py` |
| Unknown version/profile/algorithms, altered cost and size fields, trailing bytes | `test_sae1.py`, `test_robustness.py` |
| Ciphertext/tag/header tampering, forged matching length, invalid authenticated UTF-8 | `test_sae1.py`, `test_robustness.py` |
| Reordered groups, new line wrapping, random whitespace and letter case | `test_robustness.py`, `test_encoding.py`, `test_sae1.py` |
| Independent vectors, encryption and decryption in separate fresh processes | `test_vectors.py` |
| CLI confirmation, safe errors, randomized transcription errors and POSIX terminal input | `test_cli.py` |
| Frozen API/wire contract, exception privacy, KDF/random failure behavior and AAD | `test_security_contract.py` |

Multiline plaintext is supported by the Python cryptographic API. The
interactive encryption command intentionally accepts one plaintext line;
multiline HEX input is supported by interactive decryption.

## Reproducible reference vectors

`vectors/sae1.json` contains five vectors: empty input, the existing ASCII
reference, mixed Unicode/Cyrillic/multiline input, 4096-byte ASCII and
4096-byte Unicode. Each records password and plaintext bytes, salt, nonce,
derived key, complete header, ciphertext and AEAD tag. The ASCII vector
also records the canonical printable packet.

`generate_vectors.py` imports neither the project nor PyNaCl. It encodes
the FORMAT.md table directly and calls:

- Reference libargon2 `argon2_hash`: Argon2id v1.3, t=3, m=262144 KiB,
  p=1, 32-byte output.
- System libsodium `crypto_pwhash`: the corresponding fixed costs;
  its key must equal libargon2's output for every vector.
- System libsodium XChaCha20-Poly1305-IETF C API with the exact header AAD.

To reproduce and compare the committed vectors without site packages:

```sh
python -I -S tests/generate_vectors.py --check
```

To write a separate candidate for review:

```sh
python -I -S tests/generate_vectors.py > /tmp/sae1-candidate.json
```

Regeneration requires system libargon2 and libsodium; these are test-only
requirements. Initial reproduction used libargon2 package 20190702-7 and
libsodium 1.0.22 on Linux x86-64. The existing ASCII key and ciphertext/tag
remain unchanged. The generator is also run by pytest in an isolated
process, from outside the repository working directory.

## Limits

- No test suite proves security or replaces an independent audit.
- The current execution environment is Python 3.14.7 with PyNaCl 1.6.2 on
  Linux. This run does not establish compatibility with every supported
  Python version, operating system or terminal.
- Argon2 keys are cross-checked with the reference implementation. AEAD
  reference generation uses system libsodium, so it is independent of the
  project's serialization and PyNaCl binding but not an independently
  written XChaCha20-Poly1305 implementation. PyNaCl's bundled libsodium
  version was not determined.
- Some exhaustive mutation and rewrapping tests reuse a derived key to
  keep native AEAD checks inexpensive. Native full-cost Argon2id is used
  in all vector, boundary, round-trip and fresh-process tests.
- Every single HEX position is mutated once, not to every possible
  replacement. Seeded random input cases are reproducible samples, not
  exhaustive fuzzing. Random-output tests do not prove entropy quality.
- The reference regeneration test skips when system reference libraries
  are unavailable; committed-vector checks still run. New cryptographic
  tests require PyNaCl rather than silently skipping its absence. POSIX
  terminal tests skip on other operating systems.
- Tests do not establish secure memory erasure or protection against a
  compromised host, terminal recording, or a weak password.
