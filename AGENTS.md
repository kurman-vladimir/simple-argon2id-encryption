# Repository instructions for Codex

## Project

- Name: `simple-argon2id-encryption`.
- Small Python 3.10+ package for local password-based encryption of UTF-8 text of at most 4096 bytes.
- `src/` layout; CLI entry point: `simple-argon2id-encryption`.
- Keep the public code and documentation concise and neutral, describing only general-purpose text encryption.
- Avoid adding unrelated features such as file encryption, network services, web UIs, or streaming.

## Current state (v0.2.0)

- `crypto.py` provides `derive_key`, `encrypt_text`, `decrypt_text`.
- `encoding.py` provides `format_hex`, `parse_hex`.
- `cli.py` implements interactive `encrypt`/`decrypt`, `help` and `version`.
- Hidden input uses getpass without an echoing fallback; decrypt requires
  an END line and separate hidden terminal YES confirmation before display.
- `FORMAT.md` freezes SAE1 version 1, profile 0x01, with explicit parameters.
- `API.md` freezes the derive_key signature, profile and derived bytes.
- The user approved replacing the unreleased 41-byte SAE1 header with a
  60-byte header under the same marker; obsolete draft packets are unsupported.
- The earlier environment lacked PyNaCl, so native PyNaCl test execution on the user's machine is a priority. Never assume prior compatibility tests eliminate the need for native testing.
- This is developmental software, not yet independently security audited. Use synthetic test data.

## Cryptographic requirements — do not silently change

- Argon2id v1.3 (`nacl.pwhash.argon2id.kdf`), 3 operations, 256 MiB, fresh 16-byte salt.
- Derived key length: 32 bytes.
- XChaCha20-Poly1305-IETF (`nacl.bindings`), fresh 24-byte nonce, 16-byte AEAD tag.
- Authenticated associated data includes the ASCII `SAE1:` prefix and the 60-byte binary header.
- `SAE1:` plus uppercase HEX, grouped four characters, eight groups per line; input parser accepts ASCII whitespace and lowercase hex.
- Max plaintext 4096 UTF-8 bytes. Check parsing bounds BEFORE running expensive Argon2id.
- Both encryption and decryption use the single public `derive_key(password_bytes, salt, *, profile=...)` function.
- Do not implement custom cryptographic primitives. Version any incompatible wire-format or algorithm change explicitly.
- Never expose passwords or plaintext in log messages, argv, diagnostics, or committed fixtures.

## Development workflow

- First inspect actual files and run `python -m pytest -q` with the genuine PyNaCl package installed.
- Preserve `FORMAT.md` semantics and test vectors unless a documented versioned change is approved.
- Add unit/integration tests for every change and run the full suite.
- Prefer small modules and minimal dependencies; follow the existing project conventions.
- Do not claim a security audit or successful tests unless actually performed.
- Do not push to remote repositories or publish artifacts without explicit approval.

## Next implementation steps

1. Preserve frozen SAE1 packets, KDF results and compatibility vectors.
2. Run tests with genuine PyNaCl; keep reference reproduction and CI checks.
3. Extend platform/terminal verification and obtain an independent security
   review before relying on the developmental software for real data.
