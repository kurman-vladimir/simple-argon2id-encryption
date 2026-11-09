# Implementation review — 2026-11-09

This is a repository implementation review with reproducible regression
checks. It is not a professional or independent security audit, and it
does not establish that the software is free of vulnerabilities. Only
synthetic inputs were used. Nothing was published.

## Scope and verified design

The review covered `crypto.py`, `encoding.py`, `cli.py`, the source launcher,
SAE1 serialization, dependency checks and the reference-vector generator.

| Area | Finding |
|---|---|
| Argon2id | PyNaCl selects `ALG_ARGON2ID13` explicitly. Costs are 3 operations and 268435456 bytes; output is 32 bytes. Reference libargon2 uses version 0x13 and one lane and produces the same keys. |
| KDF entry point | Both encrypt and decrypt call public `derive_key`. Its keyword-only profile, default 1, strict profile type, fixed costs and output are frozen in API.md. No cheaper resource-failure fallback exists. |
| AEAD | Native XChaCha20-Poly1305-IETF uses a 32-byte key, 24-byte nonce and appended 16-byte tag. PyNaCl checks the native return code before returning a message. |
| AAD | Exactly `b"SAE1:" + packet[:60]`. The version, algorithms, costs, lengths, salt and nonce are covered. Independent vectors detect shared encrypt/decrypt serialization mistakes. Additional negative tests use omitted, truncated and wrong-version AAD. |
| Randomness | Encryption draws separate 16-byte salt and 24-byte nonce values through `secrets.token_bytes`. A random-source failure aborts; it never uses fixed or weaker randomness. Tests do not prove entropy quality. |
| Parsing | Total text length, character alphabet, even digit count, packet size, every fixed parameter and exact declared length are checked before KDF. No alternate profiles, trailing-byte tolerance or repairs are accepted. |
| Authentication | Invalid tags do not return plaintext. Authenticated bytes must then decode as strict UTF-8. A wrong password and modified data share the authentication-failure diagnostic. |
| Input | Text and passwords use getpass with echo fallback forbidden. Password confirmation is bytewise constant-time comparison after bounded UTF-8 encoding. No data arguments or application logging are provided. |
| Reproducibility | Five fixed vectors, native round trips, separate-process recovery, exhaustive single-position mutations and truncations, and POSIX terminal tests are present. |

The reviewed algorithm usage matches the upstream
[password hashing API](https://doc.libsodium.org/password_hashing/default_phf)
and [XChaCha20-Poly1305 API](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).
Primitives are delegated to native libraries, not reimplemented here.

## Corrected findings

### Display consent could come from the ciphertext input stream

The old CLI read confirmation with `sys.stdin.readline()` after `END`.
A packet stream containing `END` followed by `YES` could automatically
approve display once the user entered the password through the terminal.
This bypassed the separate display decision; it did not bypass AEAD.

Confirmation now uses the same hidden terminal mechanism as password input
and refuses echo fallback. A real controlling-terminal regression pipes a
packet with a preloaded `YES`, enters the password at the terminal, then
answers `NO`. The packet-stream answer is not consumed as consent and no
plaintext is displayed. Unit tests also cover missing confirmation and
failure of hidden input.

### Authenticated text could execute terminal control sequences

The old CLI printed authenticated text directly. A valid encrypted message
can still contain terminal escape or formatting controls; authentication
does not make its presentation safe.

On terminal output, control and Unicode format characters are now shown as
visible escape sequences, except LF and tab. Redirected output preserves
the exact API text and adds the CLI's final newline. This changes terminal
presentation only, not SAE1 or the Python cryptographic API. Tests cover
ESC, C1 controls, carriage return, backspace and Unicode formatting controls.
A program that later displays raw redirected text must handle its own
terminal presentation.

### Unicode exception chains retained original data

The library previously chained `UnicodeEncodeError` and
`UnicodeDecodeError`. Those exceptions retain their complete input objects
and can expose fragments when a caller prints the chain.

Safe library exceptions are now raised outside the original handlers;
`__cause__` and `__context__` are absent. Native authentication failures are
also reported without retaining their lower-level exception chain. Tests
check both attributes and formatted tracebacks. This is not memory erasure:
Python frames and objects can still retain data, and logging frame locals
remains unsafe.

### Oversized plaintext was encoded before rejection

The library used to allocate a complete UTF-8 copy before checking the
4096-byte limit. It now rejects strings over 4096 characters before encoding,
then enforces the byte bound. This avoids the extra allocation for obviously
oversized strings. Password and confirmation input are also checked before
encoding. getpass itself still reads a whole input line; this is a local
interactive tool, not a bounded network-input service.

### Output flush failures could escape the success path

Encrypted and decrypted results are now flushed before the command returns
success. An output error becomes an operational failure. An output device
can still accept a partial write before failing; output cannot be rolled
back. The CLI does not echo exception details in the diagnostic.

## Dependency-check correction

The reported pip-audit failure was caused by a leftover editable project
registration in the environment. The source project is not a PyPI
requirement that the advisory service can identify. Documentation and CI
now use `--skip-editable` while retaining strict third-party collection.
This is not an advisory-ID exemption. Editable source code requires its own
review, including this project's review and tests.

Offline collection with the corrected command succeeded for 36 installed
packages. A dry run does not query advisory data, despite the tool's generic
success text. The full online audit could not complete because this
execution environment could not resolve `pypi.org`; no clean vulnerability
audit is claimed. `pip check` and Ruff completed successfully.

## Format and API freeze

SAE1 version 1, profile 0x01, the 60-byte header, fixed algorithm IDs and
costs, byte order, AAD, size bounds and printable interpretation are frozen
in [FORMAT.md](FORMAT.md). Incompatible changes require a new marker.
Earlier unreleased 41-byte-header drafts remain unsupported.

[API.md](API.md) freezes `derive_key(password_bytes, salt, *, profile=1)`.
Contract tests check its signature, fixed fields, deterministic result and
unchanged vector artifact. The fixes above do not change packet bytes,
keys, ciphertext or tags for valid inputs.

## Verification and limits

Run:

```sh
python -m pytest -q
python -m ruff check .
python -m pip check
python -I -S tests/generate_vectors.py --check
python -m pip_audit --local --strict --skip-editable --progress-spinner off
```

The full suite completed with **258 passed in 28.29 seconds**, without skips.
Ruff and `pip check` passed. Native tests were performed with CPython 3.14.7
and PyNaCl 1.6.2 on Linux.
The reference generator used system libargon2 and libsodium 1.0.22 without
importing project code or PyNaCl. It reproduced all five committed vectors,
including both 4096-byte cases, and cross-checked every Argon2 key between
libargon2 and libsodium. PyNaCl's bundled native library version was not
independently determined. AEAD reference generation uses libsodium rather
than a separately written XChaCha20-Poly1305 implementation.

Selected mutation tests reuse a derived key while retaining native AEAD;
full-cost native KDF runs in the end-to-end and vector checks. The test
suite is not exhaustive fuzzing, formal verification, a timing analysis,
a binary/dependency supply-chain audit, or testing of every supported
Python/OS/terminal combination. CI configuration has not been executed on
GitHub during this review.

The design does not prevent weak-password guessing, exact message-length
leakage, memory inspection, terminal recording or loss of the password.
There is no password recovery or damaged-data reconstruction mechanism.
The host, interpreter and native cryptographic libraries remain trusted.
