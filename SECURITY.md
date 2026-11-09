# Security

## Status

`0.2.0` is developmental software. The cryptographic core and interactive
terminal encryption/decryption commands are implemented.
Do not use this development release as the sole means of protecting data.

## Design

- Argon2id v1.3 with fixed, documented resource limits and an independently
  generated 16-byte salt for every encryption.
- XChaCha20-Poly1305 authenticated encryption with a newly generated
  24-byte nonce for every encryption.
- Strict, bounded parsing before password hashing; authenticated packet
  header; no return of plaintext if authentication fails.
- Hidden text and password input with `getpass`; refusal of an echoing
  fallback and password confirmation when encrypting.
- No plaintext/password arguments or logging; fixed diagnostics that do
  not repeat rejected arguments or exception contents.
- Explicit hidden terminal confirmation after successful authentication
  before displaying text; consent is separate from the HEX data stream.
- Terminal control/format characters are escaped when displaying plaintext
  to a terminal, except LF and tab. Redirected output preserves the text.
  Displayed output may enter scrollback or be redirected.

## Limitations

The format does not protect a weak password from all offline attacks. It
cannot protect against compromised operating systems, memory inspection,
process instrumentation, terminal logging, or loss of recovery information.
Authenticated encryption detects modifications but does not reconstruct a
damaged representation. The implementation has not been independently
security audited.

## Implementation review

A repository implementation review and regression tests are recorded in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md). This is not a professional or
independent security audit. SAE1 and the KDF contract are frozen in
[FORMAT.md](FORMAT.md) and [API.md](API.md). Format stability is not a claim
that the software is free of vulnerabilities.

## Vulnerability reports

Avoid placing private text or passwords in public issue reports. The
maintainer may publish a dedicated private reporting channel in a later
release.
