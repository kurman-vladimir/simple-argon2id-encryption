# SAE1 Python API contract

The SAE1 wire format in [FORMAT.md](FORMAT.md) and the following KDF API
are frozen. These compatibility guarantees do not imply a security audit.

## derive_key

```python
def derive_key(password_bytes: bytes, salt: bytes, *, profile: int = 1) -> bytes:
    ...
```

Import from `simple_argon2id_encryption.crypto`.

- `password_bytes`: nonempty `bytes`, at most 4096 bytes. Embedded zero
  bytes are allowed. No encoding, trimming or normalization occurs here.
- `salt`: exactly 16 bytes, supplied as `bytes`. Encryption generates a
  fresh random salt; callers must not reuse a test salt for ordinary use.
- `profile`: keyword-only, exact `int` value 1. Booleans, floats, strings
  and other profile values are rejected. The default remains 1.
- Output: exactly 32 bytes from Argon2id v1.3, 3 operations, 268435456
  bytes of memory, one lane, via `nacl.pwhash.argon2id.kdf`.
- Identical inputs produce the same key. Both encryption and decryption
  call this function. No caller-selected costs or changing library default
  costs are used. Resource failures never trigger a cheaper fallback.
- Non-byte passwords raise `TypeError`; empty/oversized passwords, invalid
  salts and unsupported profiles raise `ValueError`. Incompatible native
  algorithm/constants raise `RuntimeError`. Native resource failures
  propagate; callers must handle them. Error wording is not an API contract.

Do not change the signature, default profile, accepted profile-1 costs,
output size or derived bytes in a compatible release. Any future algorithm
must be separately versioned without reinterpreting SAE1 profile 1.

## Text encryption and decryption

`encrypt_text(plaintext: str, password_bytes: bytes) -> str` accepts strict
UTF-8 text from 0 through 4096 encoded bytes. It emits canonical SAE1 HEX.
`decrypt_text(encoded: str, password_bytes: bytes) -> str` validates the
packet before KDF and returns text only after AEAD authentication and strict
UTF-8 decoding. It preserves the exact Unicode sequence, including line
breaks and zero characters. No Unicode normalization is performed.

`DecryptionError`, a `ValueError` subclass, denotes failed authentication
or authenticated non-UTF-8 content. Structural input errors raise
`TypeError` or `ValueError`. Resource failures propagate. There is no
partial-plaintext result on any failure and no repair or format fallback.

The CLI accepts one plaintext line. Its terminal confirmation and escaping
of control/format characters concern presentation only; API results and
SAE1 bytes remain exact. Redirected CLI plaintext output is unescaped and
has the CLI's final newline.

## Compatibility fixtures

`tests/vectors/sae1.json` fixes five synthetic examples, including the
32-byte KDF results, complete headers, ciphertext and tags. Its SHA-256
with LF line endings is:

`f2a3b62677dd59eafa224174d02e5b120a63af9828b5f74069d5ac0e3659e12a`

`tests/test_security_contract.py` checks the public signature, fixed wire
constants, header bytes and vector artifact. The separate reference
generator reproduces the vectors using libargon2 and the libsodium C API
without importing this project or PyNaCl.

Python does not guarantee erasure of these objects. Do not log inputs,
keys or traceback frame locals. Safe exception messages do not make a
process with accessible memory safe.
