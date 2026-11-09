# simple-argon2id-encryption

A small command-line tool for password-based encryption of short UTF-8
text. It produces printable HEX that can be copied, printed or entered
by hand, then decrypted with the original password.

**Development version 0.2.0.** This project has not received an independent
security audit. Use synthetic data while evaluating it.

## Requirements

| Component | Supported configuration |
|---|---|
| Python | CPython 3.10–3.14 |
| PyNaCl | `>=1.6.2,<2` |
| libsodium | The patched version bundled with supported PyNaCl; see below |
| Terminal | Interactive terminal with working hidden input and UTF-8 support |
| Memory | 256 MiB for each Argon2id operation, plus Python and library overhead |

PyNaCl supplies the native cryptographic implementation. Its normal binary
installation includes libsodium, so a separate system installation is not
needed. PyNaCl 1.6.2 includes libsodium 1.0.20-stable, build 2025-12-31,
with an upstream security fix. Use maintained, patched builds rather than
selecting a library by version number alone. See the upstream
[installation guide](https://github.com/pyca/pynacl/blob/main/INSTALL.rst)
and [changelog](https://pynacl.readthedocs.io/en/latest/changelog/).

Custom builds using system libsodium must provide Argon2id v1.3 and
XChaCha20-Poly1305-IETF. System libsodium 1.0.22 has been verified for the
reference vectors. Other system builds require native testing; Python
dependency checks do not audit a separately installed C library.

The local suite has passed on Linux with Python 3.14.7 and PyNaCl 1.6.2.
The configured CI matrix covers Python 3.10–3.14 on Linux, plus Python 3.14
on macOS and Windows. Those targets are not a claim of completed CI runs.
POSIX terminal tests do not run on Windows.

## Installation

Download the repository and open a terminal in its directory. Create a
virtual environment and install the dependencies.

Linux or macOS:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Check the available commands:

```sh
python run.py help
python run.py version
```

`--help` and `--version` are also available. Once dependencies are
installed, encryption and decryption run locally without network access.

## Encrypt

```sh
python run.py encrypt
```

Enter one line of text, such as `A quiet morning in the garden.` The text
is hidden while you type. Enter a password, then enter it again to confirm.
Passwords are hidden too; the command stops if hidden input is unavailable.

The command prints a complete `SAE1:` packet in uppercase HEX. Text may be
empty or contain up to 4096 UTF-8 bytes. Multibyte characters count toward
the byte limit. Passwords must contain 1–4096 UTF-8 bytes and are used
exactly as entered, without trimming or Unicode normalization.

Do not put plaintext or passwords after the command. They are requested
interactively, so they do not need to enter shell history. Rejected
arguments are not repeated in error messages.

## Print or copy the HEX

The output starts with `SAE1:` on its own line, followed by four-digit
HEX groups, eight groups per full line. The final line may be shorter.
A fresh salt and nonce make the output different on each encryption.

You can redirect the encrypted output to a text file for printing:

```sh
python run.py encrypt > encrypted.txt
```

Only the encrypted packet goes to standard output; prompts and errors go
to standard error. Check that encryption succeeded before relying on the
file. When printing, include the marker and every data line, disable
clipping, and keep the characters legible. Verify a printed or copied
packet by entering it back into `decrypt`.

The packet includes the version, algorithm identifiers, fixed parameters,
salt, nonce, ciphertext length and authentication tag. All header fields
are authenticated. The exact layout and an optional separate worksheet
for line checksums are described in [FORMAT.md](FORMAT.md). The CLI does
not accept checksum annotations in the HEX input.

## Decrypt and restore the text

```sh
python run.py decrypt
```

1. Paste or type the complete packet, beginning with `SAE1:`.
2. Enter `END` on a line by itself to finish the HEX input.
3. Enter the original password when prompted.
4. After successful authentication, type exactly `YES` at the separate
   hidden terminal prompt to display the text.

Any other confirmation cancels display. Consent is never read from the HEX
stream after `END`. EOF before `END` is an error.
Do not enter `END` as part of the saved packet.

Lowercase HEX and ASCII spaces, tabs and line breaks are accepted, even
between individual digits. The total input limit is 16384 characters.
Changing line wrapping is safe; changing, omitting or reordering HEX digits
is not. The decoder never repairs damaged input automatically.

Malformed headers, unsupported parameters and incorrect lengths are
rejected before Argon2id runs. A wrong password or failed authentication
produces an error and no plaintext. On a terminal, control and Unicode
format characters are shown as escape sequences, except line feeds and
tabs; this prevents terminal commands embedded in text from executing.
Redirected plaintext output preserves the text and adds a final newline.
Displayed text can enter terminal scrollback, recordings or redirected output.

Keep an intact copy of the packet and retain access to the password.
**There is no password reset or recovery mechanism.** A lost password or
unrecoverably damaged packet means the text cannot be restored by this
tool. Authentication detects damage; it does not reconstruct missing data.

## Cryptography and security limits

- Argon2id v1.3: 3 operations, 256 MiB memory, 16-byte random salt and a
  32-byte derived key.
- XChaCha20-Poly1305-IETF: fresh 24-byte nonce and a 16-byte authentication
  tag, implemented through PyNaCl/libsodium.
- Associated data includes the literal `SAE1:` marker and the entire
  60-byte header. Algorithm costs are fixed and validated before use.

Use a strong, unique password. Argon2id increases the cost of guessing;
it cannot make a weak password safe from offline guessing. The packet
reveals the exact UTF-8 plaintext byte length.

The tool cannot protect against a compromised host, memory inspection,
terminal recording or loss of the password. Python does not guarantee
secure erasure of password, key or plaintext objects. The CLI writes no
plaintext or passwords to logs, but displaying text exposes it to the
terminal and anything recording that terminal.

SAE1 version 1 and the `derive_key` API are frozen in [FORMAT.md](FORMAT.md)
and [API.md](API.md). Earlier unreleased drafts are incompatible. Keep an
intact packet, the password and a copy of the format documentation for
recovery. See [SECURITY.md](SECURITY.md) for security status and reporting
guidance.

## Development checks

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m pip check
python -m pip_audit --local --strict --skip-editable --progress-spinner off
```

Tests use synthetic strings and the actual PyNaCl implementation. They
cover Unicode, byte limits, authentication failures, damaged input,
transcription, fresh processes and interactive CLI behavior.

Five fixed reference vectors can also be reproduced without importing the
project or PyNaCl. This requires system libargon2 and libsodium:

```sh
python -I -S tests/generate_vectors.py --check
```

See [tests/README.md](tests/README.md) for coverage and limitations.

[GitHub Actions](.github/workflows/ci.yml) is configured to run tests, Ruff,
dependency consistency checks, an audit of installed Python dependencies,
and independent vector reproduction. The dependency audit skips editable
source projects and checks third-party packages. It runs on pushes, pull requests,
manual invocation and a weekly schedule. Audit checks require network
access and cover known reported Python dependency vulnerabilities; they
do not establish that the application or native libraries are secure.

## License

[MIT](LICENSE).
