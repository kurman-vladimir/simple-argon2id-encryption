"""Interactive password-based encryption of short UTF-8 text."""

from __future__ import annotations

import argparse
import getpass
import hmac
import sys
import unicodedata
import warnings
from collections.abc import Sequence

from . import __version__
from .encoding import MAX_FORMATTED_LENGTH, MAX_PLAINTEXT_BYTES, parse_hex


class InputError(ValueError):
    """A safe, fixed diagnostic for an interactive input error."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's original message can include sensitive rejected arguments.
        raise InputError("invalid command or arguments; use help")


def build_parser() -> argparse.ArgumentParser:
    """Create the public command-line parser; no data arguments are accepted."""
    parser = _Parser(
        prog="simple-argon2id-encryption",
        description="Local password-based encryption of short UTF-8 text.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("encrypt", help="Encrypt a short text interactively")
    commands.add_parser("decrypt", help="Decrypt multiline SAE1 HEX interactively")
    commands.add_parser("version", help="Show version")
    commands.add_parser("help", help="Show help")
    return parser


def _hidden(prompt: str) -> str:
    # getpass normally falls back to echoing input when echo control fails.
    # Turn that warning into an error before fallback reads any secret.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt, stream=sys.stderr)


def _password(prompt: str = "Password: ") -> bytes:
    value = _hidden(prompt)
    if len(value) > 4096:
        raise InputError("password must contain 1 through 4096 UTF-8 bytes")
    try:
        password = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise InputError("password must be valid UTF-8") from None
    if not 1 <= len(password) <= 4096:
        raise InputError("password must contain 1 through 4096 UTF-8 bytes")
    return password


def _read_hex() -> str:
    print("Enter SAE1 HEX; finish with END on a line by itself:", file=sys.stderr)
    lines = []
    total = 0
    while True:
        # Bound each read as well as the complete input. Allow room for END.
        line = sys.stdin.readline(MAX_FORMATTED_LENGTH - total + 5)
        if not line:
            raise InputError("HEX input ended before END")
        if line.rstrip("\r\n") == "END":
            break
        total += len(line)
        if total > MAX_FORMATTED_LENGTH:
            raise InputError("HEX input is too long")
        lines.append(line)
    encoded = "".join(lines)
    try:
        parse_hex(encoded)
    except ValueError:
        raise InputError("invalid SAE1 HEX, header, parameters or packet length") from None
    return encoded


def _encrypt() -> None:
    from .crypto import encrypt_text

    text = _hidden("Text (one line, at most 4096 UTF-8 bytes; hidden): ")
    if len(text) > MAX_PLAINTEXT_BYTES or len(text.encode("utf-8")) > MAX_PLAINTEXT_BYTES:
        raise InputError("text exceeds 4096 UTF-8 bytes")
    if "\r" in text or "\n" in text:
        raise InputError("enter a single line of text")
    password = _password()
    confirmation = _password("Confirm password: ")
    if not hmac.compare_digest(password, confirmation):
        raise InputError("passwords do not match")
    print(encrypt_text(text, password), flush=True)


def _terminal_text(text: str) -> str:
    """Make terminal control/format characters visible without executing them."""
    return "".join(
        c.encode("unicode_escape").decode("ascii")
        if c not in "\n\t" and unicodedata.category(c) in ("Cc", "Cf") else c
        for c in text
    )


def _decrypt() -> None:
    from .crypto import DecryptionError, decrypt_text

    encoded = _read_hex()
    password = _password()
    try:
        text = decrypt_text(encoded, password)
    except DecryptionError:
        raise InputError("decryption failed: wrong password or corrupted encrypted text") from None
    # Read consent from the terminal just like the password. Never consume a
    # preloaded YES from the untrusted HEX input stream after END.
    answer = _hidden("Integrity verified. Type YES to display decrypted text (hidden): ")
    if answer != "YES":
        print("Cancelled; decrypted text was not displayed.", file=sys.stderr)
        return
    print(_terminal_text(text) if sys.stdout.isatty() else text, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; report errors without input data or tracebacks."""
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        if args.command in (None, "help"):
            parser.print_help()
        elif args.command == "version":
            print(f"{parser.prog} {__version__}")
        elif args.command == "encrypt":
            _encrypt()
        elif args.command == "decrypt":
            _decrypt()
        return 0
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except getpass.GetPassWarning:
        print("error: hidden input is unavailable; use an interactive terminal", file=sys.stderr)
        return 2
    except EOFError:
        print("error: input ended before completion", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except UnicodeError:
        print("error: input or output is not valid for the text encoding", file=sys.stderr)
        return 2
    except ImportError:
        print("error: PyNaCl is required; install requirements.txt", file=sys.stderr)
        return 2
    except (OSError, MemoryError, RuntimeError):
        print("error: operation failed; check terminal access and available memory", file=sys.stderr)
        return 1
    except ValueError:
        print("error: invalid input; operation failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
