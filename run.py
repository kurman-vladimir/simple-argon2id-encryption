"""Run the local CLI from a source checkout."""

from pathlib import Path
import sys


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
    from simple_argon2id_encryption.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
