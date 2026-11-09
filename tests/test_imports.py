"""Version and module import smoke tests."""

import importlib

import pytest

from simple_argon2id_encryption import __version__


def test_version() -> None:
    assert __version__ == "0.2.0"


@pytest.mark.parametrize("name", ["crypto", "encoding", "cli", "__main__"])
def test_modules_import(name: str) -> None:
    pytest.importorskip("nacl") if name == "crypto" else None
    module = importlib.import_module(f"simple_argon2id_encryption.{name}")
    assert module is not None
