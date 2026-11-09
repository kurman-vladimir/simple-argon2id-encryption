"""Interactive CLI, safe diagnostics and source-launcher tests."""

import os
import io
import random
import warnings

import pytest
import subprocess
import sys
from pathlib import Path

from simple_argon2id_encryption import cli
from simple_argon2id_encryption.cli import main
from simple_argon2id_encryption.encoding import build_header, format_hex, MAX_FORMATTED_LENGTH


def source_environment() -> dict[str, str]:
    """Expose src-layout modules to an uninstalled subprocess."""
    environment = os.environ.copy()
    source_dir = str(Path(__file__).resolve().parents[1] / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_dir, environment.get("PYTHONPATH", "")) if part
    )
    return environment


def test_no_args_prints_help(capsys) -> None:
    assert main([]) == 0
    result = capsys.readouterr()
    assert "encrypt" in result.out
    assert "decrypt" in result.out


def test_python_module_help() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "simple_argon2id_encryption", "--help"],
        check=False,
        capture_output=True,
        text=True,
        env=source_environment(),
    )
    assert result.returncode == 0
    assert "encrypt" in result.stdout
    assert "decrypt" in result.stdout


def test_python_module_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "simple_argon2id_encryption", "--version"],
        check=False,
        capture_output=True,
        text=True,
        env=source_environment(),
    )
    assert result.returncode == 0
    assert "0.2.0" in result.stdout


def test_source_launcher_without_installed_package(tmp_path) -> None:
    launcher = Path(__file__).resolve().parents[1] / "run.py"
    for argument, expected in (("--help", "encrypt"), ("--version", "0.2.0")):
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(launcher), argument],
            cwd=tmp_path,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert expected in result.stdout
        assert result.stderr == ""


PASSWORD = "synthetic test password"
TEXT = "synthetic private text / \u00e9"
VECTOR_PASSWORD = "test password -- not a production credential"
VECTOR_TEXT = "test text SAE1"
VECTOR = format_hex(
    build_header(bytes(range(16)), bytes(range(24)), len(VECTOR_TEXT))
    + bytes.fromhex("cb8e4baff7732f9b399e3b0583dba8fe0ae6eb1ac1c10c1b399285779412")
)


def hidden_answers(monkeypatch, *answers):
    values = iter(answers)
    def getpass(prompt, *, stream):
        assert stream is sys.stderr
        print(prompt, end="", file=stream)
        value = next(values)
        if isinstance(value, BaseException):
            raise value
        return value
    monkeypatch.setattr(cli.getpass, "getpass", getpass)


def no_password(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Secret prompt must not run")
    monkeypatch.setattr(cli.getpass, "getpass", forbidden)


def assert_no_secrets(result, *secrets):
    for secret in secrets:
        assert secret not in result.out
        assert secret not in result.err
    assert "Traceback" not in result.err


def test_native_interactive_round_trip(monkeypatch, capsys):
    from simple_argon2id_encryption.crypto import decrypt_text
    hidden_answers(monkeypatch, TEXT, PASSWORD, PASSWORD)
    assert main(["encrypt"]) == 0
    result = capsys.readouterr()
    assert result.out.startswith("SAE1:\n")
    assert_no_secrets(result, TEXT, PASSWORD)
    assert decrypt_text(result.out, PASSWORD.encode()) == TEXT
    monkeypatch.setattr(sys, "stdin", io.StringIO(result.out + "END\nYES\n"))
    hidden_answers(monkeypatch, PASSWORD, "YES")
    assert main(["decrypt"]) == 0
    result = capsys.readouterr()
    assert result.out == TEXT + "\n"
    assert "Integrity verified" in result.err
    assert PASSWORD not in result.err + result.out


def test_native_multiline_vector(monkeypatch, capsys):
    # Different grouping, lowercase, CRLF and blank lines are valid.
    body = VECTOR.partition("\n")[2].replace(" ", "\t").lower()
    monkeypatch.setattr(sys, "stdin", io.StringIO("SAE1:\r\n\n" + body + "\nEND\nYES\n"))
    hidden_answers(monkeypatch, VECTOR_PASSWORD, "YES")
    assert main(["decrypt"]) == 0
    result = capsys.readouterr()
    assert result.out == VECTOR_TEXT + "\n"
    assert VECTOR_PASSWORD not in result.err


@pytest.mark.parametrize("answer,status", [("NO", 0), ("yes", 0), ("", 0), ("YES please", 0), (EOFError(), 2)])
def test_no_display_without_exact_confirmation(monkeypatch, capsys, answer, status):
    from simple_argon2id_encryption import crypto
    monkeypatch.setattr(crypto, "decrypt_text", lambda *args: TEXT)
    hidden_answers(monkeypatch, PASSWORD, answer)
    monkeypatch.setattr(sys, "stdin", io.StringIO(VECTOR + "\nEND\nYES\n"))
    assert main(["decrypt"]) == status
    assert_no_secrets(capsys.readouterr(), TEXT, PASSWORD)


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
@pytest.mark.parametrize("suffix", [["SYNTHETIC_ARG_SECRET"], ["--password", "SYNTHETIC_ARG_SECRET"]])
def test_arguments_never_echoed(monkeypatch, capsys, command, suffix):
    no_password(monkeypatch)
    assert main([command, *suffix]) == 2
    result = capsys.readouterr()
    assert "invalid command or arguments" in result.err
    assert_no_secrets(result, "SYNTHETIC_ARG_SECRET")


def test_unknown_command_never_echoed(capsys):
    assert main(["SYNTHETIC_ARG_SECRET"]) == 2
    assert_no_secrets(capsys.readouterr(), "SYNTHETIC_ARG_SECRET")


@pytest.mark.parametrize("command", ["help", "version"])
def test_help_and_version_commands(monkeypatch, capsys, command):
    no_password(monkeypatch)
    assert main([command]) == 0
    assert ("encrypt" if command == "help" else "0.2.0") in capsys.readouterr().out


def test_password_mismatch_before_encryption(monkeypatch, capsys):
    from simple_argon2id_encryption import crypto
    def forbidden(*args):
        pytest.fail("Encryption must not run")
    monkeypatch.setattr(crypto, "encrypt_text", forbidden)
    hidden_answers(monkeypatch, TEXT, PASSWORD, "different synthetic password")
    assert main(["encrypt"]) == 2
    result = capsys.readouterr()
    assert "passwords do not match" in result.err
    assert_no_secrets(result, TEXT, PASSWORD, "different synthetic password")


@pytest.mark.parametrize("password", ["", "x" * 4097, "\u00e9" * 2049, "\ud800"])
def test_invalid_password(monkeypatch, capsys, password):
    hidden_answers(monkeypatch, TEXT, password)
    assert main(["encrypt"]) == 2
    assert_no_secrets(capsys.readouterr(), TEXT)


@pytest.mark.parametrize("text", ["x" * 4097, "\u00e9" * 2049, "\ud800", "line one\nline two", "line one\rline two"])
def test_invalid_text_before_password(monkeypatch, capsys, text):
    hidden_answers(monkeypatch, text)
    assert main(["encrypt"]) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert "Traceback" not in result.err


@pytest.mark.parametrize("text", ["", "A" * 4096, "\u00e9" * 2048])
def test_cli_plaintext_boundaries(monkeypatch, capsys, text):
    from simple_argon2id_encryption import crypto
    calls = []
    def encrypt(message, password):
        calls.append((message, password))
        return VECTOR
    monkeypatch.setattr(crypto, "encrypt_text", encrypt)
    hidden_answers(monkeypatch, text, PASSWORD, PASSWORD)
    assert main(["encrypt"]) == 0
    assert calls == [(text, PASSWORD.encode())]
    assert capsys.readouterr().out == VECTOR + "\n"


@pytest.mark.parametrize("data", ["", VECTOR + "\n", "SAE1:GG\nEND\n", "\nEND\n", "SAE1:" + " " * MAX_FORMATTED_LENGTH + "\nEND\n"])
def test_bad_hex_before_password(monkeypatch, capsys, data):
    no_password(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO(data))
    assert main(["decrypt"]) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert "error:" in result.err


def test_random_transcription_errors(monkeypatch, capsys):
    no_password(monkeypatch)
    rng = random.Random(20261109)
    for _ in range(40):
        position = rng.randrange(len(VECTOR))
        bad = VECTOR[:position] + rng.choice("OIZ?!:;\u200b\u00a0") + VECTOR[position:]
        monkeypatch.setattr(sys, "stdin", io.StringIO(bad + "\nEND\n"))
        assert main(["decrypt"]) == 2
        assert capsys.readouterr().out == ""


@pytest.mark.parametrize("corrupt", [False, True])
def test_native_authentication_error_never_displays(monkeypatch, capsys, corrupt):
    packet = VECTOR
    password = "wrong synthetic password"
    if corrupt:
        packet = packet[:-1] + ("0" if packet[-1] != "0" else "1")
        password = VECTOR_PASSWORD
    hidden_answers(monkeypatch, password)
    monkeypatch.setattr(sys, "stdin", io.StringIO(packet + "\nEND\nYES\n"))
    assert main(["decrypt"]) == 2
    result = capsys.readouterr()
    assert "wrong password or corrupted" in result.err
    assert "Integrity verified" not in result.err
    assert_no_secrets(result, VECTOR_TEXT, password)


@pytest.mark.parametrize("exception,status", [(EOFError, 2), (KeyboardInterrupt, 130), (OSError, 1), (MemoryError, 1)])
def test_interrupted_or_failed_input(monkeypatch, capsys, exception, status):
    def fail(*args, **kwargs):
        raise exception("SYNTHETIC_EXCEPTION_SECRET")
    monkeypatch.setattr(cli.getpass, "getpass", fail)
    assert main(["encrypt"]) == status
    assert_no_secrets(capsys.readouterr(), "SYNTHETIC_EXCEPTION_SECRET")


def test_getpass_echo_fallback_is_forbidden(monkeypatch, capsys):
    def fallback(*args, **kwargs):
        warnings.warn("SYNTHETIC_WARNING_SECRET", cli.getpass.GetPassWarning)
        pytest.fail("Echoing fallback must not read a secret")
    monkeypatch.setattr(cli.getpass, "getpass", fallback)
    assert main(["encrypt"]) == 2
    result = capsys.readouterr()
    assert "hidden input is unavailable" in result.err
    assert_no_secrets(result, "SYNTHETIC_WARNING_SECRET")


@pytest.mark.skipif(os.name != "posix", reason="POSIX terminal integration")
def test_real_terminal_hides_text_and_password():
    import errno
    import pty
    import select
    import time

    launcher = Path(__file__).resolve().parents[1] / "run.py"
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [sys.executable, str(launcher), "encrypt"],
        stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
    )
    os.close(slave)
    transcript = bytearray()
    def read_until(marker):
        deadline = time.monotonic() + 15
        start = len(transcript)
        while marker not in transcript[start:]:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "Terminal prompt timed out"
            ready, _, _ = select.select([master], [], [], remaining)
            assert ready, "Terminal prompt timed out"
            chunk = os.read(master, 65536)
            assert chunk, "Terminal closed before prompt"
            transcript.extend(chunk)
    try:
        for marker, response in (
            (b"hidden): ", TEXT),
            (b"Password: ", PASSWORD),
            (b"Confirm password: ", PASSWORD),
        ):
            read_until(marker)
            os.write(master, response.encode("utf-8") + b"\n")
        deadline = time.monotonic() + 15
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "Encryption timed out"
            ready, _, _ = select.select([master], [], [], remaining)
            assert ready, "Encryption timed out"
            try:
                chunk = os.read(master, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            transcript.extend(chunk)
        assert process.wait(timeout=5) == 0
        output = transcript.decode("utf-8").replace("\r\n", "\n")
        assert TEXT not in output
        assert PASSWORD not in output
        assert "SAE1:\n" in output
        from simple_argon2id_encryption.crypto import decrypt_text
        encoded = "SAE1:\n" + output.split("SAE1:\n", 1)[1]
        assert decrypt_text(encoded, PASSWORD.encode()) == TEXT
    finally:
        os.close(master)
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="POSIX terminal isolation")
def test_pipe_does_not_enable_getpass_echo_fallback():
    launcher = Path(__file__).resolve().parents[1] / "run.py"
    result = subprocess.run(
        [sys.executable, str(launcher), "encrypt"],
        input=TEXT + "\n" + PASSWORD + "\n", capture_output=True, text=True,
        start_new_session=True, timeout=15,
    )
    assert result.returncode == 2
    assert "hidden input is unavailable" in result.stderr
    assert TEXT not in result.stdout + result.stderr
    assert PASSWORD not in result.stdout + result.stderr


def test_packet_cannot_supply_display_confirmation(monkeypatch, capsys):
    hidden_answers(monkeypatch, VECTOR_PASSWORD, "NO")
    stream = io.StringIO(VECTOR + "\nEND\nYES\n")
    monkeypatch.setattr(sys, "stdin", stream)
    assert main(["decrypt"]) == 0
    assert stream.read() == "YES\n"
    assert_no_secrets(capsys.readouterr(), VECTOR_TEXT, VECTOR_PASSWORD)


def test_no_hidden_confirmation_no_plaintext(monkeypatch, capsys):
    def getpass(prompt, *, stream):
        if prompt.startswith("Password"):
            return VECTOR_PASSWORD
        warnings.warn("Cannot control echo", cli.getpass.GetPassWarning)
        pytest.fail("Echo fallback must not run")
    monkeypatch.setattr(cli.getpass, "getpass", getpass)
    monkeypatch.setattr(sys, "stdin", io.StringIO(VECTOR + "\nEND\nYES\n"))
    assert main(["decrypt"]) == 2
    assert_no_secrets(capsys.readouterr(), VECTOR_TEXT, VECTOR_PASSWORD)


@pytest.mark.parametrize("tty", [True, False])
def test_control_characters_safe_on_terminal_exact_in_redirect(monkeypatch, tty):
    from simple_argon2id_encryption import crypto
    text = "synthetic\x1b]52;c;TEST\x07\r\b\x9b2J\u202etest\u200d\nnext\tcolumn"
    monkeypatch.setattr(crypto, "decrypt_text", lambda *args: text)
    class Output(io.StringIO):
        def isatty(self):
            return tty
    output = Output()
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(sys, "stdin", io.StringIO(VECTOR + "\nEND\n"))
    hidden_answers(monkeypatch, PASSWORD, "YES")
    assert main(["decrypt"]) == 0
    if tty:
        shown = output.getvalue()
        for char in ("\x1b", "\x07", "\r", "\b", "\x9b", "\u202e", "\u200d"):
            assert char not in shown
        assert "\\x1b" in shown and "\\u202e" in shown
        assert "\nnext\tcolumn" in shown
    else:
        assert output.getvalue() == text + "\n"


@pytest.mark.parametrize("confirmation", ["", "x" * 4097, "\ud800"])
def test_invalid_confirmation_password_rejected(monkeypatch, capsys, confirmation):
    hidden_answers(monkeypatch, TEXT, PASSWORD, confirmation)
    assert main(["encrypt"]) == 2
    assert_no_secrets(capsys.readouterr(), TEXT, PASSWORD)


def test_output_flush_failure_reports_failure(monkeypatch, capsys):
    from simple_argon2id_encryption import crypto
    monkeypatch.setattr(crypto, "encrypt_text", lambda *args: VECTOR)
    class Output(io.StringIO):
        def flush(self):
            raise OSError("synthetic output failure")
    monkeypatch.setattr(sys, "stdout", Output())
    hidden_answers(monkeypatch, TEXT, PASSWORD, PASSWORD)
    assert main(["encrypt"]) == 1
    result = capsys.readouterr()
    assert "operation failed" in result.err
    assert "synthetic output failure" not in result.err


@pytest.mark.skipif(os.name != "posix", reason="POSIX controlling-terminal integration")
def test_piped_yes_cannot_bypass_real_terminal_consent():
    import errno
    import pty
    import select
    import signal
    import time

    launcher = Path(__file__).resolve().parents[1] / "run.py"
    read_fd, write_fd = os.pipe()
    pid, terminal = pty.fork()
    if pid == 0:
        os.close(write_fd)
        os.dup2(read_fd, 0)
        os.close(read_fd)
        os.execv(sys.executable, [sys.executable, str(launcher), "decrypt"])
        os._exit(1)
    os.close(read_fd)
    os.write(write_fd, (VECTOR + "\nEND\nYES\n").encode("ascii"))
    os.close(write_fd)
    transcript = bytearray()
    reaped = False
    def read_chunk(deadline):
        remaining = deadline - time.monotonic()
        assert remaining > 0, "Terminal interaction timed out"
        ready, _, _ = select.select([terminal], [], [], remaining)
        assert ready, "Terminal interaction timed out"
        try:
            return os.read(terminal, 65536)
        except OSError as exc:
            if exc.errno == errno.EIO:
                return b""
            raise
    def read_until(marker):
        deadline = time.monotonic() + 15
        while marker not in transcript:
            chunk = read_chunk(deadline)
            assert chunk, "Terminal closed before consent prompt"
            transcript.extend(chunk)
    try:
        read_until(b"Password: ")
        os.write(terminal, VECTOR_PASSWORD.encode("ascii") + b"\n")
        read_until(b"Type YES")
        assert VECTOR_TEXT.encode("ascii") not in transcript
        os.write(terminal, b"NO\n")
        deadline = time.monotonic() + 15
        while True:
            chunk = read_chunk(deadline)
            if not chunk:
                break
            transcript.extend(chunk)
        _, status = os.waitpid(pid, 0)
        reaped = True
        assert os.waitstatus_to_exitcode(status) == 0
        assert VECTOR_TEXT.encode("ascii") not in transcript
        assert VECTOR_PASSWORD.encode("ascii") not in transcript
        assert b"Cancelled" in transcript
    finally:
        os.close(terminal)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
