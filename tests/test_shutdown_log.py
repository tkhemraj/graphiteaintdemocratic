import textwrap
import tempfile
from pathlib import Path

from graphiteaintdemocratic.ios.shutdown_log import parse_shutdown_log, _parse_entries, ShutdownLogResult


CLEAN_LOG = textwrap.dedent("""\
    SIGTERM: [123] SpringBoard (/System/Library/CoreServices/SpringBoard.app/SpringBoard)
    SIGTERM: [456] backboardd (/usr/libexec/backboardd)
    SIGTERM: [789] locationd (/usr/libexec/locationd)
""")

DIRTY_LOG = textwrap.dedent("""\
    SIGTERM: [123] SpringBoard (/System/Library/CoreServices/SpringBoard.app/SpringBoard)
    SIGTERM: [999] bh (/private/var/mobile/bh)
    SIGTERM: [888] suspiciousapp (/private/var/containers/Bundle/Application/DEADBEEF/app.bundle/app)
""")


def test_clean_log_is_clean():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(CLEAN_LOG)
        path = f.name
    result = parse_shutdown_log(path)
    assert result.is_clean


def test_dirty_log_flags_suspicious():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(DIRTY_LOG)
        path = f.name
    result = parse_shutdown_log(path)
    assert not result.is_clean
    proc_names = [e.process for e in result.suspicious]
    assert "bh" in proc_names


def test_dirty_log_flags_lingerers():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(DIRTY_LOG)
        path = f.name
    result = parse_shutdown_log(path)
    lingerer_paths = [e.path for e in result.anomalous_lingerers]
    assert any("/private/var/containers/Bundle/Application" in p for p in lingerer_paths)


def test_missing_file_raises():
    import pytest
    with pytest.raises(FileNotFoundError):
        parse_shutdown_log("/nonexistent/shutdown.log")
