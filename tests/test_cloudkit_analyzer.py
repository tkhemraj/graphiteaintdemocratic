import tempfile

from graphiteaintdemocratic.ios.cloudkit_analyzer import analyze_sysdiagnose


CLEAN_LOG = """\
2025-01-15 03:00:01 appleaccountd: Refreshing credentials
2025-01-15 03:00:02 appleaccountd: CloudKit fetch complete
"""

ATTACKER1_LOG = """\
2025-01-31 14:22:01 imagent: Received iMessage from ATTACKER1
2025-01-31 14:22:01 imagent: Processing iCloud Link attachment
"""

IMESSAGE_CRASH_LOG = """\
2025-01-31 14:22:05 imagent[1234]: EXC_BAD_ACCESS (SIGSEGV)
2025-01-31 14:22:05 imagent[1234]: thread 0 crashed with signal 11
"""


def _write_temp(content: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(content)
        return f.name


def test_clean_log_is_clean():
    path = _write_temp(CLEAN_LOG)
    result = analyze_sysdiagnose(path)
    assert result.is_clean


def test_attacker1_detected():
    path = _write_temp(ATTACKER1_LOG)
    result = analyze_sysdiagnose(path)
    assert not result.is_clean
    assert len(result.attacker_account_refs) > 0


def test_imessage_crash_detected():
    path = _write_temp(IMESSAGE_CRASH_LOG)
    result = analyze_sysdiagnose(path)
    assert not result.is_clean
    assert len(result.imessage_crashes) > 0


def test_missing_path_returns_error():
    result = analyze_sysdiagnose("/nonexistent/sysdiagnose.tar.gz")
    assert result.errors
    assert result.is_clean
