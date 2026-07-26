import tempfile
from pathlib import Path

from graphiteaintdemocratic.android.log_scanner import scan_log_file, scan_bugreport


CLEAN_LOG = """\
07-24 10:00:01.123  1234  1234 I ActivityManager: Start proc com.whatsapp
07-24 10:00:02.456  1234  1234 I WhatsApp: Message received
07-24 10:00:03.789  1234  1234 D Bluetooth: Connected
"""

INFECTED_LOG = """\
07-24 10:00:01.123  1234  1234 I ActivityManager: Start proc com.whatsapp
07-24 10:00:02.456  1234  1234 I WhatsApp: BIGPRETZEL injection sequence initiated
07-24 10:00:03.789  1234  1234 D com.whatsapp: memory mapping complete
"""


def _write_temp(content: str, suffix: str = ".log") -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
        f.write(content)
        return f.name


def test_clean_log_no_hits():
    path = _write_temp(CLEAN_LOG)
    result = scan_log_file(path)
    assert result.is_clean
    assert not result.errors


def test_bigpretzel_detected():
    path = _write_temp(INFECTED_LOG)
    result = scan_log_file(path)
    assert not result.is_clean
    strings_found = [h.string for h in result.hits]
    assert "BIGPRETZEL" in strings_found


def test_bigpretzel_hit_has_line_context():
    path = _write_temp(INFECTED_LOG)
    result = scan_log_file(path)
    hit = next(h for h in result.hits if h.string == "BIGPRETZEL")
    assert "BIGPRETZEL" in hit.line
    assert hit.line_number > 0


def test_missing_file_returns_error():
    result = scan_log_file("/nonexistent/logcat.log")
    assert result.errors
    assert result.is_clean
