"""
Android log scanner for Graphite-specific strings.

BIGPRETZEL: confirmed by WhatsApp's lawsuit against Paragon (NDCA 2025) to
uniquely identify Graphite infections. Found in logcat output and bugreports
on all forensically confirmed victim devices (Caccia, Casarini, et al).

Graphite loads itself into legitimate app processes (WhatsApp, Signal) rather
than spawning its own — so BIGPRETZEL appearing in those process logs is the
smoking gun.

Sources:
  WhatsApp Inc. v. Paragon Solutions Ltd., NDCA 2025
  Citizen Lab, "Spyware in the EU" June 2025
"""

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..iocs import load_log_strings


@dataclass
class LogHit:
    string: str
    line: str
    line_number: int
    source: str
    confidence: str
    notes: str


@dataclass
class LogScanResult:
    source: str
    hits: list[LogHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.hits


def scan_logcat_live(serial: str | None = None) -> LogScanResult:
    """Pull current logcat from connected Android device and scan it."""
    result = LogScanResult(source="adb_logcat_live")
    prefix = ["adb", "-s", serial] if serial else ["adb"]

    try:
        proc = subprocess.run(
            prefix + ["logcat", "-d", "-b", "all"],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            result.errors.append(f"adb logcat failed: {proc.stderr.strip()}")
            return result
        _scan_text(proc.stdout, "adb_logcat", result)
    except subprocess.TimeoutExpired:
        result.errors.append("adb logcat timed out after 60s")
    except FileNotFoundError:
        result.errors.append("adb not found on PATH")
    except Exception as e:
        result.errors.append(f"logcat scan error: {e}")

    return result


def scan_bugreport(bugreport_path: str | Path) -> LogScanResult:
    """
    Scan an Android bugreport for Graphite indicators.

    Get a bugreport with:  adb bugreport bugreport.zip
    Then point this at the extracted directory or the zip.
    """
    path = Path(bugreport_path)
    result = LogScanResult(source=str(path))

    if not path.exists():
        result.errors.append(f"Path not found: {path}")
        return result

    if path.suffix == ".zip":
        _scan_zip(path, result)
    elif path.is_dir():
        _scan_directory(path, result)
    elif path.is_file():
        _scan_file(path, result)

    return result


def scan_log_file(log_path: str | Path) -> LogScanResult:
    """Scan any arbitrary log file (logcat dump, bugreport extract, etc.)."""
    path = Path(log_path)
    result = LogScanResult(source=str(path))
    if not path.exists():
        result.errors.append(f"File not found: {path}")
        return result
    _scan_file(path, result)
    return result


def _scan_text(text: str, source_label: str, result: LogScanResult) -> None:
    indicators = load_log_strings(platform="android")
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        for ioc in indicators:
            if ioc["string"] in line:
                result.hits.append(LogHit(
                    string=ioc["string"],
                    line=line,
                    line_number=i,
                    source=source_label,
                    confidence=ioc.get("confidence", ""),
                    notes=ioc.get("notes", ""),
                ))


def _scan_file(path: Path, result: LogScanResult) -> None:
    try:
        text = path.read_text(errors="replace")
        _scan_text(text, str(path), result)
    except Exception as e:
        result.errors.append(f"Failed to read {path}: {e}")


def _scan_directory(path: Path, result: LogScanResult) -> None:
    log_extensions = {".txt", ".log", "", ".prop"}
    for f in path.rglob("*"):
        if f.is_file() and f.suffix.lower() in log_extensions:
            _scan_file(f, result)


def _scan_zip(path: Path, result: LogScanResult) -> None:
    import zipfile
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                ext = Path(name).suffix.lower()
                if ext in {".txt", ".log", "", ".prop"} or "logcat" in name.lower():
                    try:
                        text = zf.read(name).decode("utf-8", errors="replace")
                        _scan_text(text, f"{path}!{name}", result)
                    except Exception as e:
                        result.errors.append(f"Failed to read {name} in zip: {e}")
    except zipfile.BadZipFile as e:
        result.errors.append(f"Bad zip file: {e}")
