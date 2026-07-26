"""
iOS shutdown log analysis.

Citizen Lab discovered that Pegasus (and by extension Graphite-family spyware)
leaves anomalous entries in /private/var/db/diagnostics/shutdown.log during
device reboot sequences. Legitimate processes exit cleanly; spyware implants
often appear as processes that fail to terminate or show unexpected PIDs.

Reference: https://citizenlab.ca/2022/09/home-on-the-range-pegasus-shutdown-log/
"""

import re
from dataclasses import dataclass, field
from pathlib import Path


SUSPICIOUS_PROCESS_PATTERNS = [
    # Processes that should never appear in shutdown logs
    r"^bh$",
    r"^ais$",
    # Processes that linger unexpectedly
    r"^\.\w{4,8}$",  # dot-prefixed short names (common implant disguise)
]

EXPECTED_LATE_PROCESSES = {
    "SpringBoard", "backboardd", "CommCenter", "locationd",
    "lockdownd", "mediaserverd", "mDNSResponder",
}


@dataclass
class ShutdownEntry:
    pid: int
    process: str
    path: str
    raw: str


@dataclass
class ShutdownLogResult:
    path: str
    suspicious: list[ShutdownEntry] = field(default_factory=list)
    anomalous_lingerers: list[ShutdownEntry] = field(default_factory=list)
    all_entries: list[ShutdownEntry] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.suspicious and not self.anomalous_lingerers


def parse_shutdown_log(log_path: str | Path) -> ShutdownLogResult:
    path = Path(log_path)
    result = ShutdownLogResult(path=str(path))

    if not path.exists():
        raise FileNotFoundError(f"Shutdown log not found: {path}")

    text = path.read_text(errors="replace")
    _parse_entries(text, result)
    return result


def _parse_entries(text: str, result: ShutdownLogResult) -> None:
    # Shutdown log format: "SIGTERM: [pid] process_name (path)"
    entry_re = re.compile(
        r"SIGTERM:\s+\[(\d+)\]\s+(\S+)\s+\(([^)]+)\)", re.MULTILINE
    )

    for match in entry_re.finditer(text):
        pid = int(match.group(1))
        process = match.group(2)
        path = match.group(3)
        entry = ShutdownEntry(pid=pid, process=process, path=path, raw=match.group(0))
        result.all_entries.append(entry)

        if _is_suspicious_process(process, path):
            result.suspicious.append(entry)
        elif _is_anomalous_lingerer(process, path):
            result.anomalous_lingerers.append(entry)


def _is_suspicious_process(process: str, path: str) -> bool:
    for pattern in SUSPICIOUS_PROCESS_PATTERNS:
        if re.match(pattern, process):
            return True
    # Processes claiming to be system but running from unexpected paths
    if process in EXPECTED_LATE_PROCESSES and "/usr/libexec" not in path and "/System" not in path:
        return True
    return False


def _is_anomalous_lingerer(process: str, path: str) -> bool:
    # Third-party apps should not appear in shutdown logs at all
    # (they get suspended before shutdown sequence begins)
    if path.startswith("/private/var/containers/Bundle/Application"):
        return True
    return False
