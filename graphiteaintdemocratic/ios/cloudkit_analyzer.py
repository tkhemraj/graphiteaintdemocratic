"""
iOS CloudKit / appleaccountd anomaly detector (SMALLPRETZEL).

Citizen Lab June 2025: "SMALLPRETZEL" describes implausible CloudKit activity
relating to the appleaccountd process found on David Yambio's iPhone (June 2024).
The anomaly: appleaccountd making CloudKit requests at times/volumes that don't
match any legitimate user activity, consistent with spyware using CloudKit as
a covert exfiltration channel.

This module scans iOS sysdiagnose archives and system logs for these patterns.

To get sysdiagnose from an iPhone:
  Settings → Privacy & Security → Analytics & Improvements → Analytics Data
  Or: hold Volume Up + Volume Down + Side button for 1-2 seconds → generates
  sysdiagnose.tar.gz → retrieve via Xcode Devices window.
"""

import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path


# appleaccountd making CloudKit requests outside of expected windows
# (user is asleep, device locked, no app foreground activity)
SUSPICIOUS_PATTERNS = [
    # High-frequency appleaccountd activity with no corresponding user action
    re.compile(r"appleaccountd.*CloudKit.*(?:upload|push|sync)", re.IGNORECASE),
    # appleaccountd spawning network connections to non-Apple IPs
    re.compile(r"appleaccountd.*(?:connect|TCP).*(?!\b17\.\b)(?:\d{1,3}\.){3}\d{1,3}"),
    # ATTACKER1 iMessage account identifier
    re.compile(r"\bATTACKER1\b"),
    # iCloud Link processing anomalies (CVE-2025-43200 delivery vector)
    re.compile(r"imagent.*icloud.*link.*(?:error|exception|crash)", re.IGNORECASE),
    re.compile(r"IMDaemon.*(?:ParseError|MemoryCorrupt|signal 11)", re.IGNORECASE),
]

ICLOUD_LINK_CRASH_PATTERN = re.compile(
    r"(imagent|IMDaemon|BlueBubbles).*(?:SIGSEGV|SIGBUS|signal 11|EXC_BAD_ACCESS)",
    re.IGNORECASE,
)


@dataclass
class CloudKitHit:
    pattern_description: str
    line: str
    line_number: int
    file_path: str


@dataclass
class CloudKitAnalysisResult:
    source: str
    hits: list[CloudKitHit] = field(default_factory=list)
    imessage_crashes: list[CloudKitHit] = field(default_factory=list)
    attacker_account_refs: list[CloudKitHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.hits and not self.imessage_crashes and not self.attacker_account_refs

    @property
    def smallpretzel_indicators(self) -> int:
        return len([h for h in self.hits if "CloudKit" in h.pattern_description or "appleaccountd" in h.pattern_description])


def analyze_sysdiagnose(sysdiagnose_path: str | Path) -> CloudKitAnalysisResult:
    """
    Analyze a sysdiagnose archive for SMALLPRETZEL / CVE-2025-43200 indicators.

    Accepts:
      - .tar.gz sysdiagnose archive
      - extracted sysdiagnose directory
      - individual log file
    """
    path = Path(sysdiagnose_path)
    result = CloudKitAnalysisResult(source=str(path))

    if not path.exists():
        result.errors.append(f"Path not found: {path}")
        return result

    if path.suffix in (".gz", ".tgz") or path.name.endswith(".tar.gz"):
        _scan_tarball(path, result)
    elif path.is_dir():
        _scan_directory(path, result)
    elif path.is_file():
        _scan_file(path, path.name, result)

    return result


def _scan_tarball(path: Path, result: CloudKitAnalysisResult) -> None:
    try:
        with tarfile.open(path, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if not _is_relevant_log(member.name):
                    continue
                try:
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    text = f.read().decode("utf-8", errors="replace")
                    _scan_text(text, member.name, result)
                except Exception as e:
                    result.errors.append(f"Failed to read {member.name}: {e}")
    except tarfile.TarError as e:
        result.errors.append(f"Failed to open tar: {e}")


def _scan_directory(path: Path, result: CloudKitAnalysisResult) -> None:
    for f in path.rglob("*"):
        if f.is_file() and _is_relevant_log(f.name):
            _scan_file(f, str(f.relative_to(path)), result)


def _scan_file(path: Path, label: str, result: CloudKitAnalysisResult) -> None:
    try:
        text = path.read_text(errors="replace")
        _scan_text(text, label, result)
    except Exception as e:
        result.errors.append(f"Failed to read {label}: {e}")


def _scan_text(text: str, source_label: str, result: CloudKitAnalysisResult) -> None:
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        # ATTACKER1 — highest confidence, check first
        if re.search(r"\bATTACKER1\b", line):
            result.attacker_account_refs.append(CloudKitHit(
                pattern_description="ATTACKER1 iMessage account identifier",
                line=line,
                line_number=i,
                file_path=source_label,
            ))

        # iMessage/imagent crashes — CVE-2025-43200 delivery artifact
        m = ICLOUD_LINK_CRASH_PATTERN.search(line)
        if m:
            result.imessage_crashes.append(CloudKitHit(
                pattern_description="iMessage process crash (possible CVE-2025-43200 delivery)",
                line=line,
                line_number=i,
                file_path=source_label,
            ))

        # SMALLPRETZEL patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.search(line):
                result.hits.append(CloudKitHit(
                    pattern_description=pattern.pattern,
                    line=line,
                    line_number=i,
                    file_path=source_label,
                ))
                break


def _is_relevant_log(filename: str) -> bool:
    relevant_names = {
        "appleaccountd", "imagent", "imdaemon", "cloudkit",
        "system.log", "mobile.log", "syslog",
    }
    name_lower = filename.lower()
    return any(n in name_lower for n in relevant_names) or name_lower.endswith(".log")
