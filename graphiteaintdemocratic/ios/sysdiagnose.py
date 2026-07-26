"""
Extended iOS sysdiagnose analysis.

Pulls more signal beyond cloudkit_analyzer — process trees, network state,
crashed process reports, and DataUsage.sqlite (tracks which processes made
network connections and how much data they moved).

DataUsage.sqlite is particularly valuable: it records per-process network
usage by interface. A spyware process uploading gigabytes via cellular while
the device appears idle is a strong behavioral indicator.
"""

import sqlite3
import tarfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ProcessNetworkUsage:
    bundle_id: str
    wifi_in: int
    wifi_out: int
    cellular_in: int
    cellular_out: int
    timestamp: str

    @property
    def total_out(self) -> int:
        return self.wifi_out + self.cellular_out

    @property
    def is_suspicious(self) -> bool:
        # More than 50MB outbound from a process that shouldn't be uploading
        return self.total_out > 50 * 1024 * 1024 and self.bundle_id not in EXPECTED_UPLOADERS


EXPECTED_UPLOADERS = {
    "com.apple.Photos", "com.apple.cloudd", "com.apple.backupd",
    "com.apple.iCloud", "com.apple.mobileme.fmip1", "com.apple.CloudKit",
}

SUSPICIOUS_PROCESS_NAMES = {
    "bh", "ais", "fr",  # documented Graphite process disguises
}


@dataclass
class SysdiagnoseResult:
    source: str
    suspicious_network_usage: list[ProcessNetworkUsage] = field(default_factory=list)
    crashed_processes: list[dict] = field(default_factory=list)
    suspicious_processes: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not any([
            self.suspicious_network_usage,
            self.suspicious_processes,
        ])


def analyze_sysdiagnose_extended(path_or_tarball: str | Path) -> SysdiagnoseResult:
    path = Path(path_or_tarball)
    result = SysdiagnoseResult(source=str(path))

    if not path.exists():
        result.errors.append(f"Not found: {path}")
        return result

    if path.suffix in (".gz", ".tgz") or path.name.endswith(".tar.gz"):
        _analyze_tarball(path, result)
    elif path.is_dir():
        _analyze_directory(path, result)

    return result


def _analyze_tarball(path: Path, result: SysdiagnoseResult) -> None:
    try:
        with tarfile.open(path, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                name = member.name
                if "DataUsage.sqlite" in name:
                    f = tf.extractfile(member)
                    if f:
                        data = f.read()
                        _analyze_data_usage_bytes(data, result)
                elif "crashes" in name.lower() and name.endswith(".ips"):
                    f = tf.extractfile(member)
                    if f:
                        text = f.read().decode("utf-8", errors="replace")
                        _check_crash_report(text, name, result)
                elif name.endswith("ps.txt") or "process" in name.lower():
                    f = tf.extractfile(member)
                    if f:
                        text = f.read().decode("utf-8", errors="replace")
                        _check_process_list(text, name, result)
    except tarfile.TarError as e:
        result.errors.append(f"Tar error: {e}")


def _analyze_directory(path: Path, result: SysdiagnoseResult) -> None:
    for data_usage in path.rglob("DataUsage.sqlite"):
        _analyze_data_usage_file(data_usage, result)
    for crash in path.rglob("*.ips"):
        _check_crash_report(crash.read_text(errors="replace"), crash.name, result)


def _analyze_data_usage_file(sqlite_path: Path, result: SysdiagnoseResult) -> None:
    try:
        data = sqlite_path.read_bytes()
        _analyze_data_usage_bytes(data, result)
    except Exception as e:
        result.errors.append(f"DataUsage read error: {e}")


def _analyze_data_usage_bytes(data: bytes, result: SysdiagnoseResult) -> None:
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        f.write(data)
        tmp = f.name
    try:
        con = sqlite3.connect(tmp)
        cur = con.cursor()
        # ZPROCESS table stores per-bundle network usage
        cur.execute("""
            SELECT ZBUNDLENAME, ZWIFIIN, ZWIFIOUT, ZWWANIN, ZWWANOUT, ZTIMESTAMP
            FROM ZPROCESS
            ORDER BY ZWIFIOUT + ZWWANOUT DESC
            LIMIT 50
        """)
        for row in cur.fetchall():
            bundle, wifi_in, wifi_out, cell_in, cell_out, ts = row
            usage = ProcessNetworkUsage(
                bundle_id=bundle or "",
                wifi_in=wifi_in or 0,
                wifi_out=wifi_out or 0,
                cellular_in=cell_in or 0,
                cellular_out=cell_out or 0,
                timestamp=str(ts or ""),
            )
            if usage.is_suspicious:
                result.suspicious_network_usage.append(usage)
        con.close()
    except sqlite3.Error as e:
        result.errors.append(f"DataUsage SQLite error: {e}")
    finally:
        os.unlink(tmp)


def _check_crash_report(text: str, filename: str, result: SysdiagnoseResult) -> None:
    first_line = text.splitlines()[0] if text else ""
    # iMessage/imagent crashes during a zero-click attack window
    if any(p in first_line.lower() for p in ["imagent", "imdaemon", "bluebubbles"]):
        result.crashed_processes.append({"file": filename, "header": first_line})


def _check_process_list(text: str, filename: str, result: SysdiagnoseResult) -> None:
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        proc_name = parts[-1].split("/")[-1]
        if proc_name in SUSPICIOUS_PROCESS_NAMES:
            result.suspicious_processes.append({"process": proc_name, "line": line, "file": filename})
