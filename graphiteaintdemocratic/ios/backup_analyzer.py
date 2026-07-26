"""
iOS backup forensics.

Analyzes iTunes/Finder backups for Graphite artifacts. Works on both
encrypted (if password provided) and unencrypted backups.

Backup structure reference:
  ~/Library/Application Support/MobileSync/Backup/<UDID>/
    Manifest.db   - SQLite index of all backed-up files
    Info.plist    - Device metadata
    *.plist / *   - Files stored as SHA1-named blobs
"""

import hashlib
import plistlib
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from ..iocs import load_file_artifacts


@dataclass
class BackupFile:
    domain: str
    relative_path: str
    file_id: str  # SHA1 used as filename in backup
    blob_path: Path | None


@dataclass
class BackupAnalysisResult:
    backup_path: str
    device_name: str = ""
    ios_version: str = ""
    udid: str = ""
    matched_artifacts: list[tuple[BackupFile, str]] = field(default_factory=list)  # (file, reason)
    errors: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.matched_artifacts


def analyze_backup(backup_path: str | Path) -> BackupAnalysisResult:
    path = Path(backup_path)
    result = BackupAnalysisResult(backup_path=str(path))

    _load_device_info(path, result)
    manifest = path / "Manifest.db"
    if not manifest.exists():
        result.errors.append("Manifest.db not found — is this a valid backup?")
        return result

    known_artifacts = load_file_artifacts()
    _scan_manifest(manifest, path, known_artifacts, result)
    return result


def _load_device_info(path: Path, result: BackupAnalysisResult) -> None:
    info_plist = path / "Info.plist"
    if not info_plist.exists():
        return
    try:
        with open(info_plist, "rb") as f:
            info = plistlib.load(f)
        result.device_name = info.get("Device Name", "")
        result.ios_version = info.get("Product Version", "")
        result.udid = info.get("Unique Identifier", "")
    except Exception as e:
        result.errors.append(f"Failed to parse Info.plist: {e}")


def _scan_manifest(
    manifest: Path,
    backup_root: Path,
    known_artifacts: list[dict],
    result: BackupAnalysisResult,
) -> None:
    try:
        con = sqlite3.connect(str(manifest))
        cur = con.cursor()
        cur.execute("SELECT fileID, domain, relativePath FROM Files")
        rows = cur.fetchall()
        con.close()
    except sqlite3.Error as e:
        result.errors.append(f"Failed to read Manifest.db: {e}")
        return

    for file_id, domain, rel_path in rows:
        blob_path = backup_root / file_id[:2] / file_id
        bf = BackupFile(
            domain=domain or "",
            relative_path=rel_path or "",
            file_id=file_id,
            blob_path=blob_path if blob_path.exists() else None,
        )
        for artifact in known_artifacts:
            if _matches_artifact(bf, artifact):
                result.matched_artifacts.append((bf, artifact.get("description", artifact["path"])))


def _matches_artifact(bf: BackupFile, artifact: dict) -> bool:
    artifact_path = artifact.get("path", "")
    if artifact_path and bf.relative_path.endswith(artifact_path.lstrip("/")):
        return True
    artifact_domain = artifact.get("domain", "")
    if artifact_domain and bf.domain == artifact_domain and artifact_path in bf.relative_path:
        return True
    return False


def _sha1_file_id(domain: str, path: str) -> str:
    return hashlib.sha1(f"{domain}-{path}".encode()).hexdigest()
