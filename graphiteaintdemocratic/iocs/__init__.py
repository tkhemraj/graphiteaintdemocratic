"""IOC loader — reads from the flat files in this directory."""

from pathlib import Path

_IOC_DIR = Path(__file__).parent


def load_domains() -> list[dict]:
    results = []
    for line in _read_ioc_file(_IOC_DIR / "domains.txt"):
        parts = line.split("#", 1)
        domain = parts[0].strip()
        note = parts[1].strip() if len(parts) > 1 else ""
        if domain:
            results.append({"domain": domain, "description": note})
    return results


def load_ips() -> list[dict]:
    results = []
    for line in _read_ioc_file(_IOC_DIR / "ips.txt"):
        parts = line.split("#", 1)
        ip = parts[0].strip()
        note = parts[1].strip() if len(parts) > 1 else ""
        if ip:
            results.append({"ip": ip, "description": note})
    return results


def load_processes(platform: str = "") -> list[dict]:
    results = []
    for line in _read_ioc_file(_IOC_DIR / "processes.txt"):
        parts = line.split("#", 1)
        pattern = parts[0].strip()
        meta = parts[1].strip() if len(parts) > 1 else ""
        if not pattern:
            continue
        entry = {"pattern": pattern, "description": meta}
        if not platform or platform.lower() in meta.lower():
            results.append(entry)
    return results


def load_file_artifacts(platform: str = "") -> list[dict]:
    results = []
    for line in _read_ioc_file(_IOC_DIR / "file_artifacts.txt"):
        parts = line.split("#", 1)
        artifact_path = parts[0].strip()
        meta = parts[1].strip() if len(parts) > 1 else ""
        if not artifact_path:
            continue
        entry = {"path": artifact_path, "description": meta}
        if not platform or platform.lower() in meta.lower():
            results.append(entry)
    return results


def load_log_strings(platform: str = "") -> list[dict]:
    """Load confirmed log strings (BIGPRETZEL, SMALLPRETZEL, ATTACKER1, etc.)"""
    results = []
    for line in _read_ioc_file(_IOC_DIR / "log_strings.txt"):
        parts = line.split("#", 1)
        string = parts[0].strip()
        meta = parts[1].strip() if len(parts) > 1 else ""
        if not string:
            continue
        # parse structured metadata: platform | source | confidence | notes
        meta_parts = [p.strip() for p in meta.split("|")]
        entry = {
            "string": string,
            "platform": meta_parts[0] if len(meta_parts) > 0 else "",
            "source": meta_parts[1] if len(meta_parts) > 1 else "",
            "confidence": meta_parts[2] if len(meta_parts) > 2 else "",
            "notes": meta_parts[3] if len(meta_parts) > 3 else "",
        }
        if not platform or platform.lower() in entry["platform"].lower():
            results.append(entry)
    return results


def load_all_known_ips() -> set[str]:
    return {entry["ip"] for entry in load_ips()}


def _read_ioc_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines
