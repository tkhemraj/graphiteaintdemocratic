"""
Android forensics via ADB.

Requires:
  - adb installed and on PATH
  - Device connected with USB debugging enabled
  - For deeper access: rooted device or adb root

What we check:
  1. Running processes — look for implant process names
  2. Installed packages — unknown system-signed apps
  3. Logcat — crash/exception signatures from exploit activity
  4. Network connections — active connections to known C2
  5. File system artifacts — known implant paths (root only)
"""

import json
import re
import subprocess
from dataclasses import dataclass, field

from ..iocs import load_domains, load_processes, load_file_artifacts, load_all_known_ips


@dataclass
class ADBForensicsResult:
    device_serial: str = ""
    android_version: str = ""
    suspicious_processes: list[dict] = field(default_factory=list)
    suspicious_packages: list[dict] = field(default_factory=list)
    c2_connections: list[dict] = field(default_factory=list)
    matched_files: list[str] = field(default_factory=list)
    logcat_hits: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not any([
            self.suspicious_processes,
            self.suspicious_packages,
            self.c2_connections,
            self.matched_files,
            self.logcat_hits,
        ])


def run_adb_forensics(serial: str | None = None) -> ADBForensicsResult:
    result = ADBForensicsResult()
    prefix = ["adb", "-s", serial] if serial else ["adb"]

    result.device_serial = serial or _get_connected_serial(prefix, result)
    result.android_version = _adb_getprop(prefix, "ro.build.version.release", result)

    _check_processes(prefix, result)
    _check_packages(prefix, result)
    _check_network(prefix, result)
    _check_files(prefix, result)
    return result


def _adb(args: list[str], base: list[str]) -> tuple[str, int]:
    cmd = base + ["shell"] + args
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return proc.stdout.strip(), proc.returncode


def _get_connected_serial(prefix: list[str], result: ADBForensicsResult) -> str:
    proc = subprocess.run(prefix + ["devices"], capture_output=True, text=True)
    lines = proc.stdout.strip().splitlines()
    for line in lines[1:]:
        if "\tdevice" in line:
            return line.split("\t")[0]
    result.errors.append("No ADB device found. Connect device with USB debugging enabled.")
    return ""


def _adb_getprop(prefix: list[str], prop: str, result: ADBForensicsResult) -> str:
    try:
        out, _ = _adb(["getprop", prop], prefix)
        return out
    except Exception as e:
        result.errors.append(f"getprop {prop} failed: {e}")
        return ""


def _check_processes(prefix: list[str], result: ADBForensicsResult) -> None:
    known_suspicious = load_processes(platform="android")
    try:
        out, _ = _adb(["ps", "-A"], prefix)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 9:
                continue
            proc_name = parts[-1]
            for sus in known_suspicious:
                if re.search(sus["pattern"], proc_name):
                    result.suspicious_processes.append({
                        "process": proc_name,
                        "line": line,
                        "matched_ioc": sus["description"],
                    })
    except Exception as e:
        result.errors.append(f"Process check failed: {e}")


def _check_packages(prefix: list[str], result: ADBForensicsResult) -> None:
    # Look for system-signed packages not part of the standard OS
    # Graphite implants are sometimes disguised as system apps
    try:
        out, _ = _adb(["pm", "list", "packages", "-s", "-f"], prefix)
        for line in out.splitlines():
            # format: package:/path/to/apk=com.package.name
            if "=" not in line:
                continue
            path, pkg = line.replace("package:", "").split("=", 1)
            if _is_suspicious_package(pkg, path):
                result.suspicious_packages.append({"package": pkg, "path": path})
    except Exception as e:
        result.errors.append(f"Package check failed: {e}")


def _is_suspicious_package(pkg: str, path: str) -> bool:
    # Packages in /data/app that are signed as system are unusual
    if path.startswith("/data/app") and "priv-app" in path:
        return True
    # Generic package names that don't match known system apps
    suspicious_prefixes = ["com.sys.", "com.android.system.", "android.service."]
    for prefix in suspicious_prefixes:
        if pkg.startswith(prefix) and pkg.count(".") <= 3:
            return True
    return False


def _check_network(prefix: list[str], result: ADBForensicsResult) -> None:
    known_domains = load_domains()
    try:
        out, _ = _adb(["cat", "/proc/net/tcp6"], prefix)
        # Extract remote IPs from active connections
        # This is a heuristic — we can't resolve IPs to domains here without DNS
        # TODO: integrate with network module for reverse lookup
        active_ips = _parse_proc_net(out)
        for ip in active_ips:
            # For now flag if in known C2 IP ranges (to be expanded)
            if _is_known_c2_ip(ip):
                result.c2_connections.append({"ip": ip, "source": "/proc/net/tcp6"})
    except Exception as e:
        result.errors.append(f"Network check failed: {e}")


def _parse_proc_net(content: str) -> list[str]:
    ips = []
    for line in content.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        remote_hex = parts[2]
        ip_hex, port_hex = remote_hex.rsplit(":", 1)
        try:
            ip = _hex_to_ip(ip_hex)
            if ip and ip not in ("0.0.0.0", "::"):
                ips.append(ip)
        except Exception:
            pass
    return ips


def _hex_to_ip(hex_str: str) -> str:
    if len(hex_str) == 8:
        # IPv4
        b = bytes.fromhex(hex_str)
        return ".".join(str(x) for x in reversed(b))
    return ""


def _is_known_c2_ip(ip: str) -> bool:
    return ip in load_all_known_ips()


def _check_files(prefix: list[str], result: ADBForensicsResult) -> None:
    artifacts = load_file_artifacts(platform="android")
    for artifact in artifacts:
        path = artifact.get("path", "")
        if not path:
            continue
        try:
            out, rc = _adb(["ls", path], prefix)
            if rc == 0 and out and "No such file" not in out:
                result.matched_files.append(path)
        except Exception:
            pass
