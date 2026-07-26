"""
Network-level C2 detection.

Two modes:
  1. PCAP analysis — offline, analyze a packet capture
  2. Live DNS monitoring — watch DNS queries in real time for C2 lookups

Graphite C2 infrastructure characteristics (from Citizen Lab research):
  - Uses legitimate-looking domains (cloud provider subdomains, CDN-adjacent)
  - Rotates frequently
  - Often uses HTTPS on non-443 ports
  - Some operators use domain fronting
"""

import re
import socket
from dataclasses import dataclass, field
from pathlib import Path

from ..iocs import load_domains


@dataclass
class NetworkHit:
    query: str
    resolved_ip: str
    matched_ioc: str
    source: str  # "pcap" | "live" | "hosts"


@dataclass
class NetworkAnalysisResult:
    source: str
    hits: list[NetworkHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.hits


def analyze_pcap(pcap_path: str | Path) -> NetworkAnalysisResult:
    """Analyze a PCAP file for Graphite C2 communication."""
    try:
        import dpkt  # type: ignore
    except ImportError:
        result = NetworkAnalysisResult(source=str(pcap_path))
        result.errors.append("dpkt not installed. Run: pip install dpkt")
        return result

    result = NetworkAnalysisResult(source=str(pcap_path))
    known_domains = load_domains()
    known_domain_set = {d["domain"] for d in known_domains}

    path = Path(pcap_path)
    if not path.exists():
        result.errors.append(f"PCAP not found: {path}")
        return result

    try:
        with open(path, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except ValueError:
                pcap = dpkt.pcapng.Reader(f)

            for _ts, buf in pcap:
                _process_packet(buf, known_domain_set, known_domains, result)
    except Exception as e:
        result.errors.append(f"PCAP read error: {e}")

    return result


def check_hosts_file(hosts_path: str | Path = "/etc/hosts") -> NetworkAnalysisResult:
    """Check if any known C2 domains appear in the hosts file (sinkholing indicator)."""
    result = NetworkAnalysisResult(source=str(hosts_path))
    known_domains = load_domains()
    known_domain_set = {d["domain"] for d in known_domains}

    path = Path(hosts_path)
    if not path.exists():
        result.errors.append(f"Hosts file not found: {path}")
        return result

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, *domains = parts
        for domain in domains:
            if domain in known_domain_set or _matches_known_pattern(domain, known_domains):
                result.hits.append(NetworkHit(
                    query=domain,
                    resolved_ip=ip,
                    matched_ioc=domain,
                    source="hosts",
                ))
    return result


def resolve_and_check(domains_to_check: list[str]) -> NetworkAnalysisResult:
    """Resolve a list of domains and check if any IPs match known C2 infrastructure."""
    result = NetworkAnalysisResult(source="dns_resolve")
    known_domains = load_domains()
    known_ips = {d["ip"] for d in known_domains if d.get("ip")}

    for domain in domains_to_check:
        try:
            ip = socket.gethostbyname(domain)
            if ip in known_ips:
                result.hits.append(NetworkHit(
                    query=domain,
                    resolved_ip=ip,
                    matched_ioc=ip,
                    source="dns_resolve",
                ))
        except socket.gaierror:
            pass

    return result


def _process_packet(buf: bytes, known_set: set, known_domains: list, result: NetworkAnalysisResult) -> None:
    try:
        import dpkt
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            return
        ip = eth.data
        if not isinstance(ip.data, dpkt.udp.UDP):
            return
        udp = ip.data
        if udp.dport != 53 and udp.sport != 53:
            return
        dns = dpkt.dns.DNS(udp.data)
        for q in dns.qd:
            name = q.name.rstrip(".")
            if name in known_set or _matches_known_pattern(name, known_domains):
                result.hits.append(NetworkHit(
                    query=name,
                    resolved_ip="",
                    matched_ioc=name,
                    source="pcap_dns",
                ))
    except Exception:
        pass


def _matches_known_pattern(domain: str, known_domains: list[dict]) -> bool:
    for entry in known_domains:
        pattern = entry.get("pattern")
        if pattern and re.search(pattern, domain):
            return True
    return False
