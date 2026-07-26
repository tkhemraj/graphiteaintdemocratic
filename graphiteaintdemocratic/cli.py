"""
gaid — graphiteaintdemocratic CLI

Usage:
  gaid ios --backup <path>
  gaid ios --shutdown-log <path>
  gaid ios --sysdiagnose <path>
  gaid android --adb [--serial <serial>]
  gaid android --logcat <path>
  gaid android --bugreport <path>
  gaid network --pcap <path>
  gaid iocs
"""

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="gaid",
        description="graphiteaintdemocratic — Paragon Graphite spyware detector",
        epilog="No open-source Graphite detection tool existed before this one. You're welcome, Paragon.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # iOS
    ios_p = sub.add_parser("ios", help="iOS forensics")
    ios_group = ios_p.add_mutually_exclusive_group(required=True)
    ios_group.add_argument("--backup", metavar="PATH", help="iTunes/Finder backup directory")
    ios_group.add_argument("--shutdown-log", metavar="PATH", help="shutdown.log file")
    ios_group.add_argument("--sysdiagnose", metavar="PATH", help="sysdiagnose .tar.gz or directory")

    # Android
    android_p = sub.add_parser("android", help="Android forensics")
    android_group = android_p.add_mutually_exclusive_group(required=True)
    android_group.add_argument("--adb", action="store_true", help="Live ADB analysis")
    android_group.add_argument("--logcat", metavar="PATH", help="Logcat dump file")
    android_group.add_argument("--bugreport", metavar="PATH", help="ADB bugreport .zip or directory")
    android_p.add_argument("--serial", metavar="SERIAL", help="ADB device serial (optional)")

    # Network
    net_p = sub.add_parser("network", help="Network C2 detection")
    net_p.add_argument("--pcap", metavar="PATH", required=True, help="PCAP or PCAPNG file")

    # IOC summary
    sub.add_parser("iocs", help="Print loaded IOC summary")

    args = parser.parse_args()

    if args.command == "ios":
        return _cmd_ios(args)
    elif args.command == "android":
        return _cmd_android(args)
    elif args.command == "network":
        return _cmd_network(args)
    elif args.command == "iocs":
        return _cmd_iocs()

    return 0


def _cmd_ios(args: argparse.Namespace) -> int:
    clean = True

    if args.backup:
        from .ios.backup_analyzer import analyze_backup
        print(f"[*] Analyzing iOS backup: {args.backup}")
        result = analyze_backup(args.backup)
        _print_errors(result.errors)
        if result.is_clean:
            print("[+] Backup: no artifacts found.")
        else:
            clean = False
            print(f"[!] Backup: {len(result.matched_artifacts)} artifact(s) matched:")
            for bf, reason in result.matched_artifacts:
                print(f"    - {bf.domain}/{bf.relative_path}  [{reason}]")

    if args.shutdown_log:
        from .ios.shutdown_log import parse_shutdown_log
        print(f"[*] Analyzing shutdown log: {args.shutdown_log}")
        result = parse_shutdown_log(args.shutdown_log)
        _print_errors(result.errors)
        if result.is_clean:
            print("[+] Shutdown log: clean.")
        else:
            clean = False
            for e in result.suspicious:
                print(f"[!] Suspicious process in shutdown log: PID {e.pid} {e.process} ({e.path})")
            for e in result.anomalous_lingerers:
                print(f"[!] Anomalous lingering process: PID {e.pid} {e.process} ({e.path})")

    if args.sysdiagnose:
        from .ios.cloudkit_analyzer import analyze_sysdiagnose
        print(f"[*] Analyzing sysdiagnose: {args.sysdiagnose}")
        result = analyze_sysdiagnose(args.sysdiagnose)
        _print_errors(result.errors)

        if result.attacker_account_refs:
            clean = False
            print(f"[!!!] ATTACKER1 iMessage account identifier found ({len(result.attacker_account_refs)} occurrence(s)) — HIGH CONFIDENCE Graphite infection")
            for h in result.attacker_account_refs:
                print(f"      {h.file_path}:{h.line_number}  {h.line[:120]}")

        if result.imessage_crashes:
            clean = False
            print(f"[!] iMessage process crashes found ({len(result.imessage_crashes)}) — possible CVE-2025-43200 delivery artifact")
            for h in result.imessage_crashes[:5]:
                print(f"      {h.file_path}:{h.line_number}  {h.line[:120]}")

        if result.smallpretzel_indicators > 0:
            clean = False
            print(f"[!] SMALLPRETZEL indicators: {result.smallpretzel_indicators} anomalous appleaccountd/CloudKit event(s)")
            for h in result.hits[:5]:
                print(f"      {h.file_path}:{h.line_number}  {h.line[:120]}")

        if result.is_clean:
            print("[+] Sysdiagnose: no indicators found.")

    return 0 if clean else 1


def _cmd_android(args: argparse.Namespace) -> int:
    clean = True

    if args.adb or args.logcat:
        from .android.log_scanner import scan_logcat_live, scan_log_file
        if args.adb:
            print("[*] Pulling logcat from connected device...")
            result = scan_logcat_live(serial=getattr(args, "serial", None))
        else:
            print(f"[*] Scanning logcat file: {args.logcat}")
            result = scan_log_file(args.logcat)

        _print_errors(result.errors)
        if result.hits:
            clean = False
            for hit in result.hits:
                conf = f"[{hit.confidence}]" if hit.confidence else ""
                print(f"[!!!] FOUND '{hit.string}' {conf} — {hit.notes}")
                print(f"      {hit.source}:{hit.line_number}  {hit.line[:120]}")
        else:
            print("[+] Logcat: no Graphite strings found.")

    if args.bugreport:
        from .android.log_scanner import scan_bugreport
        print(f"[*] Scanning bugreport: {args.bugreport}")
        result = scan_bugreport(args.bugreport)
        _print_errors(result.errors)
        if result.hits:
            clean = False
            for hit in result.hits:
                print(f"[!!!] FOUND '{hit.string}' in bugreport")
                print(f"      {hit.source}:{hit.line_number}  {hit.line[:120]}")
        else:
            print("[+] Bugreport: no Graphite strings found.")

    if args.adb:
        from .android.adb_forensics import run_adb_forensics
        print("[*] Running full ADB forensics (processes, packages, files)...")
        adb_result = run_adb_forensics(serial=getattr(args, "serial", None))
        _print_errors(adb_result.errors)
        if not adb_result.is_clean:
            clean = False
            for p in adb_result.suspicious_processes:
                print(f"[!] Suspicious process: {p['process']}  [{p['matched_ioc']}]")
            for c in adb_result.c2_connections:
                print(f"[!] C2 connection: {c['ip']}")
            for f in adb_result.matched_files:
                print(f"[!] Artifact: {f}")

    return 0 if clean else 1


def _cmd_network(args: argparse.Namespace) -> int:
    from .network.c2_monitor import analyze_pcap
    print(f"[*] Analyzing PCAP: {args.pcap}")
    result = analyze_pcap(args.pcap)
    _print_errors(result.errors)
    if result.is_clean:
        print("[+] No C2 indicators in PCAP.")
        return 0
    for hit in result.hits:
        print(f"[!] C2 hit: {hit.query} -> {hit.resolved_ip}  [{hit.matched_ioc}]  (src: {hit.source})")
    return 1


def _cmd_iocs() -> int:
    from .iocs import load_domains, load_ips, load_log_strings, load_processes, load_file_artifacts
    domains = load_domains()
    ips = load_ips()
    strings = load_log_strings()
    processes = load_processes()
    artifacts = load_file_artifacts()

    print(f"Loaded IOCs:")
    print(f"  Domains:         {len(domains)}")
    print(f"  IPs:             {len(ips)}")
    print(f"  Log strings:     {len(strings)}")
    for s in strings:
        print(f"    [{s['confidence']}] {s['string']}  ({s['platform']}) — {s['notes'][:60]}")
    print(f"  Process patterns: {len(processes)}")
    print(f"  File artifacts:   {len(artifacts)}")
    return 0


def _print_errors(errors: list[str]) -> None:
    for err in errors:
        print(f"[!] {err}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
