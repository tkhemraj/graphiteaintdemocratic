# graphiteaintdemocratic

> Paragon Solutions sells Graphite spyware to governments under the claim it's only used in democracies against lawful targets. 
> Journalists, NGO workers, and activists in Italy (and elsewhere) got compromised anyway.
> This tool finds it on your device.

A forensic detection toolkit for **Paragon Graphite** spyware — iOS backup analysis, Android ADB forensics, and network-level C2 detection.

Inspired by / builds on Amnesty Tech's [MVT](https://github.com/mvt-project/mvt).

---

## What it detects

- Known Graphite **file artifacts** on iOS and Android
- **Shutdown log anomalies** on iOS (Graphite leaves traces during reboot sequences)
- **Sysdiagnose** process tree irregularities
- **Network callouts** to known Paragon C2 infrastructure
- Suspicious **memory-resident processes** via ADB on Android
- WhatsApp and iMessage **delivery artifacts** (zero-click exploit residue)

## Quickstart

```bash
pip install graphiteaintdemocratic

# Analyze an iOS backup
gaid ios --backup ~/Library/Application\ Support/MobileSync/Backup/<udid>

# Android via ADB (device must be connected)
gaid android --adb

# Check a PCAP for C2 callouts
gaid network --pcap capture.pcap

# Full report
gaid report --output report.html
```

## Platform support

| Platform | Method | What's needed |
|----------|--------|---------------|
| iOS | Backup analysis | iTunes/Finder backup (encrypted preferred) |
| iOS | Sysdiagnose | `.tar.gz` from Settings → Privacy → Analytics |
| iOS | Shutdown logs | `/private/var/db/diagnostics/shutdown.log` |
| Android | ADB forensics | USB debugging enabled |
| Any | Network PCAP | Wireshark/tcpdump capture |

## IOC sources

IOCs (indicators of compromise) are maintained in `graphiteaintdemocratic/iocs/` and sourced from:

- [Citizen Lab Graphite reporting](https://citizenlab.ca)
- Paragon WhatsApp lawsuit (NDCA 2025)
- Apple threat notification forensics
- Community contributions

## Contributing

IOCs go stale fast as Paragon rotates infrastructure. If you have new domains, process names, or file artifacts — open a PR against `iocs/`.

Code contributions: see `CONTRIBUTING.md`.

## The legal framework problem

This is not a geopolitical argument. It is an argument about jurisdiction, data residency, and due process.

Any entity — regardless of where it is based — that collects, processes, or retains personal data about an individual should be required to have:

1. **Legitimate legal authority** over that person (jurisdiction)
2. **A lawful basis** for collection — necessity, proportionality, judicial authorization
3. **Data residency obligations** that keep the data within a jurisdiction where the individual has enforceable rights
4. **Independent oversight** with the ability to sanction violations
5. **A right to challenge** — the subject must be able to contest the collection in a competent court

Commercial spyware operated through third-country infrastructure is engineered to circumvent all five. That is the problem.

### Why existing law doesn't fill the gap

| Framework | What it covers | What it misses |
|-----------|---------------|----------------|
| **Fourth Amendment** | US government actors | Foreign governments using Graphite on Americans — no constitutional protection applies |
| **CLOUD Act** | US companies storing data abroad | Foreign spyware operators — no mechanism to compel Paragon to preserve, disclose, or delete anything |
| **ECPA** | US law enforcement access to communications | Foreign intelligence services — entirely out of scope |
| **GDPR** | Personal data of EU residents (commercial) | National security activities — explicitly carved out by Article 2(2) |
| **HIPAA / CCPA / sector laws** | Data held by covered custodians | Data covertly exfiltrated by spyware — not obtained from a covered entity |
| **US data residency law** | — | Does not exist at the federal level |

Privacy practitioners who spent careers ensuring GDPR data residency compliance for clients — keeping EU personal data within jurisdictions where data subjects have enforceable rights — have no equivalent framework protecting their own data as Americans. When data exfiltrated from an American's device lands on servers in a third country, there is no US legal requirement that it be deleted, not shared, not retained indefinitely, or made accessible to the person it belongs to.

The full legal analysis, including framework-by-framework breakdowns for both US and EU law, is in [`graphiteaintdemocratic/legal_framework.py`](graphiteaintdemocratic/legal_framework.py).

## Defensive use

This tool is for detecting spyware on devices you own or have explicit authorization to examine. Using it to find Graphite on your own device is not illegal in any jurisdiction we're aware of. We are not lawyers.

## License

GPL-3.0 — because surveillance companies don't get to take this and make it proprietary.
