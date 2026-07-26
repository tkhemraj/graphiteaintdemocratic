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

## Legal

This tool is for **defensive use only** — detecting spyware on devices you own or have explicit authorization to examine. 

Paragon Graphite is commercial spyware sold to state actors. Using this tool to find it on your own device is not illegal in any jurisdiction we're aware of. We are not lawyers. Don't be an idiot.

## License

GPL-3.0 — because surveillance companies don't get to take this and make it proprietary.
