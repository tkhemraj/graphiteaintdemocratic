# Contributing to graphiteaintdemocratic

Two ways to help: **add IOCs** or **add code**. IOC contributions are more urgently needed — Paragon rotates infrastructure fast and the research community is always a step behind.

---

## Adding IOCs

IOCs live in `graphiteaintdemocratic/iocs/`. Plain text files, one entry per line, `#` for comments.

**If you have a new domain, IP, or log string**, open a PR against the relevant file. Include your source in the inline comment — we don't merge undocumented IOCs.

### `domains.txt` format

```
domain.example.com # source_name | codename=X | notes
```

### `ips.txt` format

```
1.2.3.4 # source_name | location | notes
```

### `log_strings.txt` format

```
STRINGNAME # platform | source | confidence | notes
```

`platform`: `android` or `ios`  
`confidence`: `HIGH`, `MEDIUM`, or `LOW`

**Sources we accept:**

| Source | Weight |
|--------|--------|
| Citizen Lab published reports | Highest — cite the URL |
| Court filings (WhatsApp v. Paragon, etc.) | Highest — cite docket/exhibit |
| Apple threat notification forensics | High — include device context |
| Amnesty Tech / Security Lab | High |
| Independent researcher with reproducible method | Medium — link the writeup |
| Community-submitted without methodology | Low — will be tagged `unverified` |

**What we won't merge**: IOCs with no source, IOCs from anonymous submissions with no corroborating evidence, anything that looks like it could target unrelated infrastructure.

### Running the IOC validator

```bash
python -c "
from graphiteaintdemocratic.iocs import load_domains, load_ips, load_log_strings
print('domains:', len(load_domains()))
print('ips:', len(load_ips()))
print('log strings:', len(load_log_strings()))
"
```

---

## Dev setup

```bash
git clone https://github.com/tkhemraj/graphiteaintdemocratic
cd graphiteaintdemocratic
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest tests/ -v
```

All 18 tests must pass before submitting a PR. If you add a detection module, add tests for it.

## Linting

```bash
ruff check graphiteaintdemocratic/
ruff format graphiteaintdemocratic/
```

CI runs both. Fix lint errors before opening a PR — the lint job will block the merge.

---

## Adding a detection module

The project is structured by platform:

```
graphiteaintdemocratic/
  ios/          # backup_analyzer, shutdown_log, cloudkit_analyzer, sysdiagnose
  android/      # adb_forensics, log_scanner
  network/      # c2_monitor
  pii_exposure  # data flow documentation
```

When adding a new detection technique:

1. Put it in the right platform directory
2. Return a `dataclass` result with an `is_clean: bool` property — the CLI checks this
3. Handle all errors non-fatally: append to `result.errors`, return the partial result
4. Wire it into `cli.py`
5. Write tests — at minimum: a clean-input test, a positive-detection test, a missing-file/error test

### Error handling philosophy

Don't raise on bad input from the outside world (missing files, malformed logs, ADB failures). Append to `result.errors` and keep going. Do raise on programming errors (wrong types, bad internal state).

---

## Submitting a PR

- Keep PRs focused: IOC additions separate from code changes
- PR description should state the source of any new IOCs
- For new detection techniques: describe what forensic artifact you're analyzing and cite the research it's based on
- Don't add detection for artifacts you haven't seen on a real or confirmed-compromised device — speculation belongs in an Issue, not in code

---

## Reporting a possible infection

If you've run gaid and got a positive hit, open a **private** issue or email the maintainer directly. Don't post device logs publicly — they contain PII.

If you're a journalist or activist who received an Apple threat notification and wants help running gaid, reach out. We'll help.

---

## License

By contributing, you agree your contributions are licensed under GPL-3.0. Surveillance companies don't get to take this and make it proprietary.
