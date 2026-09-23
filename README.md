> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# W6 — Beacon Analysis

**802.11 beacon analyzer** by **5h4d0wn1k** for **wireless security defense**:
byte-exact beacon frame parsing and synthesis, BSSID-churn tracking, beacon
flood detection, whitelist validation and SSID-confusion fingerprinting — with
pcap read/write round-trips and IDS rule generation. Pure standard library,
fully offline.

## Why beacon analysis matters

A flood of fake beacon frames — a thousand phantom BSSIDs per second — is one
of the cheapest ways to cripple wireless clients and confuse defenders. It
turns legitimate SSIDs into noise and renders rogue-AP and evil-twin
detection unreliable. This toolkit gives blue teams the exact bytes: it
synthesizes and parses beacon frames byte-exact (frame control, SSID, rates,
timestamps), computes new-BSSID-per-minute churn rates, flags flood thresholds
and SSID-confusion (>3 BSSIDs per SSID), and emits alert rules ready to drop
into an IDS. Experiments run offline against a synthetic corpus; only run
radiated beacon tests inside a shielded, authorized lab. See
[ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md).

## Features

- **Byte-exact beacon parsing** — decode management frame control, SSID
  information element, rates and timestamps (`parse_beacon_bytes`).
- **Frame synthesis** — build beacon frames and a synthetic flood corpus
  (`build_beacon_corpus`, `frame_core.py` helpers).
- **BSSID churn analysis** — new-BSSID-per-window rates across time windows
  (`compute_bssid_churn`).
- **Flood detection** — threshold-based detection (default 5 BSSIDs/sec)
  (`detect_flood`).
- **Whitelist validation** — confirm known real APs appeared in the capture
  (`validate_whitelist`).
- **SSID-confusion detection** — one SSID broadcast by many BSSIDs, a
  spoofing indicator (`compute_ssid_confusion`).
- **IDS rule generation** — emits `beacon_flood` and `ssid_confusion` alert
  rules.
- **pcap round-trip** — write a corpus to pcap and re-read it deterministically
  (`--write-pcap`/`--source pcap`).

## Quickstart

```bash
# Offline demo: build the synthetic flood corpus and run full analysis
python3 firmware/beacon_analysis.py --source synthetic --json reports/w6.json

# Write the corpus to a pcap, then re-analyze from it (deterministic)
python3 firmware/beacon_analysis.py --write-pcap reports/b.pcap
python3 firmware/beacon_analysis.py --source pcap --pcap reports/b.pcap

# Run the test suite (9 byte-exact offline tests)
python3 -m unittest discover -s tests
```

## CLI

```
python3 firmware/beacon_analysis.py [-h] [--source {synthetic,pcap}]
                                    [--pcap PATH] [--write-pcap PATH]
                                    [--json PATH]
```

- `--source` — `synthetic` (default) or `pcap`, selecting the input corpus.
- `--pcap` — pcap file to analyze when `--source pcap`.
- `--write-pcap` — write the synthetic corpus to a pcap file.
- `--json` — write the analysis report to a JSON file.

## Project structure

```
firmware/beacon_analysis.py   # analysis engine, synthetic corpus, CLI
firmware/frame_core.py        # 802.11 frame-control / header / IE encoding
tests/                        # byte-exact unittest coverage
pcap/  captures/  reports/    # gitignored — never commit traffic or reports
```

## Documentation

- [ETHICS.md](ETHICS.md) — acceptable and prohibited use.
- [SCOPE.md](SCOPE.md) — authorized target scope, shielded-lab rules.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

## Contributing

New IE parsers, churn metrics and IDS rule formats are welcome. Open an issue
or PR against the default branch; keep contributions scoped to defensive,
authorized-lab tooling.

## License

MIT — full legal shield in [LICENSE](LICENSE). Educational, authorization-
required software for analyzing 802.11 beacons on networks you own or are
explicitly permitted to test.