# W6 — Beacon Flood / SSID-Confusion Analysis

Blue-angled tooling for SSID beacon-flood stress testing, BSSID churn detection, and IDS rule generation.

## Overview

This project implements a beacon flood analysis and detection tool:
- Parses bursts of beacon frames with embedded sample data containing many fake BSSIDs
- Computes new-BSSID-per-minute and BSSID-churn rates across time windows
- Detects flood thresholds based on configurable rate limits
- Validates a whitelist of known real APs against captured beacon data
- Produces a detector report useful for IDS rule generation

## Features

- **BSSID Churn Analysis**: Tracks new BSSIDs appearing per time window
- **Flood Detection**: Threshold-based detection of abnormal beacon rates
- **Whitelist Validation**: Checks which known real APs appeared in captures
- **SSID Confusion Detection**: Identifies SSIDs broadcast by many BSSIDs (spoofing indicator)
- **IDS Rule Suggestions**: Generates alert rules for beacon flood and SSID confusion
- **Offline Demo**: Fully self-contained with embedded sample beacon data

## Installation

```bash
# No external dependencies required — pure Python stdlib
python3 beacon_analysis.py
```

## Usage

```bash
# Run full analysis demo (offline, embedded data)
python3 beacon_analysis.py

# Programmatic usage
from beacon_analysis import BeaconAnalyzer, detect_flood, validate_whitelist

analyzer = BeaconAnalyzer()
analyzer.analyze()

# Check flood on custom frames
is_flood, rate = detect_flood(custom_frames, threshold_bssid_per_sec=5)
```

## Example Output

```
============================================================
  W6 — Beacon Flood / SSID-Confusion Analysis
============================================================

[+] Loaded 31 beacon frames
[+] Unique BSSIDs: 31
[+] Unique SSIDs: 3
[+] Real beacons: 3, Fake beacons: 28

=== BSSID Churn Rate ===
  Window  New BSSIDs   Total Seen  In Window
---------------------------------------------
       0           1            1          1
       0           1            2          1
...

=== Flood Detection ===
  Flood detected: YES
  BSSID rate: 971.0 new BSSIDs/sec
  Threshold: 5 BSSIDs/sec

=== Whitelist Validation ===
BSSID               SSID            Status     Count
----------------------------------------------------
aa:bb:cc:dd:ee:01   CorpWiFi        FOUND          1
aa:bb:cc:dd:ee:11   GuestNet        FOUND          1
aa:bb:cc:dd:ee:1c   HomeWiFi        FOUND          1

=== SSID Confusion Detection ===
SSID            BSSID Count   Flood?
--------------------------------------
CorpWiFi                16      YES
GuestNet                11      YES
HomeWiFi                 5      YES

=== IDS Rule Suggestions ===
  ALERT beacon_flood: ssid="*" rate=971/sec over threshold
  ALERT ssid_confusion: ssid="CorpWiFi" bssid_count=16 > 3
  ALERT ssid_confusion: ssid="GuestNet" bssid_count=11 > 3
  ALERT ssid_confusion: ssid="HomeWiFi" bssid_count=5 > 3
[+] Analysis complete — exit 0
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before running beacon flood tests
- Generating fake beacon frames on production networks is illegal
- This tool should ONLY be used on networks you own or have written authorization to test
- Beacon flood testing should only be performed in isolated lab environments

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **FCC Part 15**: Unauthorized transmission of 802.11 frames may violate FCC regulations
- **State Laws**: Many states have additional computer crime and wireless statutes

### Acceptable Use
- Testing IDS/IPS detection of beacon floods on your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training demonstrations

### Prohibited Use
- Flooding beacons on networks you don't own
- Disrupting wireless networks with fake SSIDs
- Any activity that violates applicable laws or regulations
- Operating an intentional radiator outside FCC/regulatory limits

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover network vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the network owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## Live Lab Test Plan

This repo is a byte-level engine + simulation tool: beacons are *synthesized* offscreen and
parsed byte-exact — no capture, no radio.

Offline (this repo, no radio):
1. `python3 firmware/beacon_analysis.py --source synthetic --json reports/w6.json` — build the
   synthetic flood corpus, run flood/churn/whitelist/SSID-confusion analysis (exit 0).
2. `python3 -m unittest discover -s tests` — byte-exact unit tests pass (exit 0).
3. `python3 firmware/beacon_analysis.py --write-pcap reports/b.pcap` then re-run with
   `--source pcap --pcap reports/b.pcap` — confirm identical results (deterministic).

Authorized lab (only with owner's written scope, shield/Faraday, authorized channel):
4. Transmit the exact beacon bytes the tool prints in a shielded enclosure and confirm a lab
   monitor (e.g., w7-wids-sensor) flags the flood and SSID confusion.
5. `green = permitted`: any radiated beacon flood requires written lab authorization, an
   air-gapped/shielded bench, and an authorized channel.

## Metrics

- Frame type engineered byte-exact: beacon (subtype 8) with SSID + rates + timestamp/interval/capability
- Synthetic corpus: 3 SSIDs, 1 real AP + flood-clones per SSID (34 frames)
- Detection: BSSID churn, flood rate (threshold 5/s), whitelist validation, SSID-confusion (>3 BSSIDs)
- IDS rule generation: `beacon_flood`, `ssid_confusion`
- pcap write/read round-trip: synthetic corpus -> fixture -> identical parse

- Test suite: `python3 -m unittest discover -s tests`
- Reports: `reports/` (gitignored)

## License

MIT
