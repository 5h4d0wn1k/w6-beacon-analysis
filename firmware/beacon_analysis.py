#!/usr/bin/env python3
"""W6 — Beacon Flood / SSID-Confusion Analysis.

Byte-level 802.11 beacon engineering + flood/churn/confusion detection.
Builds a synthetic beacon corpus offscreen (frame_core), parses each frame
byte-exact, then detects beacon flood rates, BSSID churn, whitelist validity,
and SSID confusion.

No radio emitted: beacons are synthesized and parsed on the host CPU.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

try:
    from firmware import frame_core as fc
except ImportError:
    try:
        import frame_core as fc
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "firmware"))
        import frame_core as fc

# ----------------------------------------------------------------------
# Synthetic beacon corpus: (bssid, ssid, channel, rssi, type, ts_ms)
# type "real" = allowlisted legitimate AP; "fake" = flood-generated clone
# ----------------------------------------------------------------------

CORPUS = [
    ("00:11:22:33:44:01", "lab-corpwifi", 1, -35, "real", 0),
    *[(f"00:11:22:33:44:{i:02x}", "lab-corpwifi", 1, -36 - (i - 2), "fake", i) for i in range(2, 17)],
    ("00:11:22:33:44:19", "lab-guest", 6, -55, "real", 16),
    *[(f"00:11:22:33:44:{i:02x}", "lab-guest", 6, -56 - (i - 26), "fake", i) for i in range(26, 39)],
    ("00:11:22:33:44:40", "lab-home", 11, -42, "real", 39),
    *[(f"00:11:22:33:44:{i:02x}", "lab-home", 11, -43 - (i - 57), "fake", i) for i in range(57, 69)],
]

KNOWN_WHITELIST = {
    "00:11:22:33:44:01": "lab-corpwifi",
    "00:11:22:33:44:19": "lab-guest",
    "00:11:22:33:44:40": "lab-home",
}


def build_beacon_corpus():
    """Build byte-exact beacon frames from the corpus records."""
    frames = []
    for (bssid, ssid, channel, rssi, kind, tms) in CORPUS:
        beacon = fc.build_beacon(bssid, ssid=ssid, timestamp=tms * 100,
                                 beacon_interval=100, seq_num=(tms + 1) % 4096)
        beacon += fc.fcs(beacon)
        frames.append({"ts": tms / 1000.0, "bssid": bssid, "ssid": ssid,
                       "channel": channel, "rssi": rssi, "type": kind,
                       "data": beacon})
    return frames


def parse_beacon_bytes(data: bytes) -> dict:
    """Parse a raw beacon (strip FCS) via frame_core, byte-exact."""
    if fc.verify_fcs(data):
        data = data[:-4]
    fields, _ies = fc.parse_beacon(data)
    return fields


def write_beacon_pcap(frames: list[dict], path: str) -> int:
    fc.write_pcap(path, [f["data"] for f in frames], ts=frames[0]["ts"])
    return len(frames)


def read_beacon_pcap(path: str) -> list[dict]:
    out = []
    for rec in fc.read_pcap(path):
        data = rec["data"]
        try:
            fields = parse_beacon_bytes(data)
            if fields["subtype_val"] != fc.FC_SUBTYPE_BEACON:
                out.append({"kind": "ignored", "ts": rec["ts"]})
                continue
            out.append({"kind": "beacon", "bssid": fields["bssid"],
                        "ssid": fields["ssid"] or "", "seq": fields["seq_num"],
                        "interval": fields["beacon_interval"], "ts": rec["ts"]})
        except ValueError:
            out.append({"kind": "unknown", "ts": rec["ts"]})
    return out


# ----------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------


def compute_bssid_churn(frames, window_sec=1.0):
    windows = defaultdict(set)
    for f in frames:
        bucket = int(f["ts"] // window_sec)
        windows[bucket].add(f["bssid"])
    seen = set()
    churn = []
    for bucket in sorted(windows.keys()):
        new = windows[bucket] - seen
        seen |= windows[bucket]
        churn.append({"window": bucket, "new_bssids": len(new),
                      "total_bssids": len(seen), "bssids_in_window": len(windows[bucket])})
    return churn


def detect_flood(frames, threshold_per_sec=5):
    if not frames:
        return False, 0.0
    duration = (frames[-1]["ts"] - frames[0]["ts"]) if len(frames) > 1 else 1.0
    unique = len(set(f["bssid"] for f in frames))
    rate = unique / max(duration, 0.001)
    return rate > threshold_per_sec, rate


def validate_whitelist(frames, whitelist):
    present = {f["bssid"] for f in frames}
    out = []
    for bssid, ssid in whitelist.items():
        found = bssid in present
        out.append({"bssid": bssid, "ssid": ssid,
                    "status": "FOUND" if found else "MISSING",
                    "count": sum(1 for f in frames if f["bssid"] == bssid)})
    return out


def compute_ssid_confusion(frames):
    mapping = defaultdict(set)
    for f in frames:
        mapping[f["ssid"]].add(f["bssid"])
    return [{"ssid": ssid, "bssid_count": len(bssids), "is_flood": len(bssids) > 3}
            for ssid, bssids in mapping.items()]


def analyze(frames) -> dict:
    churn = compute_bssid_churn(frames, window_sec=1.0)
    flood, rate = detect_flood(frames)
    whitelist = validate_whitelist(frames, KNOWN_WHITELIST)
    confusion = compute_ssid_confusion(frames)
    rules = []
    if flood:
        rules.append({"alert": "beacon_flood", "cond": f"rate>{rate:.1f}/sec"})
    for sc in confusion:
        if sc["is_flood"]:
            rules.append({"alert": "ssid_confusion", "ssid": sc["ssid"],
                          "bssid_count": sc["bssid_count"]})
    return {
        "name": "w6-beacon-analysis",
        "radio_emitted": False,
        "total_frames": len(frames),
        "unique_bssids": len({f["bssid"] for f in frames}),
        "unique_ssids": len({f["ssid"] for f in frames}),
        "real_count": sum(1 for f in frames if f["type"] == "real"),
        "fake_count": sum(1 for f in frames if f["type"] == "fake"),
        "churn": churn,
        "flood_detected": flood,
        "flood_rate": round(rate, 1),
        "whitelist_validation": whitelist,
        "ssid_confusion": confusion,
        "ids_rules": rules,
    }


def build_args_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="w6-beacon-analysis",
        description="Beacon flood / SSID-confusion analysis over byte-exact 802.11 beacons "
                    "(pure-stdlib bytes; offline; no radio).")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--source", choices=["synthetic", "pcap"], default="synthetic")
    p.add_argument("--pcap", metavar="PATH")
    p.add_argument("--write-pcap", metavar="PATH")
    p.add_argument("--json", metavar="PATH")
    return p


def run_beacon_analysis(source, pcap_path):
    if source == "pcap":
        if not pcap_path or not os.path.exists(pcap_path):
            raise FileNotFoundError(pcap_path)
        rows = read_beacon_pcap(pcap_path)
        frames = [{"ts": r["ts"], "bssid": r["bssid"], "ssid": r["ssid"] or "<hidden>",
                   "channel": 0, "rssi": 0, "type": "pcap", "data": b""}
                  for r in rows if r["kind"] == "beacon"]
        origin = f"pcap:{pcap_path}"
    else:
        frames = build_beacon_corpus()
        origin = "byte-exact beacon builders"
    result = analyze(frames)
    result["origin"] = origin
    return result


def print_report(result: dict) -> None:
    print("=" * 66)
    print("W6 — Beacon Flood / SSID-Confusion Analysis")
    print("=" * 66)
    print(f"\n[+] Source: {result['origin']}   (radio_emitted=False)")
    print(f"[+] Beacons: {result['total_frames']}  Unique BSSIDs: {result['unique_bssids']}  "
          f"SSIDs: {result['unique_ssids']}")
    print(f"[+] Real: {result['real_count']}  Flood-clone: {result['fake_count']}\n")

    print("--- Flood Detection ---")
    print(f"  Flood detected: {'YES' if result['flood_detected'] else 'NO'}")
    print(f"  BSSID rate: {result['flood_rate']:.1f} new BSSIDs/sec (threshold 5)")

    print("\n--- Whitelist Validation ---")
    for wr in result["whitelist_validation"]:
        print(f"  {wr['status']:<7} {wr['bssid']}  {wr['ssid']}  (seen {wr['count']}x)")

    print("\n--- SSID Confusion ---")
    for sc in result["ssid_confusion"]:
        flag = "YES" if sc["is_flood"] else "no"
        print(f"  {sc['ssid']:<16} {sc['bssid_count']:>3d} BSSIDs  flood={flag}")

    print("\n--- IDS Rule Suggestions ---")
    if not result["ids_rules"]:
        print("  (none)")
    for r in result["ids_rules"]:
        print(f"  ALERT {r['alert']}: {r.get('cond', r.get('ssid', ''))}")

    print("\nOffline analysis complete — no radio emitted.")
    print("=" * 66)


def main(argv=None) -> int:
    args = build_args_parser().parse_args(argv)
    try:
        result = run_beacon_analysis(args.source, args.pcap)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print_report(result)
    if args.write_pcap:
        n = write_beacon_pcap(build_beacon_corpus(), args.write_pcap)
        print(f"\n[+] beacon corpus -> {args.write_pcap} ({n} frames)")
    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2, default=str)
    return 0


def run_demo() -> int:
    return main(["--source", "synthetic"])


if __name__ == "__main__":
    raise SystemExit(main())
