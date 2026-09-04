#!/usr/bin/env python3
"""W6 — Beacon Flood / SSID-Confusion Analysis. Detect beacon floods and BSSID churn."""

import csv
import io
import math
import sys
import time
from collections import Counter, defaultdict


def _parse_beacon_frame(raw_bytes):
    """Parse a beacon frame from raw 802.11 bytes (simplified)."""
    if len(raw_bytes) < 36:
        return None
    frame_type = (raw_bytes[0] >> 2) & 0x03
    subtype = (raw_bytes[0] >> 4) & 0x0F
    bssid = ":".join(f"{b:02x}" for b in raw_bytes[10:16])
    timestamp = int.from_bytes(raw_bytes[24:32], "little")
    beacon_interval = int.from_bytes(raw_bytes[32:34], "little")
    capability = int.from_bytes(raw_bytes[34:36], "little")
    ssid = ""
    idx = 36
    while idx < len(raw_bytes) - 2:
        elem_id = raw_bytes[idx]
        elem_len = raw_bytes[idx + 1] if idx + 1 < len(raw_bytes) else 0
        if elem_id == 0:
            ssid = raw_bytes[idx + 2:idx + 2 + elem_len].decode("utf-8", errors="replace")
        idx += 2 + elem_len
    return {
        "frame_type": frame_type,
        "subtype": subtype,
        "bssid": bssid,
        "timestamp": timestamp,
        "beacon_interval": beacon_interval,
        "capability": capability,
        "ssid": ssid,
    }


EMBEDDED_BEACON_FRAMES = [
    {"ts": 0.000, "bssid": "aa:bb:cc:dd:ee:01", "ssid": "CorpWiFi", "rssi": -35, "channel": 1, "type": "real"},
    {"ts": 0.001, "bssid": "aa:bb:cc:dd:ee:02", "ssid": "CorpWiFi", "rssi": -36, "channel": 1, "type": "fake"},
    {"ts": 0.002, "bssid": "aa:bb:cc:dd:ee:03", "ssid": "CorpWiFi", "rssi": -37, "channel": 1, "type": "fake"},
    {"ts": 0.003, "bssid": "aa:bb:cc:dd:ee:04", "ssid": "CorpWiFi", "rssi": -38, "channel": 1, "type": "fake"},
    {"ts": 0.004, "bssid": "aa:bb:cc:dd:ee:05", "ssid": "CorpWiFi", "rssi": -39, "channel": 1, "type": "fake"},
    {"ts": 0.005, "bssid": "aa:bb:cc:dd:ee:06", "ssid": "CorpWiFi", "rssi": -40, "channel": 1, "type": "fake"},
    {"ts": 0.006, "bssid": "aa:bb:cc:dd:ee:07", "ssid": "CorpWiFi", "rssi": -41, "channel": 1, "type": "fake"},
    {"ts": 0.007, "bssid": "aa:bb:cc:dd:ee:08", "ssid": "CorpWiFi", "rssi": -42, "channel": 1, "type": "fake"},
    {"ts": 0.008, "bssid": "aa:bb:cc:dd:ee:09", "ssid": "CorpWiFi", "rssi": -43, "channel": 1, "type": "fake"},
    {"ts": 0.009, "bssid": "aa:bb:cc:dd:ee:0a", "ssid": "CorpWiFi", "rssi": -44, "channel": 1, "type": "fake"},
    {"ts": 0.010, "bssid": "aa:bb:cc:dd:ee:0b", "ssid": "CorpWiFi", "rssi": -45, "channel": 1, "type": "fake"},
    {"ts": 0.011, "bssid": "aa:bb:cc:dd:ee:0c", "ssid": "CorpWiFi", "rssi": -46, "channel": 1, "type": "fake"},
    {"ts": 0.012, "bssid": "aa:bb:cc:dd:ee:0d", "ssid": "CorpWiFi", "rssi": -47, "channel": 1, "type": "fake"},
    {"ts": 0.013, "bssid": "aa:bb:cc:dd:ee:0e", "ssid": "CorpWiFi", "rssi": -48, "channel": 1, "type": "fake"},
    {"ts": 0.014, "bssid": "aa:bb:cc:dd:ee:0f", "ssid": "CorpWiFi", "rssi": -49, "channel": 1, "type": "fake"},
    {"ts": 0.015, "bssid": "aa:bb:cc:dd:ee:10", "ssid": "CorpWiFi", "rssi": -50, "channel": 1, "type": "fake"},
    {"ts": 0.016, "bssid": "aa:bb:cc:dd:ee:11", "ssid": "GuestNet", "rssi": -55, "channel": 6, "type": "real"},
    {"ts": 0.017, "bssid": "aa:bb:cc:dd:ee:12", "ssid": "GuestNet", "rssi": -56, "channel": 6, "type": "fake"},
    {"ts": 0.018, "bssid": "aa:bb:cc:dd:ee:13", "ssid": "GuestNet", "rssi": -57, "channel": 6, "type": "fake"},
    {"ts": 0.019, "bssid": "aa:bb:cc:dd:ee:14", "ssid": "GuestNet", "rssi": -58, "channel": 6, "type": "fake"},
    {"ts": 0.020, "bssid": "aa:bb:cc:dd:ee:15", "ssid": "GuestNet", "rssi": -59, "channel": 6, "type": "fake"},
    {"ts": 0.021, "bssid": "aa:bb:cc:dd:ee:16", "ssid": "GuestNet", "rssi": -60, "channel": 6, "type": "fake"},
    {"ts": 0.022, "bssid": "aa:bb:cc:dd:ee:17", "ssid": "GuestNet", "rssi": -61, "channel": 6, "type": "fake"},
    {"ts": 0.023, "bssid": "aa:bb:cc:dd:ee:18", "ssid": "GuestNet", "rssi": -62, "channel": 6, "type": "fake"},
    {"ts": 0.024, "bssid": "aa:bb:cc:dd:ee:19", "ssid": "GuestNet", "rssi": -63, "channel": 6, "type": "fake"},
    {"ts": 0.025, "bssid": "aa:bb:cc:dd:ee:1a", "ssid": "GuestNet", "rssi": -64, "channel": 6, "type": "fake"},
    {"ts": 0.026, "bssid": "aa:bb:cc:dd:ee:1b", "ssid": "GuestNet", "rssi": -65, "channel": 6, "type": "fake"},
    {"ts": 0.027, "bssid": "aa:bb:cc:dd:ee:1c", "ssid": "HomeWiFi", "rssi": -42, "channel": 11, "type": "real"},
    {"ts": 0.028, "bssid": "aa:bb:cc:dd:ee:1d", "ssid": "HomeWiFi", "rssi": -43, "channel": 11, "type": "fake"},
    {"ts": 0.029, "bssid": "aa:bb:cc:dd:ee:1e", "ssid": "HomeWiFi", "rssi": -44, "channel": 11, "type": "fake"},
    {"ts": 0.030, "bssid": "aa:bb:cc:dd:ee:1f", "ssid": "HomeWiFi", "rssi": -45, "channel": 11, "type": "fake"},
    {"ts": 0.031, "bssid": "aa:bb:cc:dd:ee:20", "ssid": "HomeWiFi", "rssi": -46, "channel": 11, "type": "fake"},
]

KNOWN_WHITELIST = {
    "aa:bb:cc:dd:ee:01": "CorpWiFi",
    "aa:bb:cc:dd:ee:11": "GuestNet",
    "aa:bb:cc:dd:ee:1c": "HomeWiFi",
}


def compute_bssid_churn(frames, window_sec=1.0):
    """Compute BSSID churn rate (new BSSIDs per minute) across time windows."""
    if not frames:
        return []
    windows = defaultdict(set)
    for f in frames:
        bucket = int(f["ts"] // window_sec)
        windows[bucket].add(f["bssid"])
    seen_total = set()
    churn = []
    for bucket in sorted(windows.keys()):
        new_bssids = windows[bucket] - seen_total
        seen_total |= windows[bucket]
        churn.append({
            "window": bucket,
            "new_bssids": len(new_bssids),
            "total_bssids": len(seen_total),
            "bssids_in_window": len(windows[bucket]),
        })
    return churn


def detect_flood(frames, threshold_bssid_per_sec=5):
    """Detect beacon flood based on BSSID rate threshold."""
    if not frames:
        return False, 0.0
    duration = frames[-1]["ts"] - frames[0]["ts"] if len(frames) > 1 else 1.0
    unique_bssids = len(set(f["bssid"] for f in frames))
    rate = unique_bssids / max(duration, 0.001)
    return rate > threshold_bssid_per_sec, rate


def validate_whitelist(frames, whitelist):
    """Validate which real APs from the whitelist appeared correctly."""
    present_bssids = set(f["bssid"] for f in frames)
    results = []
    for bssid, ssid in whitelist.items():
        if bssid in present_bssids:
            appearances = sum(1 for f in frames if f["bssid"] == bssid)
            results.append({"bssid": bssid, "ssid": ssid, "status": "FOUND", "count": appearances})
        else:
            results.append({"bssid": bssid, "ssid": ssid, "status": "MISSING", "count": 0})
    return results


def compute_ssid_confusion(frames):
    """Detect SSID confusion: same SSID broadcast by many BSSIDs."""
    ssid_bssid_map = defaultdict(set)
    for f in frames:
        ssid_bssid_map[f["ssid"]].add(f["bssid"])
    results = []
    for ssid, bssids in ssid_bssid_map.items():
        results.append({
            "ssid": ssid,
            "bssid_count": len(bssids),
            "is_flood": len(bssids) > 3,
        })
    return results


class BeaconAnalyzer:
    """Beacon flood detection and SSID-confusion analysis suite."""

    def __init__(self, frames=None):
        self.frames = frames or EMBEDDED_BEACON_FRAMES
        self.churn = []
        self.flood_detected = False
        self.flood_rate = 0.0
        self.whitelist_results = []
        self.ssid_confusion = []

    def analyze(self):
        """Run the complete beacon analysis."""
        print("=" * 60)
        print("  W6 — Beacon Flood / SSID-Confusion Analysis")
        print("=" * 60)

        print(f"\n[+] Loaded {len(self.frames)} beacon frames")

        unique_bssids = set(f["bssid"] for f in self.frames)
        unique_ssids = set(f["ssid"] for f in self.frames)
        print(f"[+] Unique BSSIDs: {len(unique_bssids)}")
        print(f"[+] Unique SSIDs: {len(unique_ssids)}")

        real_count = sum(1 for f in self.frames if f["type"] == "real")
        fake_count = sum(1 for f in self.frames if f["type"] == "fake")
        print(f"[+] Real beacons: {real_count}, Fake beacons: {fake_count}")

        self.churn = compute_bssid_churn(self.frames, window_sec=0.01)
        self.flood_detected, self.flood_rate = detect_flood(self.frames)

        print("\n=== BSSID Churn Rate ===")
        print(f"{'Window':>8} {'New BSSIDs':>12} {'Total Seen':>12} {'In Window':>10}")
        print("-" * 45)
        for entry in self.churn:
            print(f"{entry['window']:>8} {entry['new_bssids']:>12} {entry['total_bssids']:>12} {entry['bssids_in_window']:>10}")

        print(f"\n=== Flood Detection ===")
        print(f"  Flood detected: {'YES' if self.flood_detected else 'NO'}")
        print(f"  BSSID rate: {self.flood_rate:.1f} new BSSIDs/sec")
        print(f"  Threshold: 5 BSSIDs/sec")

        self.whitelist_results = validate_whitelist(self.frames, KNOWN_WHITELIST)
        print("\n=== Whitelist Validation ===")
        print(f"{'BSSID':<20} {'SSID':<15} {'Status':<10} {'Count':>5}")
        print("-" * 52)
        for wr in self.whitelist_results:
            print(f"{wr['bssid']:<20} {wr['ssid']:<15} {wr['status']:<10} {wr['count']:>5}")

        self.ssid_confusion = compute_ssid_confusion(self.frames)
        print("\n=== SSID Confusion Detection ===")
        print(f"{'SSID':<15} {'BSSID Count':>12} {'Flood?':>8}")
        print("-" * 38)
        for sc in self.ssid_confusion:
            flag = "YES" if sc["is_flood"] else "no"
            print(f"{sc['ssid']:<15} {sc['bssid_count']:>12} {flag:>8}")

        print("\n=== IDS Rule Suggestions ===")
        if self.flood_detected:
            print(f"  ALERT beacon_flood: ssid=\"*\" rate>{self.flood_rate:.0f}/sec over threshold")
        for sc in self.ssid_confusion:
            if sc["is_flood"]:
                print(f"  ALERT ssid_confusion: ssid=\"{sc['ssid']}\" bssid_count={sc['bssid_count']} > 3")
        print("[+] Analysis complete — exit 0")
        return self


def main():
    analyzer = BeaconAnalyzer()
    analyzer.analyze()
    return 0


if __name__ == "__main__":
    sys.exit(main())
