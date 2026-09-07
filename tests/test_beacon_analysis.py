#!/usr/bin/env python3
"""Byte-exact unit tests for w6-beacon-analysis."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import beacon_analysis as ba
from firmware import frame_core as fc


class BeaconBuildTest(unittest.TestCase):
    def test_beacon_roundtrip_byte_exact(self):
        beacon = fc.build_beacon("00:11:22:33:44:01", ssid="lab-corpwifi",
                                 timestamp=0, beacon_interval=100, seq_num=1)
        fields, _ies = fc.parse_beacon(beacon)
        self.assertEqual(fields["ssid"], "lab-corpwifi")
        self.assertEqual(fields["bssid"], "00:11:22:33:44:01")
        self.assertEqual(fields["beacon_interval"], 100)
        rebuilt = fc.build_beacon(fields["bssid"], ssid=fields["ssid"],
                                  timestamp=fields["timestamp"],
                                  beacon_interval=fields["beacon_interval"],
                                  seq_num=fields["seq_num"])
        self.assertEqual(rebuilt, beacon)

    def test_corpus_beacons_parse_with_fcs(self):
        for f in ba.build_beacon_corpus():
            self.assertTrue(fc.verify_fcs(f["data"]))
            fields = ba.parse_beacon_bytes(f["data"])
            self.assertEqual(fields["ssid"], f["ssid"])
            self.assertEqual(fields["bssid"], f["bssid"])


class AnalysisTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frames = ba.build_beacon_corpus()
        cls.result = ba.analyze(cls.frames)

    def test_flood_detected(self):
        self.assertTrue(self.result["flood_detected"])
        self.assertGreater(self.result["flood_rate"], 5.0)

    def test_whitelist_all_found(self):
        for wr in self.result["whitelist_validation"]:
            if wr["ssid"] in ("lab-corpwifi", "lab-guest", "lab-home"):
                self.assertEqual(wr["status"], "FOUND")

    def test_ssid_confusion_flood(self):
        for sc in self.result["ssid_confusion"]:
            if sc["ssid"] == "lab-corpwifi":
                self.assertTrue(sc["is_flood"])
                self.assertGreater(sc["bssid_count"], 3)

    def test_ids_rules_emitted(self):
        self.assertTrue(any(r["alert"] == "beacon_flood" for r in self.result["ids_rules"]))
        self.assertTrue(any(r["alert"] == "ssid_confusion" for r in self.result["ids_rules"]))


class PcapTest(unittest.TestCase):
    def test_pcap_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "b.pcap")
            frames = ba.build_beacon_corpus()
            n = ba.write_beacon_pcap(frames, path)
            self.assertEqual(n, len(frames))
            recs = ba.read_beacon_pcap(path)
            beacons = [r for r in recs if r["kind"] == "beacon"]
            self.assertEqual(len(beacons), len(frames))
            self.assertEqual(beacons[0]["ssid"], "lab-corpwifi")


class ReportTest(unittest.TestCase):
    def test_output_mode_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "o.json")
            rc = ba.main(["--source", "synthetic", "--json", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))

    def test_demo_exit_zero(self):
        self.assertEqual(ba.run_demo(), 0)


if __name__ == "__main__":
    unittest.main()
