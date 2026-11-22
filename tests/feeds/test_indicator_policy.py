#!/usr/bin/env python3
"""Offline checks of IP indicator confidence, expiry, and stable Suricata SIDs.

Run:
    python3 -m unittest discover -s tests/feeds -p 'test_*.py' -v
"""
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
module_spec = importlib.util.spec_from_file_location("build_feeds", ROOT / "tools" / "build_feeds.py")
feeds = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(feeds)


def record(value, confidence="medium", review_by="2027-04-01", *,
           kind="ipv4", actor="A", context="one"):
    return {
        "value": value, "type": kind, "confidence": confidence,
        "review_by": review_by, "actor": actor, "context": context,
        "source": "synthetic", "source_url": "https://example.invalid/source",
        "framework": "artex",
    }


class ActiveIndicatorTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.original_root = feeds.ROOT
        feeds.ROOT = Path(self.tempdir.name)

    def tearDown(self):
        feeds.ROOT = self.original_root
        self.tempdir.cleanup()

    def output(self, relative):
        return (feeds.ROOT / relative).read_text(encoding="utf-8")

    def test_expired_address_omitted_on_all_active_surfaces(self):
        good = record("192.0.2.101")
        expired = record("192.0.2.102", review_by="2026-08-29")
        feeds.plain_lists([good, expired], feeds.ROOT / "feeds")
        feeds.zeek_intel([good, expired], "artex")
        feeds.suricata_ip([good, expired], "artex")
        for path in (
            "feeds/ipv4.txt", "frameworks/artex/zeek/intel/artex.intel",
            "frameworks/artex/suricata/artex-ip.rules",
        ):
            body = self.output(path)
            self.assertIn(good["value"], body, path)
            self.assertNotIn(expired["value"], body, path)

    def test_deadline_inclusive_and_empty_deadline_allowed(self):
        self.assertTrue(feeds.active_ip(record("192.0.2.201", review_by=feeds.ACTIVE_AS_OF)))
        self.assertFalse(feeds.active_ip(record("192.0.2.202", review_by="2026-11-21")))
        self.assertTrue(feeds.active_ip(record("192.0.2.203", review_by="")))

    def test_low_confidence_not_promoted_by_grouping(self):
        rows = [
            record("192.0.2.1", confidence="medium"),
            record("192.0.2.2", confidence="low"),
            record("192.0.2.3", confidence="high", review_by="2026-08-29"),
        ]
        feeds.suricata_ip(rows, "artex")
        alerts = [line for line in self.output(
            "frameworks/artex/suricata/artex-ip.rules"
        ).splitlines() if line.startswith("alert ip ")]
        self.assertEqual(len(alerts), 2)
        for line in alerts:
            self.assertIn("confidence Low", line)
            self.assertIn("classtype:misc-activity", line)
            self.assertNotIn(rows[-1]["value"], line)

    def test_expired_group_reserves_suricata_sids(self):
        rows = [
            record("192.0.2.1", actor="A"),
            record("192.0.2.2", actor="B", review_by="2026-08-29"),
            record("192.0.2.3", actor="C"),
        ]
        feeds.suricata_ip(rows, "artex")
        body = self.output("frameworks/artex/suricata/artex-ip.rules")
        ids = re.findall(r"\bsid:(\d+);", body)
        first = feeds.FRAMEWORKS["artex"]["sid"]
        self.assertEqual(ids, [str(first), str(first + 1),
                               str(first + 4), str(first + 5)])
        self.assertNotIn(rows[1]["value"], body)

    def test_low_confidence_domains_remain_context_only(self):
        row = record("api.example.invalid", confidence="low", kind="domain")
        feeds.plain_lists([row], feeds.ROOT / "feeds")
        feeds.zeek_intel([row], "artex")
        self.assertNotIn(row["value"], self.output("feeds/domains.txt"))
        self.assertIn("low:", self.output("frameworks/artex/zeek/intel/artex.intel"))

    def test_release_snapshot_matches_waf_cutoff(self):
        signatures = (self.original_root / "waf" / "signatures.yaml").read_text(
            encoding="utf-8"
        )
        match = re.search(r'^as_of:\s*["\x27]?(\d{4}-\d{2}-\d{2})', signatures, re.M)
        self.assertIsNotNone(match)
        self.assertEqual(feeds.ACTIVE_AS_OF, match.group(1))


if __name__ == "__main__":
    unittest.main()
