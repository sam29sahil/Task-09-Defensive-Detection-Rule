import csv
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from src.detection_engine import (
    AuthEvent,
    detect_v1,
    detect_v2,
    load_events,
    parse_timestamp,
)


def event(timestamp, username, source_ip, status="failed"):
    return AuthEvent(parse_timestamp(timestamp), username, source_ip, status)


class DetectionEngineTests(unittest.TestCase):
    def setUp(self):
        self.ip_burst = [
            event(f"2026-10-29T09:0{i}:00Z", "alice", "192.0.2.10")
            for i in range(0, 5)
        ]
        self.distributed_account = [
            event(f"2026-10-29T09:1{i}:00Z", "carol", f"203.0.113.{10+i}")
            for i in range(5)
        ]

    def test_v1_detects_repeated_failures_from_one_ip(self):
        findings = detect_v1(self.ip_burst)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].subject, "192.0.2.10")
        self.assertEqual(findings[0].rule_id, "AUTH-FAIL-IP-001")

    def test_v1_does_not_detect_distributed_sources(self):
        self.assertEqual(detect_v1(self.distributed_account), [])

    def test_v2_detects_distributed_failures_against_one_account(self):
        findings = detect_v2(self.distributed_account)
        account_findings = [f for f in findings if f.grouping == "username"]
        self.assertEqual(len(account_findings), 1)
        self.assertEqual(account_findings[0].subject, "carol")

    def test_success_events_are_not_counted(self):
        events = [
            event(f"2026-10-29T09:0{i}:00Z", "alice", "192.0.2.10", "success")
            for i in range(5)
        ]
        self.assertEqual(detect_v2(events), [])

    def test_events_outside_window_are_not_combined(self):
        events = [
            event("2026-10-29T09:00:00Z", "alice", "192.0.2.10"),
            event("2026-10-29T09:06:00Z", "alice", "192.0.2.10"),
            event("2026-10-29T09:12:00Z", "alice", "192.0.2.10"),
            event("2026-10-29T09:18:00Z", "alice", "192.0.2.10"),
            event("2026-10-29T09:24:00Z", "alice", "192.0.2.10"),
        ]
        self.assertEqual(detect_v2(events), [])

    def test_unsorted_input_is_supported(self):
        findings = detect_v1(list(reversed(self.ip_burst)))
        self.assertEqual(len(findings), 1)

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            detect_v1(self.ip_burst, threshold=0)

    def test_invalid_ip_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text(
                "timestamp,username,source_ip,status\n"
                "2026-10-29T09:00:00Z,alice,not-an-ip,failed\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid source IP"):
                load_events(path)

    def test_invalid_status_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text(
                "timestamp,username,source_ip,status\n"
                "2026-10-29T09:00:00Z,alice,192.0.2.10,blocked\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "status must"):
                load_events(path)

    def test_invalid_timestamp_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text(
                "timestamp,username,source_ip,status\n"
                "not-a-time,alice,192.0.2.10,failed\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Invalid ISO-8601"):
                load_events(path)


if __name__ == "__main__":
    unittest.main()
