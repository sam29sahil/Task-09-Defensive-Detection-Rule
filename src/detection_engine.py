"""Analyze synthetic authentication logs for repeated failed logins."""

from __future__ import annotations

import argparse
import csv
import ipaddress
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


WINDOW = timedelta(minutes=5)
DEFAULT_THRESHOLD = 5
VALID_STATUSES = {"success", "failed"}


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    username: str
    source_ip: str
    status: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    grouping: str
    subject: str
    failed_attempts: int
    threshold: int
    window_start: str
    window_end: str
    severity: str
    description: str


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid ISO-8601 timestamp: {value!r}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_events(path: str | Path) -> list[AuthEvent]:
    """Load and validate authentication events from a CSV file."""
    events: list[AuthEvent] = []
    required = {"timestamp", "username", "source_ip", "status"}

    try:
        with Path(path).open("r", newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                raise ValueError(
                    "CSV must contain columns: timestamp, username, source_ip, status"
                )

            for line_number, row in enumerate(reader, start=2):
                try:
                    username = (row.get("username") or "").strip()
                    status = (row.get("status") or "").strip().lower()
                    source_ip = (row.get("source_ip") or "").strip()
                    timestamp = parse_timestamp(row.get("timestamp") or "")

                    if not username:
                        raise ValueError("username cannot be empty")
                    if status not in VALID_STATUSES:
                        raise ValueError("status must be 'success' or 'failed'")
                    try:
                        source_ip = str(ipaddress.ip_address(source_ip))
                    except ValueError as exc:
                        raise ValueError(f"invalid source IP: {source_ip!r}") from exc

                    events.append(
                        AuthEvent(timestamp, username, source_ip, status)
                    )
                except ValueError as exc:
                    raise ValueError(f"CSV line {line_number}: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"Could not read input file {path}: {exc}") from exc

    return events


def _detect_group(
    events: Iterable[AuthEvent],
    *,
    group_field: str,
    threshold: int,
    rule_id: str,
    window: timedelta,
) -> list[Finding]:
    """Detect threshold crossings independently for each selected key."""
    buckets: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.status == "failed":
            key = event.source_ip if group_field == "source_ip" else event.username
            buckets[key].append(event)

    findings: list[Finding] = []
    for subject, group_events in buckets.items():
        ordered = sorted(group_events, key=lambda item: item.timestamp)
        left = 0

        for right, current in enumerate(ordered):
            window_start = current.timestamp - window
            while left <= right and ordered[left].timestamp < window_start:
                left += 1

            count = right - left + 1
            if count == threshold:
                severity = "high" if count >= threshold * 2 else "medium"
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        grouping=group_field,
                        subject=subject,
                        failed_attempts=count,
                        threshold=threshold,
                        window_start=ordered[left].timestamp.isoformat(),
                        window_end=current.timestamp.isoformat(),
                        severity=severity,
                        description=(
                            f"{count} failed authentication events for "
                            f"{group_field} within {window.total_seconds() / 60:g} minutes."
                        ),
                    )
                )
                # Report one threshold-crossing finding per grouping key.
                break

    return findings


def detect_v1(
    events: Iterable[AuthEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window: timedelta = WINDOW,
) -> list[Finding]:
    """Version 1: repeated failed logins grouped by source IP."""
    _validate_detection_parameters(threshold, window)
    return _detect_group(
        events,
        group_field="source_ip",
        threshold=threshold,
        rule_id="AUTH-FAIL-IP-001",
        window=window,
    )


def detect_v2(
    events: Iterable[AuthEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window: timedelta = WINDOW,
) -> list[Finding]:
    """Version 2: source-IP detection plus per-account correlation."""
    _validate_detection_parameters(threshold, window)
    materialized = list(events)
    return (
        _detect_group(
            materialized,
            group_field="source_ip",
            threshold=threshold,
            rule_id="AUTH-FAIL-IP-001",
            window=window,
        )
        + _detect_group(
            materialized,
            group_field="username",
            threshold=threshold,
            rule_id="AUTH-FAIL-USER-002",
            window=window,
        )
    )


def _validate_detection_parameters(threshold: int, window: timedelta) -> None:
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    if window.total_seconds() <= 0:
        raise ValueError("window must be greater than zero")


def print_results(events: list[AuthEvent], findings: list[Finding], version: str) -> None:
    print("Defensive Detection Rule Lab")
    print("----------------------------")
    print(f"Rule Version: {version.upper()}")
    print(f"Total Events: {len(events)}")
    print(f"Successful Events: {sum(e.status == 'success' for e in events)}")
    print(f"Failed Events: {sum(e.status == 'failed' for e in events)}")
    print(f"Detection Findings: {len(findings)}")
    print("\nFindings:")
    if not findings:
        print("- No threshold crossings detected.")
    for item in findings:
        print(
            f"- [{item.severity.upper()}] {item.rule_id} | "
            f"{item.grouping}={item.subject} | "
            f"{item.failed_attempts} failures | "
            f"{item.window_start} -> {item.window_end}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect repeated failed logins in an authorized CSV dataset."
    )
    parser.add_argument("--input", required=True, help="Path to authentication CSV")
    parser.add_argument("--version", choices=("v1", "v2"), default="v2")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parser.add_argument("--window-minutes", type=float, default=5.0)
    args = parser.parse_args()

    try:
        if args.window_minutes <= 0:
            raise ValueError("window-minutes must be greater than zero")
        events = load_events(args.input)
        window = timedelta(minutes=args.window_minutes)
        findings = (
            detect_v1(events, args.threshold, window)
            if args.version == "v1"
            else detect_v2(events, args.threshold, window)
        )
        print_results(events, findings, args.version)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
