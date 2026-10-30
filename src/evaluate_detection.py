"""Evaluate V1 and V2 against labeled synthetic scenarios.

Metrics are scenario-level, not event-level. Multiple findings that map to the
same labeled scenario count as one detected scenario, not multiple true positives.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from src.detection_engine import (
    DEFAULT_THRESHOLD,
    WINDOW,
    detect_v1,
    detect_v2,
    load_events,
)


def load_ground_truth(path: str | Path) -> list[dict[str, str]]:
    required = {"scenario_id", "username", "source_ip", "description"}
    try:
        with Path(path).open("r", newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                raise ValueError(
                    "Ground-truth CSV must contain: scenario_id, username, source_ip, description"
                )
            rows = list(reader)
    except OSError as exc:
        raise ValueError(f"Could not read ground-truth file {path}: {exc}") from exc

    if not rows:
        raise ValueError("Ground-truth file must contain at least one scenario")
    if any(not row.get("scenario_id", "").strip() for row in rows):
        raise ValueError("Ground-truth scenario_id cannot be empty")
    return rows


def evaluate(findings, scenarios: list[dict[str, str]]) -> dict[str, object]:
    """Return scenario-level TP/FP/FN, precision, recall, and F1."""
    detected_scenarios: set[str] = set()
    unmatched_findings = []

    for finding in findings:
        matches = []
        for scenario in scenarios:
            same_account = (
                finding.grouping == "username"
                and finding.subject == scenario["username"].strip()
            )
            expected_ip = scenario["source_ip"].strip()
            same_ip = (
                finding.grouping == "source_ip"
                and expected_ip
                and finding.subject == expected_ip
            )
            if same_account or same_ip:
                matches.append(scenario["scenario_id"].strip())

        if matches:
            detected_scenarios.update(matches)
        else:
            unmatched_findings.append(finding)

    expected_scenarios = {row["scenario_id"].strip() for row in scenarios}
    true_positives = len(detected_scenarios & expected_scenarios)
    false_negatives = len(expected_scenarios - detected_scenarios)
    false_positives = len(unmatched_findings)

    precision = (
        true_positives / (true_positives + false_positives)
        if true_positives + false_positives
        else 0.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if true_positives + false_negatives
        else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "detected_scenarios": sorted(detected_scenarios),
        "missed_scenarios": sorted(expected_scenarios - detected_scenarios),
        "unmatched_findings": unmatched_findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate detection versions against labeled synthetic scenarios."
    )
    parser.add_argument("--input", default="data/auth_logs.csv")
    parser.add_argument("--ground-truth", default="data/ground_truth.csv")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    args = parser.parse_args()

    try:
        events = load_events(args.input)
        scenarios = load_ground_truth(args.ground_truth)
        if args.threshold < 1:
            raise ValueError("threshold must be a positive integer")

        print("Scenario-Level Detection Evaluation")
        print("-----------------------------------")
        for version, detector in (("V1", detect_v1), ("V2", detect_v2)):
            findings = detector(events, threshold=args.threshold, window=WINDOW)
            result = evaluate(findings, scenarios)
            print(f"\n{version}:")
            print(f"True Positives: {result['true_positives']}")
            print(f"False Positives: {result['false_positives']}")
            print(f"False Negatives: {result['false_negatives']}")
            print(f"Precision: {result['precision']:.1%}")
            print(f"Recall: {result['recall']:.1%}")
            print(f"F1 Score: {result['f1']:.1%}")
            print(
                "Missed Scenarios: "
                + (", ".join(result["missed_scenarios"]) or "None")
            )

        print(
            "\nNote: These are scenario-level metrics on a small, labeled synthetic "
            "dataset. They are not production performance estimates."
        )
    except ValueError as exc:
        parser.error(str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
