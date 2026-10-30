# Task 9 — Defensive Detection Rule Lab

A small defensive detection-engineering lab that analyzes **synthetic authentication events**, detects repeated failed logins, and evaluates two iterations of a rule.

> **Scope and safety:** This project uses synthetic CSV data only. It does not connect to real systems, collect credentials, scan networks, or take blocking actions. Replace the sample data only with logs you are authorized to analyze.

## Objectives

- Model authentication events in a consistent CSV schema.
- Implement a baseline threshold detector (Version 1).
- Improve coverage with account-based correlation (Version 2).
- Express the detection logic in Sigma-style YAML rules.
- Test normal, suspicious, boundary, and malformed input cases.
- Review limitations, false-positive risk, and missed-detection scenarios.

## Repository structure

```text
Task-09-Defensive-Detection-Rule/
├── data/
│   └── auth_logs.csv
├── rules/
│   ├── detection_v1.yml
│   └── detection_v2.yml
├── src/
│   └── detection_engine.py
├── tests/
│   └── test_detection.py
├── reports/
│   └── .gitkeep
├── .gitignore
├── README.md
└── requirements.txt
```

## Dataset schema

| Field | Meaning |
|---|---|
| timestamp | ISO-8601 event time |
| username | Account name involved |
| source_ip | Source IPv4/IPv6 address |
| status | `success` or `failed` |

The sample includes a normal user, repeated failures from a single source, and repeated failures against one account from multiple sources. All addresses are documentation ranges reserved for examples.

## Detection logic

### Version 1 — Source-IP threshold

Flags a source IP after **5 or more failed events in a rolling 5-minute window**.

### Version 2 — IP and account correlation

Retains the source-IP rule and adds detection for **5 or more failed events against the same username in a rolling 5-minute window**, even if attempts arrive from different source IPs.

The detector evaluates each event timestamp as the end of a rolling window and supports unsorted input.

## Setup

Python 3.10+ is recommended. There are no third-party runtime dependencies.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python src/detection_engine.py --input data/auth_logs.csv --version v1
python src/detection_engine.py --input data/auth_logs.csv --version v2
python -m unittest discover -s tests -v
```

## Local execution results

The user-provided PowerShell output for the included 15-event dataset showed:

| Metric | Result |
|---|---:|
| Total events | 15 |
| Successful events | 3 |
| Failed events | 12 |
| Version 1 findings | 1 |
| Version 2 findings | 3 |

Version 1 flagged source IP `192.0.2.10` after five failures. Version 2 retained that IP finding and additionally flagged the accounts `alice` and `carol`. The distributed failures for `carol` came from multiple source IPs, demonstrating the additional coverage of account-based correlation.

 The subsequent PowerShell test run completed successfully: `Ran 10 tests in 0.015s` followed by `OK`. All 10 unit tests passed in the user's local environment.

## Output

Each finding includes a rule identifier, grouping key, failed-event count, threshold, window start/end, severity, and description.

## Test coverage

Unit tests cover:
- Baseline source-IP detection.
- Improved account-based detection.
- Success events are not counted as failures.
- Events outside the time window are not combined.
- Unsorted event timestamps.
- Invalid statuses, timestamps, thresholds, and IP addresses.

## Detection limitations and tuning

- Thresholds are illustrative and should be tuned to the environment and baseline behavior.
- Shared NAT, proxies, automated clients, and misconfigured applications can create false positives.
- Distributed attempts across many accounts and IPs may evade these simple per-key thresholds.
- A threshold crossing is an alert signal, not proof of compromise.
- The YAML files are Sigma-style conceptual rule definitions. The Python engine is the executable implementation; native SIEM correlation syntax and backend conversion are not claimed.

## References

- [Sigma rule specification](https://sigmahq.io/sigma-specification/)
- [Sigma rules repository](https://github.com/SigmaHQ/sigma)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Python csv documentation](https://docs.python.org/3/library/csv.html)
- [Python unittest documentation](https://docs.python.org/3/library/unittest.html)

## Evidence

Store genuine terminal screenshots in `screenshots/`. Do not represent reconstructed illustrations as actual execution evidence.
