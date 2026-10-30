# Task 9 — Detection Evaluation Results

**Dataset:** `data/auth_logs.csv` (15 synthetic authentication events)  
**Ground truth:** `data/ground_truth.csv` (2 labeled scenarios)  
**Evaluation unit:** Scenario-level

## Command executed

```powershell
python -m src.evaluate_detection --input data/auth_logs.csv --ground-truth data/ground_truth.csv
```

## Results

| Metric | V1 | V2 |
|---|---:|---:|
| True positives | 1 | 2 |
| False positives | 0 | 0 |
| False negatives | 1 | 0 |
| Precision | 100.0% | 100.0% |
| Recall | 50.0% | 100.0% |
| F1 score | 66.7% | 100.0% |

## Interpretation

- **V1** detected the repeated failures from source IP `192.0.2.10`.
- **V1 missed** `carol_distributed_burst`: five failures targeted account `carol` from different source IPs, so no individual IP reached the threshold.
- **V2** retained the source-IP detection and added username-based correlation, detecting both labeled scenarios.
- No findings were unmatched to the two labeled scenarios in this dataset.

## Limitations

These are scenario-level metrics from a tiny, deliberately constructed synthetic dataset. They demonstrate the evaluation method and the effect of adding account-based correlation; they do not establish real-world accuracy, operational false-positive rates, or production readiness.
