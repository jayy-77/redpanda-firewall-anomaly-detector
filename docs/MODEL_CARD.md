# Model Card — Firewall Anomaly Detector (streaming)

## Task
Real-time anomaly scoring of firewall log time-windows. Inputs are
60-second aggregates per log_source; output is a single anomaly score in
[0,1] that drives Kafka topic routing.

## Inputs (7-dim feature vector)
- `mean_value` — mean of the metric (connection_count / bytes_sent / bytes_recv) in the window
- `std_dev` — sample std of metric values in the window
- `max_value`, `min_value` — extremes within the window
- `percent_change` — % difference vs. previous window's mean
- `unique_ips` — count of distinct src IPs
- `peak_to_mean_ratio` — max / mean

These are emitted by the Go processor and reproduced bit-for-bit by
`training/extract_features.py` to avoid train-serve skew.

## Models supported
- IsolationForest (default; calibrated to [0,1] in `model_server/main.py`)
- One-Class SVM
- Local Outlier Factor (novelty mode)
- (Future) Autoencoder via ONNX-exported PyTorch model

## Intended use
SOC tier-1 triage: route anomalous time windows to a high-priority Kafka
topic that feeds a SIEM rule chain or analyst queue.

## Out-of-scope
- Per-packet inspection (this works on aggregates only)
- Slow exfil that stays under window-level thresholds
- Adversarial evasion attacks shaping traffic to mimic baseline

## Latency budget
- Heuristic scorer: ~hundreds of nanoseconds in-process
- HTTP scorer: ~1-3 ms with model server on the same host
- ONNX in-process: ~50-200 μs (when wired in)

## Drift policy
PSI is computed online per feature against a baseline reservoir; PSI ≥ 0.2
emits a `drift_events` Prometheus counter and a `drift_psi` field on the
output JSON. Retraining trigger (operator playbook): when ≥3 features sit
above PSI 0.2 for >1h, run the training pipeline against the last 7 days
of feature store data.
