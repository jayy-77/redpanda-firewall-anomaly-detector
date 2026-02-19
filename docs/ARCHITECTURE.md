# Architecture

## End-to-end data flow

```
   ┌──────────────┐    ┌────────┐    ┌──────────────────────────┐
   │ firewall log │ ─► │ Redis  │ ─► │ Benthos pipeline          │
   │   sources    │    │  list  │    │ (firewall_anomaly_detector│
   └──────────────┘    └────────┘    │  processor + drift)       │
                                     └───────────┬──────────────┘
                                                 │
                          features (JSON)        │
                                                 ▼
                              ┌─────────────────────────┐
                              │ ml.Scorer interface     │
                              ├─────────┬──────┬────────┤
                              │heuristic│ HTTP │ ONNX    │
                              └─────────┴──────┴────────┘
                                          │
                                          ▼
                              ┌──────────────────────────┐
                              │ Python model_server      │
                              │ (FastAPI + IF/OCSVM/LOF) │
                              └──────────────────────────┘

                Result → Kafka topic (firewall-anomalies / firewall-normal)
                Metrics → Prometheus → Grafana dashboard
                Features ↘ optional → feature store (Redis)
```

## Components

### 1. Benthos / Redpanda Connect plugin
- `processor/firewall_anomaly_detector.go` — main processor, time-windowed aggregation
- `processor/ml/` — Scorer interface + heuristic / HTTP / ONNX implementations
- `processor/drift/` — streaming PSI drift detector with bounded reservoirs
- `processor/featurestore/` — Redis-backed feature store for offline-training symmetry

### 2. Python model server
- `model_server/main.py` — FastAPI service exposed at `/score`
- Loads joblib bundle `{model, scaler, feature_order}`
- Prometheus metrics on `/metrics`

### 3. Training pipeline
- `training/extract_features.py` — produces parquet of 7-feature windows
  identical to the Go side's schema (train-serve symmetry)
- `training/train.py` — IF / OCSVM / LOF
- `training/evaluate.py` — PR-AUC, ROC-AUC, precision@K

### 4. Observability stack
- Prometheus scrapes both the Go processor (port 4195) and the model server (8000)
- Grafana dashboard (`firewall.json`) shows logs/sec, anomalies/sec, drift events, p95 score latency

## Train-serve symmetry

The most subtle MLE concern here is making sure the features used to train
the model match the features extracted at inference. Two safeguards:

1. The Python `training/extract_features.py` reproduces the exact math in
   `processor/firewall_anomaly_detector.go::extractFeatures` — same
   FEATURE_ORDER list, same percent_change formula, same peak_to_mean ratio
   handling for zero-mean windows.
2. The model server's `/score` endpoint accepts a `Dict[str, float]` keyed
   by feature name (not positional), so a schema drift on either side
   gets a `0.0` rather than a silent column-shuffle bug.

## Scorer rollout pattern

The factory's `FallbackToHeur` flag enables a canary rollout:
- Deploy the HTTP scorer with fallback enabled.
- If the model server is unreachable at startup, the heuristic baseline
  keeps the pipeline alive.
- When the model is up and stable, flip `fallback_to_heuristic: false`.
