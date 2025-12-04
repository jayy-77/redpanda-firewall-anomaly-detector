# Training pipeline

Three-step offline workflow that ends with a joblib bundle the
`model_server` can serve to the streaming Go processor.

```bash
# 1. Generate sample logs and push to Redis
python3 ../scripts/generate_firewall_logs.py --count 50000 --redis-host localhost

# 2. Dump Redis to JSONL
redis-cli LRANGE firewall_logs 0 -1 | jq -c . > raw_logs.jsonl

# 3. Extract per-window features
python3 extract_features.py --logs raw_logs.jsonl --out features.parquet

# 4. Train a model
python3 train.py --features features.parquet --model isolation_forest --out models/firewall_anomaly.joblib

# 5. Evaluate
python3 evaluate.py --features features.parquet --bundle models/firewall_anomaly.joblib
```

The Go processor's `scorer.type=http` config will then POST the seven
window features to `model_server` at `/score`.
