"""Offline evaluation: PR-AUC / ROC-AUC / precision@K of a trained bundle."""

from __future__ import annotations

import argparse
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from extract_features import FEATURE_ORDER


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", required=True)
    ap.add_argument("--bundle", required=True)
    args = ap.parse_args()

    bundle = joblib.load(args.bundle)
    df = pd.read_parquet(args.features)
    X = df[FEATURE_ORDER].to_numpy()
    y = df["anomaly_label"].to_numpy() if "anomaly_label" in df else np.zeros(len(df))

    X_s = bundle["scaler"].transform(X)
    raw = -bundle["model"].decision_function(X_s)
    scores = (raw - raw.min()) / max(raw.max() - raw.min(), 1e-9)

    out = {"n": int(len(y))}
    if y.sum() > 0 and y.sum() < len(y):
        out["pr_auc"] = float(average_precision_score(y, scores))
        out["roc_auc"] = float(roc_auc_score(y, scores))
        top_k = max(1, int(len(scores) * 0.05))
        top_idx = np.argsort(scores)[::-1][:top_k]
        out["precision_at_5pct"] = float(y[top_idx].mean())
        out["recall_at_5pct"] = float(y[top_idx].sum() / max(int(y.sum()), 1))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
