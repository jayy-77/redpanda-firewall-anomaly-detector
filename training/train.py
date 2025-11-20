"""Train an anomaly detector on the offline-extracted feature windows.

Produces a joblib bundle of the form { "model": ..., "scaler": ... }
that the model_server can load directly.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from extract_features import FEATURE_ORDER

MODEL_FACTORIES = {
    "isolation_forest": lambda: IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1),
    "one_class_svm": lambda: OneClassSVM(nu=0.05, kernel="rbf", gamma="scale"),
    "lof": lambda: LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.05),
}


def _decision_to_score(model, X: np.ndarray) -> np.ndarray:
    raw = -model.decision_function(X)
    return (raw - raw.min()) / max(raw.max() - raw.min(), 1e-9)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", required=True, help="Parquet from extract_features.py")
    ap.add_argument("--model", choices=list(MODEL_FACTORIES), default="isolation_forest")
    ap.add_argument("--out", required=True, help="Output joblib bundle path")
    ap.add_argument("--metrics-out", default=None)
    args = ap.parse_args()

    df = pd.read_parquet(args.features)
    X = df[FEATURE_ORDER].to_numpy()
    y = df["anomaly_label"].to_numpy() if "anomaly_label" in df else np.zeros(len(df))

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_test_s = scaler.transform(X_test)

    model = MODEL_FACTORIES[args.model]()
    model.fit(X_train_s)

    metrics: dict[str, float] = {}
    if y.sum() > 0 and y.sum() < len(y):
        scores = _decision_to_score(model, X_test_s)
        metrics["pr_auc"] = float(average_precision_score(y_test, scores))
        metrics["roc_auc"] = float(roc_auc_score(y_test, scores))
        top_k = max(1, int(len(scores) * 0.05))
        top_idx = np.argsort(scores)[::-1][:top_k]
        metrics["precision_at_5pct"] = float(y_test[top_idx].mean())

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler, "feature_order": FEATURE_ORDER}, out_path)
    print(f"saved {out_path}")
    if args.metrics_out:
        Path(args.metrics_out).write_text(json.dumps(metrics, indent=2))
    print("metrics:", json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
