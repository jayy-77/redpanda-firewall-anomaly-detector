"""FastAPI model server consumed by the Go processor's HTTPScorer.

Loads a joblib artifact at startup and exposes:
  POST /score   { "features": { ... } } -> { "score": float }
  GET  /healthz
  GET  /metrics (Prometheus)

The feature order in the inbound JSON must match what the Go side emits,
which is exactly the seven window aggregates from extractFeatures().
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel
from starlette.responses import Response

log = logging.getLogger("model_server")
logging.basicConfig(level=logging.INFO)

MODEL_PATH = os.environ.get("MODEL_PATH", "/models/firewall_anomaly.joblib")
FEATURE_ORDER = [
    "mean_value",
    "std_dev",
    "max_value",
    "min_value",
    "percent_change",
    "unique_ips",
    "peak_to_mean_ratio",
]

app = FastAPI(title="firewall-anomaly model server", version="0.1.0")

_score_count = Counter("model_server_scored_total", "Records scored")
_score_latency = Histogram("model_server_score_latency_seconds", "Score latency")
_load_failed = Counter("model_server_load_errors_total", "Model load failures")

_model = None
_scaler = None


class ScoreRequest(BaseModel):
    features: Dict[str, float]


class ScoreResponse(BaseModel):
    score: float


def _load_model() -> None:
    global _model, _scaler
    path = Path(MODEL_PATH)
    if not path.exists():
        log.warning("model file %s not found, scorer returns 0.0 until present", path)
        return
    try:
        bundle = joblib.load(path)
        _model = bundle["model"]
        _scaler = bundle.get("scaler")
        log.info("loaded %s (model=%s)", path, type(_model).__name__)
    except Exception:
        _load_failed.inc()
        log.exception("failed to load model")


@app.on_event("startup")
def _startup() -> None:
    _load_model()


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "model_loaded": _model is not None}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _to_vector(feats: Dict[str, float]) -> np.ndarray:
    return np.asarray([[feats.get(k, 0.0) for k in FEATURE_ORDER]], dtype=float)


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    if _model is None:
        # Don't 503: returning a calibrated 0.0 keeps the streaming
        # pipeline alive even while the model is being warm-loaded.
        return ScoreResponse(score=0.0)
    x = _to_vector(req.features)
    if _scaler is not None:
        x = _scaler.transform(x)
    with _score_latency.time():
        # sklearn IsolationForest: decision_function — higher is more normal.
        if hasattr(_model, "decision_function"):
            raw = -_model.decision_function(x)[0]
            s = float(np.clip((raw + 0.5) / 1.0, 0.0, 1.0))
        elif hasattr(_model, "score_samples"):
            raw = -_model.score_samples(x)[0]
            s = float(np.clip((raw + 0.5) / 1.0, 0.0, 1.0))
        else:
            raise HTTPException(500, "model has no decision_function/score_samples")
    _score_count.inc()
    return ScoreResponse(score=s)
