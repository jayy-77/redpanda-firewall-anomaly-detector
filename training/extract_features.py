"""Offline feature extraction.

Reads raw firewall logs (the JSON shape that the Go processor expects in
Redis) and produces the same 7-feature window aggregate the Go side
computes, so models trained here can score Go's streaming output without
distribution skew.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

FEATURE_ORDER = [
    "mean_value",
    "std_dev",
    "max_value",
    "min_value",
    "percent_change",
    "unique_ips",
    "peak_to_mean_ratio",
]


def _parse_ts(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1]
    return datetime.fromisoformat(s)


def _metric(log: dict, metric_field: str) -> float:
    if metric_field == "connection_count":
        return float(log.get("connection_count", 0))
    if metric_field == "bytes_sent":
        return float(log.get("bytes_sent", 0))
    if metric_field == "bytes_recv":
        return float(log.get("bytes_recv", 0))
    return 0.0


def extract_windows(
    logs_path: Path,
    metric_field_by_source: dict[str, str],
    window_seconds: int = 60,
) -> pd.DataFrame:
    """Group logs into per-source time windows and emit aggregate rows."""
    by_source: dict[str, list[dict]] = defaultdict(list)
    with logs_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            log = json.loads(line)
            src = log.get("log_source")
            if src in metric_field_by_source:
                by_source[src].append(log)

    rows: list[dict] = []
    for source, logs in by_source.items():
        metric_field = metric_field_by_source[source]
        logs.sort(key=lambda r: r["timestamp"])
        last_mean = 0.0
        window: list[dict] = []
        wstart: datetime | None = None
        for log in logs:
            ts = _parse_ts(log["timestamp"])
            if wstart is None:
                wstart = ts
            if (ts - wstart).total_seconds() >= window_seconds and window:
                rows.append(
                    _aggregate(source, metric_field, window, wstart, ts, last_mean)
                )
                last_mean = rows[-1]["mean_value"]
                window = []
                wstart = ts
            window.append(log)
        if window:
            rows.append(
                _aggregate(source, metric_field, window, wstart, ts, last_mean)
            )

    return pd.DataFrame(rows)


def _aggregate(source, metric_field, window, wstart, wend, last_mean):
    values = np.asarray([_metric(l, metric_field) for l in window], dtype=float)
    unique_ips = len({l.get("source_ip") for l in window if l.get("source_ip")})
    mean = float(values.mean())
    std = float(values.std(ddof=1)) if len(values) > 1 else 0.0
    mx = float(values.max())
    mn = float(values.min())
    pct = ((mean - last_mean) / last_mean * 100.0) if last_mean > 0 else 0.0
    ptm = (mx / mean) if mean > 0 else 0.0
    return {
        "log_source": source,
        "window_start": wstart.isoformat(),
        "window_end": wend.isoformat(),
        "mean_value": mean,
        "std_dev": std,
        "max_value": mx,
        "min_value": mn,
        "percent_change": pct,
        "unique_ips": float(unique_ips),
        "peak_to_mean_ratio": ptm,
        "anomaly_label": int(any(l.get("severity") == "high" for l in window)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True, help="JSON-lines firewall log dump")
    ap.add_argument("--out", required=True, help="Output Parquet path")
    ap.add_argument("--window", type=int, default=60)
    args = ap.parse_args()

    metric_map = {
        "fortinet.firewall": "connection_count",
        "paloalto.firewall": "bytes_sent",
        "checkpoint.firewall": "bytes_recv",
        "cisco.asa": "connection_count",
        "juniper.srx": "connection_count",
    }
    df = extract_windows(Path(args.logs), metric_map, args.window)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False)
    print(f"wrote {len(df)} windows to {args.out}")


if __name__ == "__main__":
    main()
