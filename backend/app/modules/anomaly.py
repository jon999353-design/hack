"""Behavioural anomaly detection for vendor gateway traffic.

Uses scikit-learn's IsolationForest trained on seeded baseline traffic.
Features per request:
  [ records_requested, hour_of_day, is_weekend, endpoint_bucket, ip_class ]

This replaces the original single-threshold `if records > max` rule with a
real unsupervised-ML anomaly engine. Score < 0 means the model considers the
request anomalous; the magnitude is how far outside the learned manifold.

Runs on CPU, no GPU needed. Model is fit once at process start (~50 samples)
and thereafter `score(...)` is O(trees * log n) per call — sub-millisecond.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

_DATA = Path(__file__).parent.parent / "data" / "baseline_traffic.json"


def _load_baseline() -> np.ndarray:
    raw = json.loads(_DATA.read_text())
    return np.array(raw["samples"], dtype=float)


class BehaviouralModel:
    """Thin wrapper around IsolationForest with stable feature extraction."""

    def __init__(self) -> None:
        self._X = _load_baseline()
        self._model = IsolationForest(
            n_estimators=120,
            contamination=0.05,
            random_state=42,
        )
        self._model.fit(self._X)
        self._trained_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    @staticmethod
    def _endpoint_bucket(endpoint: str) -> int:
        e = endpoint.lower()
        if "admin" in e:
            return 2
        if any(t in e for t in ("create", "update", "delete", "export")):
            return 1
        return 0

    @staticmethod
    def _ip_class(ip: str) -> int:
        # Stable buckets used in the baseline: 0=corp, 1=vendor, 2=unknown.
        if ip.startswith(("10.", "192.168.", "172.16.")):
            return 0
        if ip.startswith("203.0.113."):
            return 1
        return 2

    def featurize(
        self,
        records_requested: int,
        endpoint: str,
        client_ip: str,
        when: datetime | None = None,
    ) -> np.ndarray:
        now = when or datetime.now(timezone.utc)
        vec = [
            float(records_requested),
            float(now.hour),
            1.0 if now.weekday() >= 5 else 0.0,
            float(self._endpoint_bucket(endpoint)),
            float(self._ip_class(client_ip)),
        ]
        return np.array([vec], dtype=float)

    def score(
        self,
        records_requested: int,
        endpoint: str,
        client_ip: str,
    ) -> tuple[float, bool]:
        """Return (anomaly_score, is_anomalous).

        Lower (more negative) score = more anomalous. `is_anomalous` uses the
        model's own `predict` which returns -1 for outliers.
        """
        X = self.featurize(records_requested, endpoint, client_ip)
        # `score_samples` is inverted from `decision_function` sign convention;
        # we use decision_function for "higher is more normal" semantics.
        s = float(self._model.decision_function(X)[0])
        is_anom = int(self._model.predict(X)[0]) == -1
        return s, is_anom

    def summary(self) -> dict:
        return {
            "model": "IsolationForest",
            "n_estimators": 120,
            "contamination": 0.05,
            "baseline_samples": int(self._X.shape[0]),
            "features": ["records_requested", "hour", "is_weekend", "endpoint_bucket", "ip_class"],
            "trained_at": self._trained_at,
        }


_MODEL: BehaviouralModel | None = None


def model() -> BehaviouralModel:
    global _MODEL
    if _MODEL is None:
        _MODEL = BehaviouralModel()
    return _MODEL
