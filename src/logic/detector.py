"""Isolation Forest anomaly detector — single source of truth for is_anomaly."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple

import joblib
import numpy as np

FEATURE_ORDER: Tuple[str, ...] = ("CPU", "MEMORY", "STORAGE", "NETWORK")
DEFAULT_MIN_CONFIDENCE = 0.55


@dataclass(frozen=True)
class InferenceResult:
    """Output of a single Isolation Forest inference pass."""

    ai_prediction: int  # 1 = anomaly, 0 = normal (project convention)
    is_anomaly: bool
    confidence: float
    anomaly_score: float
    culprit: Optional[str]
    features: Dict[str, float]

    @property
    def should_remediate(self) -> bool:
        return self.is_anomaly and self.confidence >= DEFAULT_MIN_CONFIDENCE


class AnomalyDetector:
    """
    Production Isolation Forest detector.

    Flow: vectorize metrics -> predict -> map to is_anomaly -> score confidence.
    No static thresholds or baseline comparisons.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        feature_order: Sequence[str] = FEATURE_ORDER,
    ) -> None:
        self.min_confidence = float(min_confidence)
        self.feature_order = tuple(feature_order)
        self.model = self._load_model(model_path or self._default_model_path())

    @staticmethod
    def _default_model_path() -> str:
        # Resolve relative to the project's src/ directory so the model loads
        # regardless of the terminal's current working directory.
        src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(src_dir, "isolation_forest.pkl")

    @staticmethod
    def _load_model(model_path: str):
        if not os.path.exists(model_path):
            print(f"⚠️ CRITICAL: {model_path} not found! Run train_model.py first.")
            return None
        print("🧠 Isolation Forest Model Loaded Successfully.")
        return joblib.load(model_path)

    def _vectorize(self, metrics: Dict[str, float]) -> np.ndarray:
        values = [float(metrics.get(name, 0.0) or 0.0) for name in self.feature_order]
        return np.array([values], dtype=np.float64)

    @staticmethod
    def _sklearn_to_label(raw_prediction: int) -> int:
        """Map sklearn output (-1 anomaly, 1 normal) to project convention (1 anomaly, 0 normal)."""
        return 1 if int(raw_prediction) == -1 else 0

    def _compute_confidence(self, score: float, is_anomaly: bool) -> float:
        """
        Derive remediation confidence from the Isolation Forest score margin.

        Lower score_samples => more anomalous. Confidence scales with distance
        below the model's learned offset threshold.
        """
        if not is_anomaly or self.model is None:
            return 0.0

        offset = float(getattr(self.model, "offset_", 0.0))
        margin = offset - float(score)
        if margin <= 0.0:
            return 0.0

        scale = max(abs(offset), 1e-6)
        return float(min(1.0, margin / scale))

    @staticmethod
    def _identify_culprit(metrics: Dict[str, float]) -> Optional[str]:
        if not metrics:
            return None
        return max(metrics, key=lambda key: float(metrics.get(key, 0.0) or 0.0))

    def infer(self, metrics: Optional[Dict[str, float]]) -> Optional[InferenceResult]:
        """
        Run AI inference on a metrics snapshot.

        Returns None when the model is unavailable or metrics are invalid.
        """
        if self.model is None or not isinstance(metrics, dict):
            return None

        features = self._vectorize(metrics)
        raw_prediction = int(self.model.predict(features)[0])
        score = float(self.model.score_samples(features)[0])

        ai_prediction = self._sklearn_to_label(raw_prediction)
        is_anomaly = ai_prediction == 1
        confidence = self._compute_confidence(score, is_anomaly)
        culprit = self._identify_culprit(metrics) if is_anomaly else None

        return InferenceResult(
            ai_prediction=ai_prediction,
            is_anomaly=is_anomaly,
            confidence=confidence,
            anomaly_score=score,
            culprit=culprit,
            features=dict(metrics),
        )

    def should_remediate(self, result: Optional[InferenceResult]) -> bool:
        if result is None:
            return False
        return result.is_anomaly and result.confidence >= self.min_confidence
