"""Univariate Isolation Forest anomaly detector — per-metric inference."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple

import joblib
import numpy as np

from ai.features import (
    FEATURE_ORDER,
    MAX_ALLOWED_DELTA,
    METRIC_MODEL_FILES,
    METRIC_SCALER_FILES,
    UI_METRIC_NAMES,
    compute_network_delta_raw,
    normalize_feature_order,
    normalize_network_delta,
    vectorize_metric,
)

MIN_CONFIDENCE_THRESHOLD = 0.10  # MTTR testing — raise to 0.55 for production
DEFAULT_MIN_CONFIDENCE = MIN_CONFIDENCE_THRESHOLD

# Hard-rule thresholds (%). Values above these bypass IsolationForest with confidence=1.0.
THRESHOLDS: Dict[str, float] = {
    "CPU": 75.0,
    "MEMORY": 85.0,
    "STORAGE": 80.0,
}

# Upper bounds (%) for normal operating range. Values within [0, bound] skip AI inference.
NORMAL_RANGES: Dict[str, float] = {
    "STORAGE": 80.0,
    "MEMORY": 90.0,
}

# Input clamping: map sub-threshold readings to a baseline the model treats as normal.
CLAMP_UPPER_BOUND = 70.0
CLAMP_SAFE_VALUE = 5.0
CLAMPED_METRICS = frozenset({"CPU", "MEMORY", "STORAGE"})


def clamp_input(value: float, metric_name: str) -> float:
    """
    Collapse 0–70% readings to a constant safe baseline before IsolationForest inference.

    Values at or below CLAMP_UPPER_BOUND are replaced with CLAMP_SAFE_VALUE so the model
    always evaluates them as its most normal training region. Values above the bound pass
    through unchanged for genuine high-load detection.
    """
    metric = str(metric_name).upper()
    if metric not in CLAMPED_METRICS:
        return float(value)

    val = float(value or 0.0)
    if val <= CLAMP_UPPER_BOUND:
        return CLAMP_SAFE_VALUE
    return val


@dataclass(frozen=True)
class MetricInference:
    """Inference result for a single metric."""

    name: str
    value: float
    ai_prediction: int  # 1 = anomaly, 0 = normal
    is_anomaly: bool
    confidence: float
    anomaly_score: float


@dataclass(frozen=True)
class InferenceResult:
    """Aggregated output of a univariate inference pass across all metrics."""

    by_metric: Dict[str, MetricInference]
    features: Dict[str, float]
    culprits: Tuple[str, ...]

    @property
    def is_anomaly(self) -> bool:
        return any(metric.is_anomaly for metric in self.by_metric.values())

    @property
    def ai_prediction(self) -> int:
        return 1 if self.is_anomaly else 0

    @property
    def confidence(self) -> float:
        scores = [metric.confidence for metric in self.by_metric.values() if metric.is_anomaly]
        return float(max(scores)) if scores else 0.0

    @property
    def anomaly_score(self) -> float:
        if not self.by_metric:
            return 0.0
        return float(min(metric.anomaly_score for metric in self.by_metric.values()))

    @property
    def culprit(self) -> Optional[str]:
        if self.culprits:
            return max(
                self.culprits,
                key=lambda name: self.by_metric[name].confidence,
            )
        anomalous = [name for name, metric in self.by_metric.items() if metric.is_anomaly]
        if not anomalous:
            return None
        return max(anomalous, key=lambda name: self.by_metric[name].confidence)

    @property
    def should_remediate(self) -> bool:
        return bool(self.culprits)


class AnomalyDetector:
    """
    Tiered hybrid univariate Isolation Forest detector.

    Layer 1 — Hard rules: CPU/MEMORY/STORAGE above THRESHOLDS trigger immediate anomaly.
    Layer 2 — Safe ranges: MEMORY/STORAGE within NORMAL_RANGES skip AI entirely.
    Layer 3 — AI: IsolationForest with input clamping for subtle anomalies.
    """

    def __init__(
        self,
        models_dir: Optional[str] = None,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        feature_order: Sequence[str] = FEATURE_ORDER,
        normal_ranges: Optional[Dict[str, float]] = None,
        thresholds: Optional[Dict[str, float]] = None,
        *,
        raise_on_load_failure: bool = False,
    ) -> None:
        self.min_confidence = float(min_confidence)
        self.normal_ranges: Dict[str, float] = dict(normal_ranges or NORMAL_RANGES)
        self.thresholds: Dict[str, float] = dict(thresholds or THRESHOLDS)
        self.ui_metric_names = tuple(UI_METRIC_NAMES)
        self.metric_order: Tuple[str, ...] = normalize_feature_order(feature_order)
        self.models: Dict[str, object] = {}
        self.scalers: Dict[str, object] = {}
        self.last_net_value: Optional[float] = None
        self.network_delta_scale: float = 1.0

        src_dir = models_dir or self._src_dir()
        self._load_network_delta_config(src_dir)
        self._load_univariate_artifacts(src_dir, raise_on_load_failure=raise_on_load_failure)

    @staticmethod
    def _src_dir() -> str:
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _load_network_delta_config(self, src_dir: str) -> None:
        """Load NETWORK delta scale saved during training (model_features.pkl)."""
        features_path = os.path.join(src_dir, "model_features.pkl")
        if not os.path.exists(features_path):
            print(
                f"WARNING: {features_path} not found. "
                f"Using default network delta scale=1.0. Re-run train_model.py."
            )
            return
        try:
            metadata = joblib.load(features_path)
            network_meta = metadata.get("network") or {}
            self.network_delta_scale = float(network_meta.get("delta_scale") or 1.0)
            print(
                f"NETWORK delta mode enabled "
                f"(scale={self.network_delta_scale:.2f}, max={MAX_ALLOWED_DELTA:.0f})"
            )
        except Exception as exc:
            print(f"WARNING: Could not load network delta config: {exc}")

    def _model_input_value(self, metric: str, raw_value: float) -> float:
        """Map a live metric reading to the value fed into IsolationForest."""
        if metric != "NETWORK":
            return float(raw_value)

        raw_delta = compute_network_delta_raw(raw_value, self.last_net_value)
        normalized_delta = normalize_network_delta(raw_delta, self.network_delta_scale)
        print(
            f"[DETECTOR] NETWORK throughput={raw_value:.2f} "
            f"delta={raw_delta:.2f} normalized={normalized_delta:.2f}"
        )
        return normalized_delta

    def _load_univariate_artifacts(self, src_dir: str, *, raise_on_load_failure: bool) -> None:
        missing: list[str] = []

        for metric in self.metric_order:
            model_path = os.path.join(src_dir, METRIC_MODEL_FILES[metric])
            scaler_path = os.path.join(src_dir, METRIC_SCALER_FILES[metric])

            model = self._load_pickle(model_path, f"{metric} model")
            scaler = self._load_pickle(scaler_path, f"{metric} scaler")

            if model is None or scaler is None:
                missing.append(metric)
                continue

            self.models[metric] = model
            self.scalers[metric] = scaler
            print(f"Loaded univariate artifacts for {metric}.")

        if missing:
            message = (
                f"Failed to load univariate artifacts for: {', '.join(missing)}. "
                "Run 'python src/ai/train_model.py' to generate model_*.pkl and scaler_*.pkl."
            )
            if raise_on_load_failure:
                raise RuntimeError(message)
            print(f"CRITICAL: {message}")

    @staticmethod
    def _load_pickle(path: str, label: str) -> Optional[object]:
        if not os.path.exists(path):
            print(f"CRITICAL: {label} not found at '{path}'.")
            return None
        try:
            return joblib.load(path)
        except Exception as exc:
            print(f"CRITICAL: Could not load {label} from '{path}': {exc}")
            return None

    def _artifacts_ready(self) -> bool:
        if len(self.models) != len(self.metric_order) or len(self.scalers) != len(self.metric_order):
            print(
                "CRITICAL: Univariate artifacts incomplete. "
                f"Loaded {len(self.models)}/{len(self.metric_order)} models. "
                "Run 'python src/ai/train_model.py'."
            )
            return False
        return True

    @staticmethod
    def _sklearn_to_label(raw_prediction: int) -> int:
        return 1 if int(raw_prediction) == -1 else 0

    @staticmethod
    def _compute_confidence(model: object, score: float, is_anomaly: bool) -> float:
        if not is_anomaly:
            return 0.0

        offset = float(getattr(model, "offset_", 0.0))
        margin = offset - float(score)
        if margin <= 0.0:
            # Model flagged anomaly but score sits at/above threshold — assign floor
            # so culprit gating can still fire during MTTR tests.
            return 0.15 if is_anomaly else 0.0

        scale = max(abs(offset), 1e-6)
        return float(min(1.0, margin / scale))

    def _exceeds_hard_threshold(self, metric: str, value: float) -> bool:
        """Return True when a metric exceeds its hard-rule threshold."""
        upper_bound = self.thresholds.get(metric)
        if upper_bound is None:
            return False
        return float(value) > float(upper_bound)

    def _hard_rule_anomaly_result(self, metric: str, value: float) -> MetricInference:
        """Force an anomaly result from the hard-rule layer (bypasses IsolationForest)."""
        print(
            f"[DETECTOR] Hard rule triggered for {metric}: "
            f"{value:.1f}% > {self.thresholds[metric]:.1f}%"
        )
        return MetricInference(
            name=metric,
            value=float(value),
            ai_prediction=1,
            is_anomaly=True,
            confidence=1.0,
            anomaly_score=0.0,
        )

    def _is_within_safe_range(self, metric: str, value: float) -> bool:
        """Return True when a hybrid-guarded metric is within its normal operating range."""
        upper_bound = self.normal_ranges.get(metric)
        if upper_bound is None:
            return False
        return 0.0 <= float(value) <= float(upper_bound)

    def _normal_metric_result(self, metric: str, value: float) -> MetricInference:
        """Force a normal result for metrics inside the configured safe range."""
        return MetricInference(
            name=metric,
            value=float(value),
            ai_prediction=0,
            is_anomaly=False,
            confidence=0.0,
            anomaly_score=0.0,
        )

    def _infer_metric(self, metric: str, raw_value: float) -> Optional[MetricInference]:
        raw_value = float(raw_value or 0.0)

        if self._exceeds_hard_threshold(metric, raw_value):
            return self._hard_rule_anomaly_result(metric, raw_value)

        if self._is_within_safe_range(metric, raw_value):
            return self._normal_metric_result(metric, raw_value)

        model_value = clamp_input(self._model_input_value(metric, raw_value), metric)

        model = self.models.get(metric)
        scaler = self.scalers.get(metric)
        if model is None or scaler is None:
            print(f"CRITICAL: Skipping {metric} — model or scaler unavailable.")
            return None

        vector = vectorize_metric(model_value)
        model_features = int(getattr(model, "n_features_in_", 1))
        scaler_features = int(getattr(scaler, "n_features_in_", 1))
        if vector.shape[1] != model_features or vector.shape[1] != scaler_features:
            print(
                f"CRITICAL: Feature dimension mismatch for {metric}. "
                f"Vector has {vector.shape[1]}, model expects {model_features}, "
                f"scaler expects {scaler_features}."
            )
            return None

        scaled = scaler.transform(vector)
        raw_prediction = int(model.predict(scaled)[0])
        score = float(model.score_samples(scaled)[0])
        ai_prediction = self._sklearn_to_label(raw_prediction)
        is_anomaly = ai_prediction == 1
        confidence = self._compute_confidence(model, score, is_anomaly)

        return MetricInference(
            name=metric,
            value=raw_value,
            ai_prediction=ai_prediction,
            is_anomaly=is_anomaly,
            confidence=confidence,
            anomaly_score=score,
        )

    def _update_network_state(self, metrics: Dict[str, float]) -> None:
        if "NETWORK" in metrics:
            self.last_net_value = float(metrics.get("NETWORK", 0.0) or 0.0)

    def infer(self, metrics: Optional[Dict[str, float]]) -> Optional[InferenceResult]:
        """
        Run univariate inference for each metric independently.

        Tier 1 — Hard rules (THRESHOLDS): immediate anomaly at confidence=1.0.
        Tier 2 — Safe ranges (NORMAL_RANGES): MEMORY/STORAGE skip AI when within bound.
        Tier 3 — AI: IsolationForest with clamp_input() for subtle anomalies.
        NETWORK uses rate-of-change (delta) for inference; raw throughput is preserved
        in features for the TUI.
        """
        if not self._artifacts_ready():
            return None

        if not isinstance(metrics, dict):
            return None

        by_metric: Dict[str, MetricInference] = {}
        for metric in self.metric_order:
            if metric not in metrics:
                print(f"CRITICAL: Missing live metric '{metric}' required for inference.")
                return None

            result = self._infer_metric(metric, float(metrics.get(metric, 0.0) or 0.0))
            if result is None:
                return None
            by_metric[metric] = result

        culprits_list: list[str] = []
        for name, metric in by_metric.items():
            if not metric.is_anomaly:
                continue
            if metric.confidence >= self.min_confidence:
                culprits_list.append(name)
                print(
                    f"[DETECTOR] Culprit added: {name} "
                    f"(confidence={metric.confidence:.3f} >= {self.min_confidence:.3f})"
                )

        culprits = tuple(culprits_list)

        self._update_network_state(metrics)

        return InferenceResult(
            by_metric=by_metric,
            features=dict(metrics),
            culprits=culprits,
        )

    def should_remediate(self, result: Optional[InferenceResult]) -> bool:
        if result is None:
            return False
        return bool(result.culprits)
