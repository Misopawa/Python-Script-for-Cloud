"""Single source of truth for AI training and inference feature alignment."""

from __future__ import annotations

from typing import Dict, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

UI_METRIC_NAMES: Tuple[str, ...] = ("CPU", "MEMORY", "STORAGE", "NETWORK")
FEATURE_ORDER: Tuple[str, ...] = ("CPU", "MEMORY", "STORAGE", "NETWORK")

TRAINING_COLUMN_MAP: Dict[str, str] = {
    "CPU": "cpu_usage",
    "MEMORY": "memory_usage",
    "STORAGE": "storage_usage",
    "NETWORK": "network_usage",
}

METRIC_MODEL_FILES: Dict[str, str] = {
    "CPU": "model_cpu.pkl",
    "MEMORY": "model_mem.pkl",
    "STORAGE": "model_stg.pkl",
    "NETWORK": "model_net.pkl",
}

METRIC_SCALER_FILES: Dict[str, str] = {
    "CPU": "scaler_cpu.pkl",
    "MEMORY": "scaler_mem.pkl",
    "STORAGE": "scaler_stg.pkl",
    "NETWORK": "scaler_net.pkl",
}

# Network rate-of-change: normalized delta magnitude capped to 0–100 for the model.
MAX_ALLOWED_DELTA = 100.0
NETWORK_DELTA_QUANTILE = 0.95


def normalize_feature_order(feature_order: Sequence[str]) -> Tuple[str, ...]:
    return tuple(feature_order)


def compute_network_delta_raw(current: float, previous: Optional[float]) -> float:
    """Absolute throughput change between two consecutive samples."""
    if previous is None:
        return 0.0
    return abs(float(current) - float(previous))


def normalize_network_delta(raw_delta: float, scale_factor: float) -> float:
    """
    Map a raw network delta into a consistent 0–100 input for IsolationForest.

    scale_factor is the training-set reference (e.g. p95 abs diff from Westermo).
    """
    raw_delta = max(0.0, float(raw_delta))
    if scale_factor <= 0.0:
        return float(min(raw_delta, MAX_ALLOWED_DELTA))
    normalized = (raw_delta / float(scale_factor)) * MAX_ALLOWED_DELTA
    return float(min(max(normalized, 0.0), MAX_ALLOWED_DELTA))


def extract_network_delta_series(
    network_values: pd.Series,
    scale_factor: Optional[float] = None,
) -> tuple[pd.Series, float]:
    """
    Build normalized network delta series from consecutive throughput samples.

    Returns (normalized_delta_series, scale_factor_used).
    """
    raw_delta = network_values.astype(float).diff().abs().fillna(0.0)
    if scale_factor is None:
        scale_factor = float(raw_delta.quantile(NETWORK_DELTA_QUANTILE)) or 1.0
    normalized = (raw_delta / float(scale_factor)) * MAX_ALLOWED_DELTA
    normalized = normalized.clip(lower=0.0, upper=MAX_ALLOWED_DELTA)
    return normalized, float(scale_factor)


def extract_training_frame(df: pd.DataFrame, feature_order: Sequence[str] = FEATURE_ORDER) -> pd.DataFrame:
    """Build the training matrix in the exact column order used by inference."""
    order = normalize_feature_order(feature_order)
    missing_columns = [
        TRAINING_COLUMN_MAP[name] for name in order if TRAINING_COLUMN_MAP[name] not in df.columns
    ]
    if missing_columns:
        raise ValueError(
            f"Training dataset is missing required columns: {missing_columns}. "
            f"Expected mapping: {TRAINING_COLUMN_MAP}"
        )

    training_data = pd.DataFrame(
        {name: df[TRAINING_COLUMN_MAP[name]] for name in order},
        columns=list(order),
    )
    return training_data.fillna(0.0)


def vectorize_metric(value: float) -> np.ndarray:
    """Build a (1, 1) row for univariate inference."""
    return np.array([[float(value or 0.0)]], dtype=np.float64)
