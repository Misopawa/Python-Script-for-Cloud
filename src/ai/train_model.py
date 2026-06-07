"""Train univariate Isolation Forest models with augmented normal-density data."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Sequence, Tuple

SRC_DIR = Path(__file__).resolve().parents[1]
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from ai.features import (
    FEATURE_ORDER,
    MAX_ALLOWED_DELTA,
    METRIC_MODEL_FILES,
    METRIC_SCALER_FILES,
    extract_network_delta_series,
    extract_training_frame,
    normalize_feature_order,
)

CONTAMINATION = 0.01
RANDOM_STATE = 42
N_ESTIMATORS = 100

# Data augmentation — increases "normal" density so 0–70% operating range is learned
BASELINE_DUPLICATION_FACTOR = 10
SYNTHETIC_SAMPLES_PER_METRIC = 8000
SYNTHETIC_PERCENT_MAX = 70.0  # target upper bound (% scale for CPU/MEM/STG; NET uses dataset units)
SYNTHETIC_DENSE_BAND_MIN_PCT = 35.0  # extra density from 35% upward


def _default_paths() -> tuple[Path, Path]:
    ai_dir = Path(__file__).resolve().parent
    src_dir = ai_dir.parent
    return ai_dir / "data" / "westermo.csv", src_dir


def _artifact_paths(src_dir: Path, metric: str) -> tuple[Path, Path]:
    return (
        src_dir / METRIC_MODEL_FILES[metric],
        src_dir / METRIC_SCALER_FILES[metric],
    )


def _synthetic_upper_bound(metric: str, real_values: np.ndarray) -> float:
    """Compute the upper bound for synthetic padding in the metric's native units."""
    real_values = real_values.astype(np.float64)
    if metric == "NETWORK":
        # Network model trains on normalized delta (0–100), not raw throughput.
        return min(SYNTHETIC_PERCENT_MAX, MAX_ALLOWED_DELTA)
    return SYNTHETIC_PERCENT_MAX


def _prepare_training_column(
    training_data: pd.DataFrame,
    metric: str,
) -> tuple[np.ndarray, Dict[str, float]]:
    """Return the 1-D values used to train a metric (delta series for NETWORK)."""
    if metric != "NETWORK":
        column = training_data[metric].to_numpy(dtype=np.float64)
        return column, {}

    delta_series, scale_factor = extract_network_delta_series(training_data["NETWORK"])
    stats = {
        "delta_scale": scale_factor,
        "max_allowed_delta": MAX_ALLOWED_DELTA,
        "mode": "rate_of_change",
    }
    return delta_series.to_numpy(dtype=np.float64), stats


def _generate_synthetic_padding(metric: str, real_values: np.ndarray) -> np.ndarray:
    """Generate synthetic 'normal' samples from 0% up to the 70% operating bound."""
    rng = np.random.default_rng(RANDOM_STATE + hash(metric) % 10_000)
    upper = _synthetic_upper_bound(metric, real_values)
    lower = 0.0
    dense_lower = upper * (SYNTHETIC_DENSE_BAND_MIN_PCT / SYNTHETIC_PERCENT_MAX)

    half = SYNTHETIC_SAMPLES_PER_METRIC // 2
    quarter = SYNTHETIC_SAMPLES_PER_METRIC // 4

    # Broad 0–70% coverage
    grid = np.linspace(lower, upper, half)
    uniform = rng.uniform(lower, upper, size=half)

    # Extra density in the 35–70% band where live workloads often sit
    dense_band = rng.uniform(dense_lower, upper, size=quarter)
    dense_grid = np.linspace(dense_lower, upper, quarter)

    synthetic = np.concatenate([grid, uniform, dense_band, dense_grid])

    noise_scale = max((upper - lower) * 0.01, 1e-6)
    synthetic = np.clip(synthetic + rng.normal(0.0, noise_scale, size=synthetic.size), lower, upper)
    return synthetic.astype(np.float64)


def augment_metric_column(
    real_values: np.ndarray,
    metric: str,
    *,
    duplication_factor: int = BASELINE_DUPLICATION_FACTOR,
) -> np.ndarray:
    """
    Build an augmented 1-D training column:
      1. Duplicate real Westermo baseline rows
      2. Append synthetic padding across the 0–70% normal operating range
    """
    real = np.asarray(real_values, dtype=np.float64).reshape(-1)
    duplicated = np.tile(real, max(1, int(duplication_factor)))
    synthetic = _generate_synthetic_padding(metric, real)
    combined = np.concatenate([duplicated, synthetic])

    rng = np.random.default_rng(RANDOM_STATE)
    rng.shuffle(combined)
    return combined.reshape(-1, 1)


def train_and_save_model(
    csv_path: str | Path | None = None,
    output_dir: str | Path | None = None,
    feature_order: Sequence[str] = FEATURE_ORDER,
    contamination: float = CONTAMINATION,
    duplication_factor: int = BASELINE_DUPLICATION_FACTOR,
    synthetic_samples: int = SYNTHETIC_SAMPLES_PER_METRIC,
) -> None:
    default_csv, default_src = _default_paths()
    csv_path = Path(csv_path or default_csv)
    src_dir = Path(output_dir or default_src)
    resolved_feature_order = normalize_feature_order(feature_order)

    global SYNTHETIC_SAMPLES_PER_METRIC
    SYNTHETIC_SAMPLES_PER_METRIC = int(synthetic_samples)

    print("Initializing univariate Isolation Forest training with data augmentation...")

    if not csv_path.exists():
        print(f"Error: Could not find dataset at {csv_path}")
        return

    df = pd.read_csv(csv_path)
    training_data = extract_training_frame(df, resolved_feature_order)

    print(f"Baseline rows: {len(training_data)}")
    print(f"Augmentation: {duplication_factor}x duplication + {synthetic_samples} synthetic points/metric")
    print(f"Synthetic normal band: 0–{SYNTHETIC_PERCENT_MAX}% (NETWORK uses normalized delta 0–{MAX_ALLOWED_DELTA})")
    print(f"Metrics ({len(resolved_feature_order)}): {', '.join(resolved_feature_order)}")
    print(f"Contamination: {contamination:.2%} per metric")

    src_dir.mkdir(parents=True, exist_ok=True)
    trained_metrics: Tuple[str, ...] = tuple()
    augmentation_stats: Dict[str, Dict[str, float]] = {}
    network_training_meta: Dict[str, float] = {}

    for metric in resolved_feature_order:
        real_column, metric_meta = _prepare_training_column(training_data, metric)
        if metric == "NETWORK":
            network_training_meta = metric_meta
            print(
                f"  [NETWORK] training on rate-of-change delta "
                f"(scale p95={metric_meta.get('delta_scale', 0):.2f} -> normalized 0–{MAX_ALLOWED_DELTA})"
            )

        augmented_column = augment_metric_column(
            real_column,
            metric,
            duplication_factor=duplication_factor,
        )

        augmentation_stats[metric] = {
            "real_rows": float(len(real_column)),
            "augmented_rows": float(len(augmented_column)),
            "synthetic_upper_bound": _synthetic_upper_bound(metric, real_column),
        }

        scaler = RobustScaler()
        scaled = scaler.fit_transform(augmented_column)

        model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=contamination,
            random_state=RANDOM_STATE,
        )
        model.fit(scaled)

        model_path, scaler_path = _artifact_paths(src_dir, metric)
        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)
        trained_metrics += (metric,)

        stats = augmentation_stats[metric]
        print(
            f"  [{metric}] augmented {int(stats['real_rows'])} -> {int(stats['augmented_rows'])} rows "
            f"(synthetic upper={stats['synthetic_upper_bound']:.2f}) "
            f"-> {model_path.name}, {scaler_path.name}"
        )

    metadata = {
        "mode": "univariate_augmented",
        "feature_order": resolved_feature_order,
        "model_files": {name: METRIC_MODEL_FILES[name] for name in resolved_feature_order},
        "scaler_files": {name: METRIC_SCALER_FILES[name] for name in resolved_feature_order},
        "augmentation": {
            "duplication_factor": duplication_factor,
            "synthetic_samples_per_metric": synthetic_samples,
            "synthetic_percent_max": SYNTHETIC_PERCENT_MAX,
            "stats": augmentation_stats,
        },
        "network": network_training_meta,
    }
    metadata_path = src_dir / "model_features.pkl"
    joblib.dump(metadata, metadata_path)

    print(f"Feature metadata saved to {metadata_path}")
    print(f"Training complete for metrics: {', '.join(trained_metrics)}")


if __name__ == "__main__":
    train_and_save_model()
