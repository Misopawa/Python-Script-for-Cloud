import datetime
from typing import Dict, Optional

import numpy as np


class ThresholdEngine:
    MIN_THRESH = 70.0
    MAX_THRESH = 95.0
    STUDY_DURATION_SECONDS = 172800

    def __init__(self):
        self.study_duration = self.STUDY_DURATION_SECONDS
        self.start_time = datetime.datetime.now()
        self.history: Dict[str, list] = {
            "CPU": [],
            "MEMORY": [],
            "STORAGE": [],
            "NETWORK": [],
        }
        self.active_thresholds: Dict[str, float] = {
            "CPU": float(self.MIN_THRESH),
            "MEMORY": float(self.MIN_THRESH),
            "STORAGE": float(self.MIN_THRESH),
            "NETWORK": float(self.MIN_THRESH),
        }

    def record_data_point(self, current_metrics: Optional[Dict[str, float]]) -> None:
        if not isinstance(current_metrics, dict):
            return

        for metric in self.history:
            try:
                value = float(current_metrics.get(metric, 0.0))
            except Exception:
                continue
            self.history[metric].append(value)

    def update_thresholds(self) -> None:
        elapsed_seconds = (datetime.datetime.now() - self.start_time).total_seconds()
        if elapsed_seconds < self.study_duration:
            return

        for metric, values in self.history.items():
            if not values:
                continue

            try:
                p95 = float(np.percentile(np.array(values, dtype=np.float64), 95))
            except Exception:
                continue

            new_thresh = max(self.MIN_THRESH, min(self.MAX_THRESH, p95 + 2.0))
            self.active_thresholds[metric] = float(new_thresh)

    def evaluate_state(self, current_metrics: Optional[Dict[str, float]]) -> Optional[str]:
        if not isinstance(current_metrics, dict):
            return None

        for metric in ["CPU", "MEMORY", "STORAGE", "NETWORK"]:
            try:
                metric_value = float(current_metrics.get(metric, 0.0))
            except Exception:
                metric_value = 0.0

            threshold = float(self.active_thresholds.get(metric, self.MIN_THRESH))
            if metric_value > threshold:
                return metric

        return None
