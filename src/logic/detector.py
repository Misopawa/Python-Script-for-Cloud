import joblib
import os
import numpy as np
from typing import Dict, Optional


class ThresholdEngine:
    def __init__(self, model_path="isolation_forest.pkl"):
        self.active_thresholds = {"CPU": 75.0, "MEMORY": 75.0, "STORAGE": 75.0, "NETWORK": 75.0}

        if os.path.exists(model_path):
            print("🧠 Isolation Forest Model Loaded Successfully.")
            self.model = joblib.load(model_path)
        else:
            print(f"⚠️ CRITICAL: {model_path} not found! Run train_model.py first.")
            self.model = None

    def record_data_point(self, current_metrics: Optional[Dict[str, float]]) -> None:
        # No warm-up calibration needed: model makes decisions from Cycle 1.
        return None

    def update_thresholds(self) -> None:
        # Keep dashboard thresholds stable so the UI does not flash red.
        self.active_thresholds = {"CPU": 75.0, "MEMORY": 75.0, "STORAGE": 75.0, "NETWORK": 75.0}

    def evaluate_state(self, current_metrics: Optional[Dict[str, float]]) -> Optional[str]:
        if not self.model or not isinstance(current_metrics, dict):
            return None

        cpu = float(current_metrics.get("CPU", 0.0))
        mem = float(current_metrics.get("MEMORY", 0.0))
        stg = float(current_metrics.get("STORAGE", 0.0))
        net = float(current_metrics.get("NETWORK", 0.0))

        features = np.array([[cpu, mem, stg, net]], dtype=float)
        prediction = self.model.predict(features)[0]

        if prediction == -1:
            return max(current_metrics, key=current_metrics.get)

        return None
