import joblib
import os
import numpy as np
from typing import Dict, Optional


class ThresholdEngine:
    def __init__(self, model_path="isolation_forest.pkl"):
        self.active_thresholds = {"CPU": 0.0, "MEMORY": 0.0, "STORAGE": 0.0, "NETWORK": 0.0}

        if os.path.exists(model_path):
            print("🧠 Isolation Forest Model Loaded Successfully.")
            self.model = joblib.load(model_path)
        else:
            print(f"⚠️ CRITICAL: {model_path} not found! Run train_model.py first.")
            self.model = None

    def record_data_point(self, current_metrics: Optional[Dict[str, float]]) -> None:
        pass

    def update_thresholds(self) -> None:
        pass

    def evaluate_state(self, current_metrics: Optional[Dict[str, float]]) -> Optional[str]:
        if not self.model or not isinstance(current_metrics, dict):
            return None

        cpu = float(current_metrics.get("CPU", 0.0))
        mem = float(current_metrics.get("MEMORY", 0.0))
        stg = float(current_metrics.get("STORAGE", 0.0))
        net = float(current_metrics.get("NETWORK", 0.0))

        features = np.array([[cpu, mem, stg, net]])

        prediction = self.model.predict(features)[0]

        if prediction == -1:
            culprit = max(current_metrics, key=current_metrics.get)
            return culprit

        return None
