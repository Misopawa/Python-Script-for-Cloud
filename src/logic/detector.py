<<<<<<< HEAD
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
=======
import datetime
import csv
import os
from typing import Dict, Optional
import numpy as np


class ThresholdEngine:
    MIN_THRESH = 70.0
    MAX_THRESH = 95.0
    STUDY_DURATION_SECONDS = 0 

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
        
        # Load the Westermo dataset on startup to establish the baseline
        self.preload_mock_data()
>>>>>>> b0b94af748ce490793235c01c7c9842806199784

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

    def preload_mock_data(self, filepath: str = "data/westermo.csv") -> None:
        """Instantly feeds historical mock data into the AI baseline."""
        if not os.path.exists(filepath):
            print(f"⚠️ Mock dataset not found at {filepath}. Using live baseline.")
            return
            
        print(f"📊 Loading historical mock dataset from {filepath}...")
        try:
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Maps your CSV columns to your engine's memory
                    self.history["CPU"].append(float(row.get("cpu_usage", 0.0)))
                    self.history["MEMORY"].append(float(row.get("memory_usage", 0.0)))
                    self.history["STORAGE"].append(float(row.get("storage_usage", 0.0)))
                    self.history["NETWORK"].append(float(row.get("network_usage", 0.0)))
            print(f"✅ Successfully ingested historical data. Baseline established.")
            self.update_thresholds() # Calculate the baseline instantly
        except Exception as e:
            print(f"⚠️ Error loading mock data: {e}")
