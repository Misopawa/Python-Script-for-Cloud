import pandas as pd
import os
import time
import csv
from utils.logger import setup_logger

_logger = setup_logger()

def save_metrics(metrics, file_path):
    if isinstance(metrics, dict):
        metrics = [metrics]
    df_new = pd.DataFrame(metrics)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    if os.path.isfile(file_path):
        df_new.to_csv(file_path, mode='a', header=False, index=False)
    else:
        df_new.to_csv(file_path, mode='w', header=True, index=False)

    try:
        df_existing = pd.read_csv(file_path)
        if len(df_existing) >= 1000:
            df_existing = df_existing.iloc[500:]
            df_existing.to_csv(file_path, mode='w', header=True, index=False)
    except Exception:
        pass

def save_metrics_to_csv(metrics, config=None):
    path = None
    if isinstance(config, dict):
        path = config.get("processed_data") or config.get("raw_data")
    if not path:
        path = os.path.join("data", "metrics.csv")
    save_metrics(metrics, path)
    _logger.info(f"Metrics written to {path}")

def load_dataset(file_path):
    return pd.read_csv(file_path)

def log_historical_score(score, file_path=None, retention_days=7, max_rows=60000):
    os.makedirs("data", exist_ok=True)
    if not file_path:
        file_path = os.path.join("data", "historical_scores.csv")

    now = time.time()
    cutoff = now - (retention_days * 24 * 60 * 60)

    file_exists = os.path.isfile(file_path)
    try:
        with open(file_path, "a", newline="") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "score"])
            writer.writerow([now, float(score or 0.0)])
    except Exception as e:
        _logger.error(f"Failed to write historical score: {e}")
        return

    try:
        with open(file_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            rows = []
            for row in reader:
                try:
                    ts = float(row.get("timestamp", 0) or 0)
                    if ts >= cutoff:
                        rows.append((ts, float(row.get("score", 0) or 0)))
                except Exception:
                    continue

        if len(rows) > max_rows:
            rows = rows[-max_rows:]

        with open(file_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "score"])
            for ts, sc in rows:
                writer.writerow([ts, sc])
    except Exception:
        return
