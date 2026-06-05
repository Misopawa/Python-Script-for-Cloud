import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, confusion_matrix


def validate_ai_model() -> None:
    dataset_path = Path(__file__).resolve().parents[1] / "data" / "westermo" / "system-1.csv"
    df = pd.read_csv(dataset_path)

    features = [
        'load-1m', 'load-5m', 'load-15m',
        'sys-mem-swap-free', 'sys-mem-free', 'sys-mem-cache',
        'sys-fork-rate', 'sys-context-switch-rate',
        'disk-io-time', 'disk-bytes-read',
        'cpu-iowait', 'cpu-system', 'cpu-user'
    ]

    df['is_anomaly'] = np.where(df['server-up'] == 0, 1, 0)
    df = df.dropna(subset=features)
    X = df[features]

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    raw_predictions = model.fit_predict(X)

    df['AI_Prediction'] = np.where(raw_predictions == -1, 1, 0)

    y_true = df['is_anomaly'].astype(int)
    y_pred = df['AI_Prediction'].astype(int)

    accuracy = accuracy_score(y_true, y_pred)
    confusion = confusion_matrix(y_true, y_pred)

    print("\n" + "=" * 60)
    print("ANOMALY DETECTION VALIDATION")
    print("=" * 60)
    print(f"Dataset              : {dataset_path}")
    print(f"Total samples        : {len(df)}")
    print(f"True anomalies       : {int(y_true.sum())}")
    print(f"Predicted anomalies  : {int(y_pred.sum())}")
    print(f"Accuracy             : {accuracy * 100:.2f}%")
    print("\nConfusion Matrix [TN, FP] / [FN, TP]:")
    print(confusion)
    print("=" * 60)

    output_path = Path(__file__).resolve().parents[1] / 'validation_results_output.csv'
    df.to_csv(output_path, index=False)
    print(f"\nSaved validation output to: {output_path}")


if __name__ == "__main__":
    validate_ai_model()
