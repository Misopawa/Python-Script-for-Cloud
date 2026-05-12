import pandas as pd
from pathlib import Path

RAW_DATA = Path("data/westermo/system-1.csv")
OUTPUT_DATA = Path("data/raw/mock_metrics.csv")

def preprocess_westermo():
    # Load Westermo dataset
    df = pd.read_csv(RAW_DATA)

    # Select relevant Westermo system metrics
    processed = df[[
        "load-1m",
        "load-5m",
        "load-15m",
        "sys-mem-available",
        "sys-fork-rate",
        "sys-interrupt-rate",
        "sys-context-switch-rate",
        "cpu-iowait",
        "cpu-system",
        "cpu-user",
        "server-up"
    ]]

    # Remove missing values
    processed = processed.dropna()

    OUTPUT_DATA.parent.mkdir(parents=True, exist_ok=True)
    processed.to_csv(OUTPUT_DATA, index=False)

    print("✅ Westermo dataset converted for AI training")

if __name__ == "__main__":
    preprocess_westermo()