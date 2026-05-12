import os
import yaml
from pathlib import Path

def load_config(_path=None):
    base = Path(__file__).resolve().parents[2]
    cfg_path = base / "config" / "config.yaml"
    if not cfg_path.exists():
        return {}
    with cfg_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data
