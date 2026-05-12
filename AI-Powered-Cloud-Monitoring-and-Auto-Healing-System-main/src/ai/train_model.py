import pandas as pd
import joblib
import os
from sklearn.ensemble import IsolationForest
from pathlib import Path
from utils.config_loader import load_config
from utils.logger import get_logger

logger = get_logger(__name__)

def preprocess_westermo(file_path):
    """
    Preprocess Westermo dataset to match the 12 required features exactly.
    Includes Unit Normalization Layer (converting memory from Bytes to GB).
    """
    df = pd.read_csv(file_path)
    
    # Required Features List (Normalized Names)
    # 1. load1_norm 2. load5_norm 3. load15_norm 
    # 4. mem_free_ratio 5. mem_available_ratio 6. mem_total_ratio 
    # 7. mem_cache_ratio 8. mem_buffered_ratio 
    # 9. swap_total_ratio 10. swap_free_ratio 
    # 11. fork_rate 12. intr_rate
    
    # Mapping from Westermo headers to normalized names
    mapping = {
        'load-1m': 'load1_norm',
        'load-5m': 'load5_norm',
        'load-15m': 'load15_norm',
        'sys-mem-free': 'mem_free_ratio',
        'sys-mem-available': 'mem_available_ratio',
        'sys-mem-total': 'mem_total_ratio',
        'sys-mem-cache': 'mem_cache_ratio',
        'sys-mem-buffered': 'mem_buffered_ratio',
        'sys-mem-swap-total': 'swap_total_ratio',
        'sys-mem-swap-free': 'swap_free_ratio',
        'sys-fork-rate': 'fork_rate',
        'sys-interrupt-rate': 'intr_rate'
    }
    
    # Return only the required features in exact order
    features_old = [
        'load-1m', 'load-5m', 'load-15m', 
        'sys-mem-free', 'sys-mem-available', 'sys-mem-total', 
        'sys-mem-cache', 'sys-mem-buffered', 
        'sys-mem-swap-total', 'sys-mem-swap-free', 
        'sys-fork-rate', 'sys-interrupt-rate'
    ]
    df = df[features_old]

    # Rename columns to match FEATURE_COLUMNS
    df = df.rename(columns=mapping)
    
    features_new = [
        'load1_norm', 'load5_norm', 'load15_norm', 
        'mem_free_ratio', 'mem_available_ratio', 'mem_total_ratio', 
        'mem_cache_ratio', 'mem_buffered_ratio', 
        'swap_total_ratio', 'swap_free_ratio', 
        'fork_rate', 'intr_rate'
    ]
    return df[features_new]

def train(config=None, additional_data=None):
    """
    Phase 1: Baseline training with Westermo dataset.
    Phase 2: Continuous training with rolling buffer data.
    Phase 3: Local Baseline Adaptation using data/metrics.csv if available.
    """
    if config is None:
        config = load_config("config/config.yaml")
        
    ai_cfg = config.get('ai', {})
    westermo_path = ai_cfg.get('westermo_path', 'data/westermo/system-1.csv')
    model_path = ai_cfg.get('model_path', 'models/isolation_forest.pkl')
    local_metrics_path = config.get('monitoring', {}).get('csv_path', 'data/metrics.csv')
    
    # Load baseline
    logger.info(f"[LEARNING] Loading baseline data from {westermo_path}")
    baseline_df = preprocess_westermo(westermo_path)
    
    # Local Baseline Adaptation: Load live data from metrics.csv if exists
    local_df = pd.DataFrame()
    if os.path.exists(local_metrics_path):
        try:
            logger.info(f"[LEARNING] Loading local baseline adaptation data from {local_metrics_path}")
            local_df = pd.read_csv(local_metrics_path)
            # Standardize column names for local data
            mapping = {
                'load1_norm': 'load1_norm',
                'load5_norm': 'load5_norm',
                'load15_norm': 'load15_norm',
                'mem_free_ratio': 'mem_free_ratio',
                'mem_available_ratio': 'mem_available_ratio',
                'mem_total_ratio': 'mem_total_ratio',
                'mem_cache_ratio': 'mem_cache_ratio',
                'mem_buffered_ratio': 'mem_buffered_ratio',
                'swap_total_ratio': 'swap_total_ratio',
                'swap_free_ratio': 'swap_free_ratio',
                'fork_rate': 'fork_rate',
                'intr_rate': 'intr_rate'
            }
            # Only keep the 12 features
            features = list(mapping.keys())
            local_df = local_df[features]
            logger.info(f"[LEARNING] Local adaptation data loaded: {len(local_df)} rows")
        except Exception as e:
            logger.warning(f"[LEARNING] Failed to load local metrics for adaptation: {e}")

    # Combine data: Baseline + Local + Additional (Buffer)
    train_df = baseline_df
    if not local_df.empty:
        train_df = pd.concat([train_df, local_df], ignore_index=True)
    
    if additional_data is not None and not additional_data.empty:
        logger.info("[LEARNING] Merging baseline data with online learning buffer")
        train_df = pd.concat([train_df, additional_data], ignore_index=True)
        
    # Train Isolation Forest
    # multivariate anomaly detection
    model = IsolationForest(
        n_estimators=100,
        contamination=0.15,
        random_state=42
    )
    
    features = [
        'load1_norm', 'load5_norm', 'load15_norm', 
        'mem_free_ratio', 'mem_available_ratio', 'mem_total_ratio', 
        'mem_cache_ratio', 'mem_buffered_ratio', 
        'swap_total_ratio', 'swap_free_ratio', 
        'fork_rate', 'intr_rate'
    ]
    model.fit(train_df[features])
    
    # Save model
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    logger.info(f"[LEARNING] Model saved to {model_path}")
    
    return model

if __name__ == "__main__":
    train()
