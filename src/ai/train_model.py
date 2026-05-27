import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
import os

def train_and_save_model(csv_path="data/westermo.csv"):
    print("🧠 Initializing Isolation Forest Training...")
    
    if not os.path.exists(csv_path):
        print(f"❌ Error: Could not find dataset at {csv_path}")
        return

    df = pd.read_csv(csv_path)
    
    training_data = pd.DataFrame()
    training_data['CPU'] = df['cpu_usage'] 
    training_data['MEMORY'] = df['memory_usage']
    training_data['STORAGE'] = df['storage_usage']
    training_data['NETWORK'] = df['network_usage']
    
    training_data = training_data.fillna(0)

    print(f"📊 Training on {len(training_data)} rows of historical data...")
    model = IsolationForest(
        n_estimators=100, 
        contamination=0.15, 
        random_state=42
    )
    model.fit(training_data)
    
    joblib.dump(model, 'isolation_forest.pkl')
    print("✅ Model successfully trained and saved as 'isolation_forest.pkl'")

if __name__ == "__main__":
    train_and_save_model()
