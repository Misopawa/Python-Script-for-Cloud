import time
import datetime

# Ensure these imports match your actual folder structure!
from data.collector import DataCollector
from logic.detector import ThresholdEngine
from logic.auto_healer import PolicyEngine  # Fix 1: Corrected import name

def main():
    # Fix 2: Provide the configuration dictionary auto_healer.py needs
    config = {
        "monitoring": {
            "demo_mode": True, 
            "service_name": "nginx" # Change to the service you are stress-testing
        },
        "proxmox": {
            "vmid": 100,            # Your Target Node CT 100
            "node": "pve"           # Default Proxmox node name
        },
        "policies": {
            "docker_containers": []
        }
    }

    collector = DataCollector()
    engine = ThresholdEngine()
    healer = PolicyEngine(config=config) # Instantiated with config

    print("🚀 AI-Powered Monitoring Started. 48-Hour Calibration Active.")

    try:
        while True:
            timestamp = datetime.datetime.now().isoformat()

            # SENSE
            state = collector.get_live_state()

            # LEARN
            engine.record_data_point(state)
            engine.update_thresholds()

            # THINK
            culprit = engine.evaluate_state(state)

            # ACT
            action_message = None
            if culprit is not None:
                current_value = float(state.get(culprit, 0.0) or 0.0)
                
                # Fix 3 & 4: Format the data exactly how auto_healer.py expects it
                anomaly_data = {
                    "anomaly": True,
                    "culprits": [culprit],
                    "score": 0.85, # Baseline score for forensic logging
                    "features": state
                }
                
                # Call the correct function name and receive the single return string
                action_message = healer.execute_remediation(anomaly_data)
                
                if action_message:
                    action_message = str(action_message).upper()

            # LOGGING
            threshold_info = ", ".join(
                f"{metric}={engine.active_thresholds.get(metric, 0.0):.1f}%"
                for metric in ["CPU", "MEMORY", "STORAGE", "NETWORK"]
            )
            metric_info = ", ".join(
                f"{metric}={float(state.get(metric, 0.0)):.1f}%"
                for metric in ["CPU", "MEMORY", "STORAGE", "NETWORK"]
            )

            print(f"[{timestamp}] METRICS: {metric_info} | THRESHOLDS: {threshold_info}")
            if action_message:
                print(f"[{timestamp}] ACTION: {action_message}")

            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\nShutdown requested by user. Cleaning up...")


if __name__ == "__main__":
    main()
