import time
import datetime

from data.collector import DataCollector
from logic.detector import ThresholdEngine
from healing.auto_healer import PolicyEngine


def main():
    config = {
        "monitoring": {
            "demo_mode": True,
            "service_name": "nginx"
        },
        "proxmox": {
            "vmid": 100,
            "node": "pve"
        },
        "policies": {
            "docker_containers": []
        }
    }

    collector = DataCollector()
    engine = ThresholdEngine()
    healer = PolicyEngine(config=config)

    print("🚀 AI-Powered Monitoring Started.")

    try:
        while True:
            timestamp = datetime.datetime.now().isoformat()

            state = collector.get_live_state()

            engine.record_data_point(state)
            engine.update_thresholds()

            culprit = engine.evaluate_state(state)

            action_message = None
            if culprit is not None:
                anomaly_data = {
                    "anomaly": True,
                    "culprits": [culprit],
                    "score": 0.85,
                    "features": state
                }

                action_message = healer.execute_remediation(anomaly_data)

                if action_message:
                    action_message = str(action_message).upper()

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
