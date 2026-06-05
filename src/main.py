import time
import datetime
import argparse
import sys

from data.collector import DataCollector
from logic.detector import ThresholdEngine
from healing.auto_healer import PolicyEngine
from ui.dashboard_tui import HealingDashboard
from rich.live import Live


def main_console():
    """Original console output mode (for backward compatibility)"""
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

    print("🚀 AI-Powered Monitoring Started (CONSOLE MODE).")

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


def main_tui():
    """TUI (Terminal User Interface) mode with rich dashboard"""
    config = {
        "monitoring": {
            "demo_mode": True,
            "service_name": "nginx"
        },
        "proxmox": {
            "host": "127.0.0.1",
            "node": "pve",
            "vmid": 101,
            "user": "root@pam",
            "password": "",
            "verify_ssl": False
        },
        "policies": {
            "docker_containers": []
        }
    }

    collector = DataCollector()
    engine = ThresholdEngine()
    healer = PolicyEngine(config=config)
    dashboard = HealingDashboard(config, collector=collector)

    print("🚀 AI-Powered Monitoring Started (TUI MODE).")
    print("Press Ctrl+C to exit...")
    time.sleep(2)

    try:
        cycle_count = 0
        last_action_time = time.time()
        
        with Live(dashboard.generate_layout(), console=dashboard.console, refresh_per_second=2, screen=True) as live:
            while True:
                cycle_count += 1
                timestamp = datetime.datetime.now().isoformat()

                # Collect metrics
                state = collector.get_live_state()
                
                # Process through detection engine
                engine.record_data_point(state)
                engine.update_thresholds()

                # Check for anomalies
                culprit = engine.evaluate_state(state)
                action_message = None
                escalation_level = 0
                
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
                        escalation_level = 1
                        last_action_time = time.time()

                # Build decision heads for TUI display
                decision_heads = {
                    "CPU": {
                        "value": state.get("CPU", 0),
                        "baseline": 50,
                        "deviation": abs(state.get("CPU", 0) - 50),
                        "threshold": engine.active_thresholds.get("CPU", 70.0),
                        "anomaly": state.get("CPU", 0) > engine.active_thresholds.get("CPU", 70.0),
                    },
                    "MEMORY": {
                        "value": state.get("MEMORY", 0),
                        "baseline": 50,
                        "deviation": abs(state.get("MEMORY", 0) - 50),
                        "threshold": engine.active_thresholds.get("MEMORY", 70.0),
                        "anomaly": state.get("MEMORY", 0) > engine.active_thresholds.get("MEMORY", 70.0),
                    },
                    "STORAGE": {
                        "value": state.get("STORAGE", 0),
                        "baseline": 50,
                        "deviation": abs(state.get("STORAGE", 0) - 50),
                        "threshold": engine.active_thresholds.get("STORAGE", 70.0),
                        "anomaly": state.get("STORAGE", 0) > engine.active_thresholds.get("STORAGE", 70.0),
                    },
                    "NETWORK": {
                        "value": state.get("NETWORK", 0),
                        "baseline": 50,
                        "deviation": abs(state.get("NETWORK", 0) - 50),
                        "threshold": engine.active_thresholds.get("NETWORK", 70.0),
                        "anomaly": state.get("NETWORK", 0) > engine.active_thresholds.get("NETWORK", 70.0),
                        "latency_ms": 0.0,
                        "retrans_per_sec": 0.0,
                        "speed_mbps": 0.0,
                    }
                }

                # Update dashboard
                dashboard.update_view(
                    metrics=state,
                    anomaly_score=0.85 if culprit else 0.0,
                    threshold=engine.active_thresholds.get("CPU", 70.0),
                    escalation_level=escalation_level,
                    action_name=str(action_message or "MONITORING"),
                    stabilization_window=10,
                    last_action_timestamp=last_action_time,
                    is_connected=True,
                    cycle_count=cycle_count,
                    culprits=[culprit] if culprit else [],
                    decision_heads=decision_heads,
                    ui_messages=[f"[{timestamp}] {msg}" for msg in [
                        "Metrics collected",
                        f"CPU: {state.get('CPU', 0):.1f}%",
                        f"MEMORY: {state.get('MEMORY', 0):.1f}%",
                        f"STORAGE: {state.get('STORAGE', 0):.1f}%",
                        f"NETWORK: {state.get('NETWORK', 0):.1f}%",
                    ]]
                )

                live.update(dashboard.generate_layout())
                time.sleep(2)

    except KeyboardInterrupt:
        print("\n✓ Shutdown requested by user. Cleaning up...")
        dashboard.disable_key_listener()


def main():
    """Main entry point with argument parser"""
    parser = argparse.ArgumentParser(
        description="AI-Powered Cloud Monitoring & Auto-Healing System"
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Run with Terminal User Interface (TUI) dashboard"
    )
    parser.add_argument(
        "--console",
        action="store_true",
        default=True,
        help="Run with console output (default)"
    )

    args = parser.parse_args()

    # If --tui is explicitly set, use TUI mode
    if args.tui:
        main_tui()
    # Otherwise, use console mode (default)
    else:
        main_console()


if __name__ == "__main__":
    main()
