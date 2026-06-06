"""Monitoring pipeline: Data Acquisition -> AI Inference -> Remediation Trigger."""

import argparse
import datetime
import time

from data.collector import DataCollector
from healing.auto_healer import PolicyEngine
from logic.detector import AnomalyDetector, InferenceResult
from rich.live import Live
from ui.dashboard_tui import HealingDashboard


DEFAULT_CONFIG = {
    "monitoring": {
        "demo_mode": True,
        "service_name": "nginx",
    },
    "proxmox": {
        "host": "127.0.0.1",
        "node": "pve",
        "vmid": 101,
        "user": "root@pam",
        "password": "",
        "verify_ssl": False,
    },
    "policies": {
        "docker_containers": [],
    },
}


def _build_anomaly_payload(result: InferenceResult) -> dict:
    return {
        "anomaly": True,
        "ai_prediction": result.ai_prediction,
        "culprits": [result.culprit] if result.culprit else [],
        "score": result.anomaly_score,
        "confidence": result.confidence,
        "features": result.features,
    }


def _build_decision_heads(result: InferenceResult | None) -> dict:
    """Shape metric rows for the TUI from a single AI inference result."""
    features = (result.features if result else {}) or {}
    is_anomaly = bool(result and result.is_anomaly)
    confidence = float(result.confidence if result else 0.0)
    ai_score = float(result.anomaly_score if result else 0.0)

    heads = {}
    for name in ("CPU", "MEMORY", "STORAGE", "NETWORK"):
        heads[name] = {
            "value": float(features.get(name, 0.0) or 0.0),
            "anomaly": is_anomaly,
            "confidence": confidence,
            "ai_score": ai_score,
            "ai_prediction": int(result.ai_prediction if result else 0),
        }
    return heads


def run_cycle(
    collector: DataCollector,
    detector: AnomalyDetector,
    healer: PolicyEngine,
) -> tuple[dict, InferenceResult | None, str | None]:
    """
    Execute one monitoring cycle.

    1. Data Acquisition — pull live metrics from Prometheus.
    2. AI Inference — Isolation Forest classifies is_anomaly.
    3. Remediation Trigger — call execute_remediation() on confident anomalies.
    """
    metrics = collector.get_live_state()
    result = detector.infer(metrics)

    action_message = None
    if detector.should_remediate(result):
        action_message = healer.execute_remediation(_build_anomaly_payload(result))
        if action_message:
            action_message = str(action_message).upper()
    elif result is not None and not result.is_anomaly:
        # Heartbeat: a clean inference resets the healer's escalation state.
        healer.execute_remediation({"anomaly": False})

    return metrics, result, action_message


def main_console() -> None:
    collector = DataCollector()
    detector = AnomalyDetector()
    healer = PolicyEngine(config=dict(DEFAULT_CONFIG))

    print("🚀 AI-Powered Monitoring Started (CONSOLE MODE).")
    print(f"   Confidence gate: >= {detector.min_confidence:.0%}")

    try:
        while True:
            timestamp = datetime.datetime.now().isoformat()
            metrics, result, action_message = run_cycle(collector, detector, healer)

            metric_info = ", ".join(
                f"{name}={float(metrics.get(name, 0.0)):.1f}%"
                for name in ("CPU", "MEMORY", "STORAGE", "NETWORK")
            )

            if result is None:
                ai_status = "MODEL_UNAVAILABLE"
            elif result.is_anomaly:
                ai_status = (
                    f"ANOMALY (pred=1, confidence={result.confidence:.0%}, "
                    f"score={result.anomaly_score:.4f})"
                )
            else:
                ai_status = f"NORMAL (pred=0, score={result.anomaly_score:.4f})"

            print(f"[{timestamp}] METRICS: {metric_info} | AI: {ai_status}")
            if action_message:
                print(f"[{timestamp}] ACTION: {action_message}")

            time.sleep(5)
    except KeyboardInterrupt:
        print("\nShutdown requested by user. Cleaning up...")


def main_tui() -> None:
    config = dict(DEFAULT_CONFIG)
    collector = DataCollector()
    detector = AnomalyDetector()
    healer = PolicyEngine(config=config)
    dashboard = HealingDashboard(config, collector=collector)

    print("🚀 AI-Powered Monitoring Started (TUI MODE).")
    print("Press Ctrl+C to exit...")
    time.sleep(2)

    try:
        cycle_count = 0
        last_action_time = time.time()

        with Live(
            dashboard.generate_layout(),
            console=dashboard.console,
            refresh_per_second=2,
            screen=True,
        ) as live:
            while True:
                cycle_count += 1
                timestamp = datetime.datetime.now().isoformat()

                metrics, result, action_message = run_cycle(collector, detector, healer)

                escalation_level = 1 if action_message and action_message not in ("NONE", "STABILIZATION_SKIP") else 0
                if escalation_level:
                    last_action_time = time.time()

                decision_heads = _build_decision_heads(result)
                culprits = [result.culprit] if result and result.culprit else []

                dashboard.update_view(
                    metrics=metrics,
                    anomaly_score=float(result.confidence if result and result.is_anomaly else 0.0),
                    escalation_level=escalation_level,
                    action_name=str(action_message or "MONITORING"),
                    stabilization_window=10,
                    last_action_timestamp=last_action_time,
                    is_connected=True,
                    cycle_count=cycle_count,
                    culprits=culprits,
                    decision_heads=decision_heads,
                    raw_score=float(result.anomaly_score if result else 0.0),
                    ui_messages=[
                        f"[{timestamp}] Metrics collected",
                        f"[{timestamp}] AI prediction: {result.ai_prediction if result else 'N/A'}",
                        f"[{timestamp}] Confidence: {result.confidence:.0%}" if result else f"[{timestamp}] Confidence: N/A",
                    ],
                )

                live.update(dashboard.generate_layout())
                time.sleep(2)
    except KeyboardInterrupt:
        print("\n✓ Shutdown requested by user. Cleaning up...")
        dashboard.disable_key_listener()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-Powered Cloud Monitoring & Auto-Healing System",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Run with Terminal User Interface (TUI) dashboard",
    )
    parser.add_argument(
        "--console",
        action="store_true",
        default=True,
        help="Run with console output (default)",
    )

    args = parser.parse_args()

    if args.tui:
        main_tui()
    else:
        main_console()


if __name__ == "__main__":
    main()
