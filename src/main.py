import time
import datetime
import logging

from data.collector import DataCollector
from logic.detector import ThresholdEngine
from logic.healer import PolicyHealer


def main():
    collector = DataCollector()
    engine = ThresholdEngine()
    healer = PolicyHealer()

    logger = logging.getLogger(__name__)
    logger.info("🚀 AI-Powered Monitoring Started. 48-Hour Calibration Active.")

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
                level, action_message = healer.execute_policy(culprit, current_value)
                action_message = action_message.upper()

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
        print("Shutdown requested by user. Cleaning up...")


if __name__ == "__main__":
    main()
