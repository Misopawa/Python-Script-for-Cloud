from collections import deque
import math
import time

from utils.logger import get_logger

logger = get_logger(__name__)


class AnomalyDetector:
    def __init__(self, config):
        self.config = config or {}

        self.recent_maxlen = 100
        self.study_maxlen = 200
        self.study_min_points = 20
        self.safe_start_min_points = 10
        self.floor_threshold = 70.0
        self.ceiling_threshold = 95.0
        self.study_padding = 2.0
        self.recalibration_period_seconds = 172800
        self.next_calibration_ts = float(time.time() + float(self.recalibration_period_seconds))

        self.cpu_recent = deque(maxlen=self.recent_maxlen)
        self.mem_recent = deque(maxlen=self.recent_maxlen)
        self.stg_recent = deque(maxlen=self.recent_maxlen)
        self.net_recent = deque(maxlen=self.recent_maxlen)

        self.cpu_study = deque(maxlen=self.study_maxlen)
        self.mem_study = deque(maxlen=self.study_maxlen)
        self.stg_study = deque(maxlen=self.study_maxlen)
        self.net_study = deque(maxlen=self.study_maxlen)

    def detect_anomaly(self, metrics):
        if metrics is None:
            return {"anomaly": False, "score": 0.0, "skip": True, "culprits": [], "heads": {}}

        now_ts = float(time.time())
        if now_ts >= float(self.next_calibration_ts):
            self.cpu_recent.clear()
            self.mem_recent.clear()
            self.stg_recent.clear()
            self.net_recent.clear()
            self.cpu_study.clear()
            self.mem_study.clear()
            self.stg_study.clear()
            self.net_study.clear()
            self.next_calibration_ts = float(now_ts + float(self.recalibration_period_seconds))

        cpu = self._as_float(metrics.get("cpu_usage_pct", metrics.get("cpu_usage_ratio", 0.0) * 100.0))
        mem = self._as_float(metrics.get("mem_used_pct", metrics.get("mem_used_ratio", 0.0) * 100.0))
        stg = self._as_float(metrics.get("storage_used_pct", metrics.get("storage_used_ratio", 0.0) * 100.0))
        net = self._as_float(metrics.get("network_pct", metrics.get("network_ratio", 0.0) * 100.0))

        cpu_head = self._study_head("CPU", cpu, self.cpu_recent, self.cpu_study)
        mem_head = self._study_head("MEMORY", mem, self.mem_recent, self.mem_study)
        stg_head = self._study_head("STORAGE", stg, self.stg_recent, self.stg_study)
        net_head = self._study_head("NETWORK", net, self.net_recent, self.net_study)

        net_head["latency_ms"] = float(self._as_float(metrics.get("network_latency_ms", 0.0)))
        net_head["retrans_per_sec"] = float(self._as_float(metrics.get("network_retrans_per_sec", 0.0)))
        net_head["probe_success"] = float(self._as_float(metrics.get("probe_success", 1.0)))
        net_head["speed_mbps"] = float(self._as_float(metrics.get("network_speed_mbps", 0.0)))
        net_head["network_bytes_per_sec"] = float(self._as_float(metrics.get("network_bytes_per_sec", 0.0)))

        heads = {"CPU": cpu_head, "MEMORY": mem_head, "STORAGE": stg_head, "NETWORK": net_head}
        culprits = [name for name, info in heads.items() if bool(info.get("anomaly"))]

        init_mode = any(bool(info.get("init_mode", False)) for info in heads.values())

        max_over = 0.0
        chosen_threshold = float(self.floor_threshold)
        if culprits:
            for name in culprits:
                try:
                    chosen_threshold = max(chosen_threshold, float((heads.get(name) or {}).get("threshold", self.floor_threshold)))
                except Exception:
                    continue
        else:
            for info in heads.values():
                try:
                    chosen_threshold = max(chosen_threshold, float(info.get("threshold", self.floor_threshold)))
                except Exception:
                    continue
        for info in heads.values():
            over = float(info.get("value", 0.0) or 0.0) - float(info.get("threshold", 0.0) or 0.0)
            if over > max_over:
                max_over = over
        score = -float(max_over) if culprits else float(abs(max_over))

        if culprits:
            logger.warning("[DETECTION] Thermostat anomaly in %s (over=%.2f)", ",".join(culprits), float(max_over))
        else:
            logger.info("[DETECTION] Thermostat healthy")

        status = "Initializing..." if init_mode else "OK"
        next_in = max(0, int(float(self.next_calibration_ts) - float(now_ts)))
        return {
            "anomaly": bool(culprits),
            "score": float(score),
            "threshold": float(chosen_threshold),
            "status": str(status),
            "next_calibration_in": int(next_in),
            "features": metrics,
            "culprits": culprits,
            "heads": heads,
        }

    def _as_float(self, value, default: float = 0.0) -> float:
        try:
            return float(value)
        except Exception:
            return float(default)

    def _p95(self, values):
        if not values:
            return None
        data = sorted([float(v) for v in values])
        n = len(data)
        if n == 1:
            return float(data[0])
        k = int(math.ceil(0.95 * n)) - 1
        k = max(0, min(n - 1, k))
        return float(data[k])

    def _study_head(self, name: str, current: float, recent_window: deque, study_buffer: deque) -> dict:
        current = max(0.0, min(100.0, float(current)))
        recent_window.append(float(current))
        if float(current) > float(self.floor_threshold):
            study_buffer.append(float(current))

        baseline = float(sum(recent_window) / max(1, len(recent_window)))
        deviation = abs(float(current) - float(baseline))

        p95 = None
        study_active = False
        init_mode = bool(len(study_buffer) < int(self.safe_start_min_points))
        if not init_mode and len(study_buffer) >= int(self.study_min_points):
            try:
                p95 = self._p95(study_buffer)
                study_active = True
            except Exception:
                p95 = None
                study_active = False

        try:
            if p95 is None:
                threshold_active = float(self.floor_threshold)
            else:
                threshold_active = float(max(self.floor_threshold, float(p95) + float(self.study_padding)))
                threshold_active = float(min(self.ceiling_threshold, threshold_active))
        except Exception:
            threshold_active = float(self.floor_threshold)

        anomaly = bool(float(current) > float(threshold_active))
        in_study_zone = bool(float(current) > float(self.floor_threshold) and float(current) <= float(threshold_active))

        return {
            "value": float(current),
            "baseline": float(baseline),
            "deviation": float(deviation),
            "threshold": float(threshold_active),
            "anomaly": anomaly,
            "excess_ratio": float(max(0.0, float(current) - float(threshold_active)) / 100.0),
            "study_active": bool(study_active),
            "in_study_zone": bool(in_study_zone),
            "init_mode": bool(init_mode),
        }
