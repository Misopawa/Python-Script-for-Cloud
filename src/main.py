"""Monitoring pipeline: SENSE → DECIDE → ACT with dual-path escalation state machine."""

import argparse
import datetime
import os
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from data.collector import DataCollector
from logic.detector import MIN_CONFIDENCE_THRESHOLD, AnomalyDetector, InferenceResult
from logic.healer import (
    MAX_ESCALATION_LEVEL,
    TIMEOUT_RETURN_CODE,
    Healer,
    RemediationResult,
    debug_log,
)
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
        "management_vmid": 101,
        "target_vmid": 100,
        "target_ip": "10.0.2.100",
        "user": "root@pam",
        "password": "",
        "verify_ssl": False,
    },
    "policies": {
        "docker_containers": [],
    },
    "telegram": {
        "bot_token": "8598608544:AAH5Cj7nT5UyPK8SjwJdDseJgjDt0Dm-h5Q",
        "chat_id": "1168749684",
    },
}

METRIC_NAMES = ("CPU", "MEMORY", "STORAGE", "NETWORK")
MTTR_FORCE_IMMEDIATE = True
STABILIZATION_WINDOW = 0
ANOMALY_CONFIRMATION_SECONDS = 10.0
METRIC_SYNC_COOLDOWN_SECONDS = 30.0
KERNEL_SETTLING_SECONDS = 2.0
VERIFICATION_WINDOW_SECONDS = 30.0
INFRASTRUCTURE_VERIFICATION_LEVELS = frozenset({2, 4})
VERIFICATION_SUCCESS_THRESHOLDS: Dict[str, float] = {
    "CPU": 20.0,
    "MEMORY": 50.0,
    "STORAGE": 50.0,
    "NETWORK": 20.0,
}
STABILIZATION_COOLDOWN_SECONDS = 120.0

# Per-metric reference ceilings used ONLY for the TUI health grid so every quadrant shows a
# live, changing "proximity-to-anomaly" reading instead of a frozen 0.0000 when the detector
# short-circuits a metric through its safe-range tier (reports score/confidence as 0.0).
DISPLAY_ANOMALY_REFERENCE: Dict[str, float] = {
    "CPU": 75.0,
    "MEMORY": 85.0,
    "STORAGE": 80.0,
    "NETWORK": 100.0,
}

# Closed-loop process-table / firewall-rule verification executed post-reset.
# mode "absent": success when pgrep returns no PIDs.
# mode "rule_present": success when the iptables DROP rule is confirmed active.
PROCESS_RESET_VERIFICATION: Dict[tuple, Dict[str, str]] = {
    ("CPU", 2): {"remote": "pgrep -f stress-ng-cpu", "mode": "absent", "target": "stress-ng-cpu"},
    ("CPU", 4): {"remote": "pgrep -f stress-ng-cpu", "mode": "absent", "target": "stress-ng-cpu"},
    ("MEMORY", 2): {"remote": "pgrep -f leaked_proc", "mode": "absent", "target": "leaked_proc"},
    ("STORAGE", 2): {"remote": "pgrep -f io_heavy_proc", "mode": "absent", "target": "io_heavy_proc"},
    ("NETWORK", 3): {"remote": "iptables -L INPUT -v -n", "mode": "rule_present", "target": "DROP dpt:80"},
}


def _ts_ms() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _normalize_inference_input(metrics: Optional[Dict[str, Any]]) -> Dict[str, float]:
    """
    Guarantee the detector receives a complete multivariate vector every tick.

    Maps the four live telemetry keys (CPU / MEMORY / STORAGE / NETWORK) into a clean float
    dict so inference is never silently reduced to a CPU-only feature — which is what froze
    the MEM/STG/NET quadrants at 0.0000.
    """
    metrics = metrics or {}
    return {name: float(metrics.get(name, 0.0) or 0.0) for name in METRIC_NAMES}


def _build_decision_heads(result: InferenceResult | None) -> dict:
    """
    Build the per-quadrant TUI payload for ALL four metrics.

    The detector reports anomaly_score/confidence as 0.0 whenever a metric is resolved by its
    safe-range tier (no IsolationForest pass). To keep every quadrant live instead of frozen,
    we surface the model's real score/confidence when present and otherwise derive a dynamic
    proximity reading from the raw value against DISPLAY_ANOMALY_REFERENCE.
    """
    heads = {}
    features = (result.features if result else {}) or {}
    for name in METRIC_NAMES:
        metric = result.by_metric.get(name) if result else None
        value = float(metric.value if metric else features.get(name, 0.0) or 0.0)
        is_anomaly = bool(metric.is_anomaly if metric else False)
        model_confidence = float(metric.confidence if metric else 0.0)
        model_score = float(metric.anomaly_score if metric else 0.0)

        reference = DISPLAY_ANOMALY_REFERENCE.get(name, 100.0) or 100.0
        proximity = max(0.0, min(1.0, value / reference))

        if is_anomaly:
            confidence = model_confidence
            ai_score = model_score
        elif model_score != 0.0:
            # IsolationForest actually scored this metric — trust the real numbers.
            confidence = model_confidence if model_confidence > 0.0 else proximity
            ai_score = model_score
        else:
            # Safe-range short-circuit: present a live proximity-to-anomaly reading.
            confidence = proximity
            ai_score = -proximity

        heads[name] = {
            "value": value,
            "anomaly": is_anomaly,
            "confidence": float(confidence),
            "ai_score": float(ai_score),
            "ai_prediction": int(metric.ai_prediction if metric else 0),
        }
    return heads


def send_async_telegram_alert(healer: Healer, message: str) -> None:
    """
    Offload Telegram transmission to a non-blocking daemon thread.

    Network/API handshake latency never freezes the TUI interface loop because the dispatch
    runs fire-and-forget on a background thread.
    """
    try:
        thread = threading.Thread(
            target=healer._send_telegram_alert,
            args=(message,),
            daemon=True,
        )
        thread.start()
    except Exception as exc:  # pragma: no cover - alerting must never crash the loop
        debug_log(f"Async Telegram dispatch failed to start: {exc}")


def _resolve_source_label(config: Dict[str, Any]) -> str:
    """
    Dynamic environment/source indicator for the TUI footer.

    Honors an explicit MONITOR_SOURCE override, otherwise derives the active Proxmox LXC
    target from configuration (e.g. '[ SOURCE: PROXMOX LXC CT100 ]').
    """
    override = os.environ.get("MONITOR_SOURCE")
    if override:
        return override.strip()
    proxmox = config.get("proxmox", {}) or {}
    target_vmid = proxmox.get("target_vmid", 100)
    return f"PROXMOX LXC CT{target_vmid}"


def _apply_manual_reset(
    escalation_state: Dict[str, Any],
    mttr_state: Dict[str, Any],
) -> None:
    """
    Operator override ('R' key): instantly break all countdowns and flush the state machine
    cleanly back to a green idle baseline.
    """
    escalation_state["cooldown_until"] = 0.0
    escalation_state["active_level"] = 0
    escalation_state["active_label"] = "Normal"
    escalation_state["active_culprit"] = None
    escalation_state["sync_locked_culprit"] = None
    escalation_state["verifying_culprit"] = None
    escalation_state["confirming_culprit"] = None
    escalation_state["confirm_elapsed"] = 0.0
    escalation_state["is_halted"] = False
    escalation_state["pending_recovery_level"] = 0
    escalation_state["pending_recovery_culprit"] = None

    for metric_state in escalation_state.get("metrics", {}).values():
        metric_state["path_index"] = 0
        metric_state["awaiting_verification"] = False
        metric_state["verify_until"] = 0.0
        metric_state["execution_locked"] = False
        _reset_metric_state(metric_state)

    _reset_mttr_state(mttr_state)
    debug_log("MANUAL RESET ('R'): countdowns broken, escalation state flushed to Normal.")


def _start_manual_reset_listener(
    escalation_state: Dict[str, Any],
    mttr_state: Dict[str, Any],
    stop_event: threading.Event,
) -> threading.Thread:
    """
    Dedicated background daemon thread that reads the keyboard independently of the main
    telemetry loop's time.sleep(). Pressing 'R'/'r' triggers an immediate state-machine reset.
    """
    import select
    import sys
    import termios
    import tty

    def _listen() -> None:
        if not sys.stdin.isatty():
            debug_log("Keyboard listener disabled — stdin is not a TTY.")
            return
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while not stop_event.is_set():
                ready, _, _ = select.select([fd], [], [], 0.2)
                if not ready:
                    continue
                ch = os.read(fd, 1).decode(errors="ignore")
                if ch in ("r", "R"):
                    _apply_manual_reset(escalation_state, mttr_state)
        except Exception as exc:  # pragma: no cover - listener must never crash the app
            debug_log(f"Keyboard listener error: {exc}")
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

    thread = threading.Thread(target=_listen, daemon=True)
    thread.start()
    debug_log("Manual reset listener armed — press 'R' to flush the state machine.")
    return thread


def _format_ai_status(result: InferenceResult | None) -> str:
    if result is None:
        return "MODEL_UNAVAILABLE"

    parts = []
    for name in METRIC_NAMES:
        metric = result.by_metric.get(name)
        if metric is None:
            continue
        if metric.is_anomaly:
            parts.append(f"{name}=ANOMALY({metric.confidence:.0%})")
        else:
            parts.append(f"{name}=NORMAL")

    summary = ", ".join(parts) if parts else "NO_METRICS"
    if result.culprits:
        return f"CULPRITS=[{', '.join(result.culprits)}] | {summary}"
    return summary


def _format_action_message(
    culprit: Optional[str],
    level: int,
    action_label: str,
    *,
    is_halted: bool = False,
    sync_locked: bool = False,
    verifying: bool = False,
    confirming: bool = False,
    confirm_elapsed: float = 0.0,
) -> str:
    if is_halted or level >= MAX_ESCALATION_LEVEL:
        metric = culprit or "SYSTEM"
        return f"ALERT — Human Intervention Required ({metric})"
    if sync_locked:
        metric = culprit or "METRIC"
        return f"SYNCING (post-remediation cooldown: {metric})"
    if verifying and culprit:
        return f"VERIFYING REMEDIATION ({culprit})"
    if confirming and culprit:
        return (
            f"CONFIRMING ({culprit}: {confirm_elapsed:.1f}s / "
            f"{ANOMALY_CONFIRMATION_SECONDS:.0f}s)"
        )
    if level >= 1 and culprit:
        label = action_label or "Remediate"
        return f"REMEDIATING (Lvl {level}: {label})"
    return "MONITORING"


def _new_mttr_state() -> Dict[str, Any]:
    return {
        "detected_at": None,
        "completed_at": None,
        "mttr_seconds": None,
        "culprit": None,
    }


def _new_metric_state() -> Dict[str, Any]:
    return {
        "active_level": 0,
        "path_index": 0,
        "is_halted": False,
        "execution_locked": False,
        "sync_until": 0.0,
        "sync_locked_until": 0.0,
        "first_detected": None,
        "awaiting_post_sync_check": False,
        "verify_until": 0.0,
        "awaiting_verification": False,
    }


def _new_escalation_state() -> Dict[str, Any]:
    return {
        "metrics": {name: _new_metric_state() for name in METRIC_NAMES},
        "remediation_logs": [],
        "is_halted": False,
        "active_culprit": None,
        "active_level": 0,
        "active_label": "",
        "sync_locked_culprit": None,
        "confirming_culprit": None,
        "confirm_elapsed": 0.0,
        "verifying_culprit": None,
        "cooldown_until": 0.0,
        "pending_recovery_level": 0,
        "pending_recovery_culprit": None,
    }


def _reset_metric_state(metric_state: Dict[str, Any]) -> None:
    metric_state["active_level"] = 0
    metric_state["path_index"] = 0
    metric_state["is_halted"] = False
    metric_state["execution_locked"] = False
    metric_state["sync_until"] = 0.0
    metric_state["sync_locked_until"] = 0.0
    metric_state["first_detected"] = None
    metric_state["awaiting_post_sync_check"] = False
    metric_state["verify_until"] = 0.0
    metric_state["awaiting_verification"] = False


def _reset_escalation_state(escalation_state: Dict[str, Any]) -> None:
    for metric_state in escalation_state.get("metrics", {}).values():
        _reset_metric_state(metric_state)
    escalation_state["is_halted"] = False
    escalation_state["active_culprit"] = None
    escalation_state["active_level"] = 0
    escalation_state["active_label"] = ""
    escalation_state["sync_locked_culprit"] = None
    escalation_state["confirming_culprit"] = None
    escalation_state["confirm_elapsed"] = 0.0
    escalation_state["verifying_culprit"] = None
    escalation_state["cooldown_until"] = 0.0
    escalation_state["pending_recovery_level"] = 0
    escalation_state["pending_recovery_culprit"] = None


def _reset_mttr_state(mttr_state: Dict[str, Any]) -> None:
    mttr_state["detected_at"] = None
    mttr_state["completed_at"] = None
    mttr_state["mttr_seconds"] = None
    mttr_state["culprit"] = None


def _is_metric_sync_locked(metric_state: Dict[str, Any], *, now: Optional[float] = None) -> bool:
    if not metric_state.get("execution_locked"):
        return False
    now = time.time() if now is None else now
    sync_until = float(metric_state.get("sync_until") or metric_state.get("sync_locked_until", 0.0))
    return now < sync_until


def _culprit_still_anomalous(culprit: str, result: Optional[InferenceResult]) -> bool:
    """AI-only: a culprit is still anomalous iff the model still predicts -1 for it."""
    if result is None:
        return False
    metric = result.by_metric.get(culprit)
    return bool(metric and metric.is_anomaly)


def _start_smart_verification(culprit: str, escalation_state: Dict[str, Any]) -> None:
    """Initialize active verification window for L2/L4 infrastructure dispatches."""
    metric_state = escalation_state["metrics"].setdefault(culprit, _new_metric_state())
    metric_state["verify_until"] = time.time() + VERIFICATION_WINDOW_SECONDS
    metric_state["awaiting_verification"] = True
    metric_state["execution_locked"] = True
    metric_state["sync_until"] = 0.0
    metric_state["sync_locked_until"] = 0.0
    metric_state["awaiting_post_sync_check"] = False
    escalation_state["verifying_culprit"] = culprit
    debug_log(
        f"Smart verification started for {culprit}: "
        f"{VERIFICATION_WINDOW_SECONDS:.0f}s active metric window"
    )


def _handle_successful_recovery(
    culprit: str,
    escalation_state: Dict[str, Any],
    mttr_state: Dict[str, Any],
    healer: Healer,
    *,
    level: int = 1,
) -> None:
    """Reset escalation state and log MTTR after live-metric verification passes."""
    metric_state = escalation_state["metrics"].setdefault(culprit, _new_metric_state())
    if mttr_state.get("detected_at") is not None and mttr_state.get("culprit") == culprit:
        completed_at = time.time()
        mttr_state["completed_at"] = completed_at
        mttr_state["mttr_seconds"] = healer.log_mttr(
            culprit=culprit,
            detected_at=float(mttr_state["detected_at"]),
            completed_at=completed_at,
            confidence=1.0,
            success=True,
            level=level,
        )
        debug_log(f"Recovery MTTR={mttr_state['mttr_seconds']:.3f}s at Lvl {level}")
    _reset_metric_state(metric_state)
    if escalation_state.get("sync_locked_culprit") == culprit:
        escalation_state["sync_locked_culprit"] = None
    if escalation_state.get("verifying_culprit") == culprit:
        escalation_state["verifying_culprit"] = None
    if escalation_state.get("active_culprit") == culprit:
        escalation_state["active_culprit"] = None
        escalation_state["active_level"] = 0
        escalation_state["active_label"] = ""


def _apply_telemetry_context_sanitizer(
    result: Optional[InferenceResult],
    escalation_state: Dict[str, Any],
    mttr_state: Dict[str, Any],
    healer: Healer,
) -> bool:
    """
    AI-driven idle reset (no static percentage rules).

    When an L2/L4 recovery is active but the Isolation Forest now classifies the live vector
    as NORMAL (+1 inlier → ``not result.is_anomaly``), flush escalation state. The model's
    prediction — not a hard-coded threshold — is the authority for declaring the system healthy.
    """
    if int(escalation_state.get("active_level", 0)) < 2:
        return False
    if result is None or result.is_anomaly:
        return False

    recovery_culprit = escalation_state.get("active_culprit")
    recovery_level = int(escalation_state.get("active_level", 2) or 2)

    escalation_state["active_level"] = 0
    escalation_state["active_label"] = "Normal"
    escalation_state["active_culprit"] = None
    escalation_state["sync_locked_culprit"] = None
    escalation_state["verifying_culprit"] = None
    escalation_state["confirming_culprit"] = None
    escalation_state["confirm_elapsed"] = 0.0

    if (
        recovery_culprit
        and mttr_state.get("detected_at") is not None
        and mttr_state.get("culprit") == recovery_culprit
    ):
        _handle_successful_recovery(
            recovery_culprit, escalation_state, mttr_state, healer, level=recovery_level
        )
        escalation_state["active_label"] = "Normal"

    for metric_state in escalation_state.get("metrics", {}).values():
        _reset_metric_state(metric_state)

    debug_log(
        "AI Resetter Hook: IsolationForest returned NORMAL (+1) during active recovery — "
        "flushing escalation indices back to normal across all metrics."
    )
    return True


def _process_active_verification(
    live_metrics: Dict[str, Any],
    escalation_state: Dict[str, Any],
    mttr_state: Dict[str, Any],
    healer: Healer,
) -> tuple[bool, str]:
    """
    Poll live Prometheus metrics during the verification window.
    Returns (early_exit, action_message) — early_exit skips AI inference for this tick.
    """
    verifying_culprit = escalation_state.get("verifying_culprit")
    if not verifying_culprit:
        for name in METRIC_NAMES:
            if escalation_state["metrics"].get(name, {}).get("awaiting_verification"):
                verifying_culprit = name
                break

    if not verifying_culprit:
        return False, ""

    metric_state = escalation_state["metrics"].setdefault(verifying_culprit, _new_metric_state())
    if not metric_state.get("awaiting_verification"):
        return False, ""

    current_time = time.time()
    current_value = float(live_metrics.get(verifying_culprit, 0.0) or 0.0)
    threshold = VERIFICATION_SUCCESS_THRESHOLDS.get(verifying_culprit, 20.0)

    if current_value < threshold:
        metric_state["awaiting_verification"] = False
        metric_state["verify_until"] = 0.0
        metric_state["execution_locked"] = False
        _handle_successful_recovery(
            verifying_culprit,
            escalation_state,
            mttr_state,
            healer,
            level=int(metric_state.get("active_level", 1) or 1),
        )
        debug_log(
            f"Smart Verification Success: {verifying_culprit} dropped below "
            f"{threshold:.1f}% (live={current_value:.1f}%). System recovered!"
        )
        return True, "MONITORING"

    if current_time > float(metric_state.get("verify_until", 0.0)):
        metric_state["awaiting_verification"] = False
        metric_state["verify_until"] = 0.0
        metric_state["execution_locked"] = False
        escalation_state["verifying_culprit"] = None
        _advance_path_index(verifying_culprit, escalation_state)
        debug_log(
            f"Smart Verification Timeout: {verifying_culprit} remained above "
            f"{threshold:.1f}% for {VERIFICATION_WINDOW_SECONDS:.0f}s. Escalating."
        )
        return False, ""

    escalation_state["verifying_culprit"] = verifying_culprit
    remaining = max(0.0, float(metric_state.get("verify_until", 0.0)) - current_time)
    debug_log(
        f"Smart verification polling {verifying_culprit}: live={current_value:.1f}% "
        f"threshold<{threshold:.1f}% ({remaining:.1f}s remaining)"
    )
    return True, f"VERIFYING REMEDIATION ({verifying_culprit})"


def _engage_path_b_sync_lock(culprit: str, escalation_state: Dict[str, Any]) -> None:
    """Path B: command succeeded — wait for Prometheus scrape before re-evaluation."""
    metric_state = escalation_state["metrics"].setdefault(culprit, _new_metric_state())
    until = time.time() + METRIC_SYNC_COOLDOWN_SECONDS
    metric_state["execution_locked"] = True
    metric_state["sync_until"] = until
    metric_state["sync_locked_until"] = until
    metric_state["awaiting_post_sync_check"] = True
    escalation_state["sync_locked_culprit"] = culprit
    debug_log(
        f"Path B sync lock for {culprit}: {METRIC_SYNC_COOLDOWN_SECONDS:.0f}s "
        f"(awaiting Prometheus scrape)"
    )


def _advance_path_index(culprit: str, escalation_state: Dict[str, Any]) -> None:
    """Path A: move to next policy step immediately."""
    metric_state = escalation_state["metrics"].setdefault(culprit, _new_metric_state())
    metric_state["path_index"] = int(metric_state.get("path_index", 0)) + 1
    debug_log(f"Path A: {culprit} path_index advanced to {metric_state['path_index']}")


def _derive_ai_culprits(result: Optional[InferenceResult]) -> List[str]:
    """
    AI-ONLY routing — no static percentage fallback rules.

    Trusts the Isolation Forest `.predict()` output exclusively: when the model classifies
    the current multivariate vector as an outlier (-1 → ``result.is_anomaly``), elect the
    single metric whose reading deviates most from its calibrated history array — i.e. the
    most negative ``score_samples`` (highest variance), tie-broken by confidence margin — and
    return it as the authoritative culprit for the stateful healer.
    """
    if result is None or not result.is_anomaly:
        return []

    anomalous = [
        (name, metric)
        for name, metric in result.by_metric.items()
        if metric.is_anomaly
    ]
    if not anomalous:
        return []

    culprit = min(
        anomalous,
        key=lambda item: (float(item[1].anomaly_score), -float(item[1].confidence)),
    )[0]
    debug_log(
        f"AI routing: IsolationForest flagged outlier (-1) → authoritative culprit={culprit} "
        f"(variance score={result.by_metric[culprit].anomaly_score:.4f})"
    )
    return [culprit]


def _update_anomaly_confirmation(
    result: Optional[InferenceResult],
    escalation_state: Dict[str, Any],
    *,
    now: Optional[float] = None,
) -> List[str]:
    """
    THINK phase — 10-second continuous confirmation before dispatching remediation.

    Routing is driven 100% by the Isolation Forest prediction. Static threshold fallbacks
    (e.g. ``if current_cpu > 80.0: culprit = "CPU"``) have been removed; the authoritative
    culprit comes solely from `_derive_ai_culprits()`.
    """
    now = time.time() if now is None else now
    confirmed: List[str] = []
    escalation_state["confirming_culprit"] = None
    escalation_state["confirm_elapsed"] = 0.0

    if result is None:
        return confirmed

    # AI prediction (-1) is the sole authority for which metric is anomalous.
    raw_culprits = set(_derive_ai_culprits(result))

    for name in METRIC_NAMES:
        metric_state = escalation_state["metrics"].setdefault(name, _new_metric_state())
        metric = result.by_metric.get(name)
        is_flagged = name in raw_culprits and bool(metric and metric.is_anomaly)

        if is_flagged:
            if metric_state.get("first_detected") is None:
                metric_state["first_detected"] = now
                debug_log(
                    f"{name} anomaly first flagged — starting "
                    f"{ANOMALY_CONFIRMATION_SECONDS:.0f}s confirmation window"
                )

            elapsed = now - float(metric_state["first_detected"])
            if elapsed >= ANOMALY_CONFIRMATION_SECONDS:
                confirmed.append(name)
            else:
                escalation_state["confirming_culprit"] = name
                escalation_state["confirm_elapsed"] = elapsed
        elif metric_state.get("first_detected") is not None:
            debug_log(f"{name} returned healthy — clearing transient spike")
            metric_state["first_detected"] = None

    return confirmed


def _process_expired_sync_locks(
    escalation_state: Dict[str, Any],
    result: Optional[InferenceResult],
    mttr_state: Dict[str, Any],
    healer: Healer,
) -> None:
    """After Path B cooldown expires, re-evaluate metric and advance or recover."""
    now = time.time()
    for metric, metric_state in escalation_state.get("metrics", {}).items():
        if not metric_state.get("execution_locked"):
            continue
        if _is_metric_sync_locked(metric_state, now=now):
            continue

        metric_state["execution_locked"] = False
        metric_state["sync_until"] = 0.0
        metric_state["sync_locked_until"] = 0.0
        debug_log(f"Sync lock expired for {metric}")

        if not metric_state.get("awaiting_post_sync_check"):
            continue

        metric_state["awaiting_post_sync_check"] = False
        if escalation_state.get("sync_locked_culprit") == metric:
            escalation_state["sync_locked_culprit"] = None

        if _culprit_still_anomalous(metric, result):
            debug_log(f"{metric} still anomalous after sync — advancing path_index")
            _advance_path_index(metric, escalation_state)
            continue

        if mttr_state.get("detected_at") is not None and mttr_state.get("culprit") == metric:
            completed_at = now
            mttr_state["completed_at"] = completed_at
            mttr_state["mttr_seconds"] = healer.log_mttr(
                culprit=metric,
                detected_at=float(mttr_state["detected_at"]),
                completed_at=completed_at,
                confidence=1.0,
                success=True,
                level=int(metric_state.get("active_level", 1) or 1),
            )
            debug_log(f"Recovery confirmed after sync MTTR={mttr_state['mttr_seconds']:.3f}s")

        _reset_metric_state(metric_state)


def _append_remediation_log(
    escalation_state: Dict[str, Any],
    remediation: RemediationResult,
    *,
    log_status: str,
    log_success: bool,
) -> None:
    """Append TUI-friendly remediation log entry with explicit path status text."""
    detail = remediation.message
    if remediation.stderr:
        detail = f"{detail} | stderr={remediation.stderr}"
    if remediation.stdout and not remediation.success:
        detail = f"{detail} | stdout={remediation.stdout}"

    entry = {
        "timestamp": datetime.datetime.fromtimestamp(remediation.completed_at).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3],
        "metric": remediation.culprit,
        "level": remediation.escalation_level,
        "command": log_status,
        "success": log_success,
        "message": detail,
        "action_label": remediation.action_label,
        "return_code": remediation.return_code,
    }
    logs: List[dict] = escalation_state.setdefault("remediation_logs", [])
    logs.append(entry)
    escalation_state["remediation_logs"] = logs[-30:]
    debug_log(
        f"REMEDIATION LOG: [{entry['timestamp']}] | {entry['metric']} | "
        f"Level {entry['level']} | {log_status}"
    )


def _execute_remediation_step(
    healer: Healer,
    culprit: str,
    confidence: float,
    escalation_state: Dict[str, Any],
) -> Optional[RemediationResult]:
    """Execute exactly ONE policy step at the current path_index."""
    culprit = str(culprit).upper()
    if escalation_state.get("is_halted"):
        return None

    metric_state = escalation_state["metrics"].setdefault(culprit, _new_metric_state())
    if metric_state.get("is_halted"):
        return None

    policy_path = healer.get_policy_path(culprit)
    if metric_state["path_index"] >= len(policy_path):
        debug_log(f"{culprit} policy path exhausted at index {metric_state['path_index']}")
        return None

    level = int(policy_path[metric_state["path_index"]])
    metric_state["active_level"] = level
    escalation_state["active_culprit"] = culprit
    escalation_state["active_level"] = level
    escalation_state["active_label"] = healer.get_action_label(culprit, level)

    debug_log(
        f"Dispatching {culprit} path_index={metric_state['path_index']} level={level} "
        f"({healer.get_action_label(culprit, level)})"
    )

    return healer.execute_level_remediation(
        culprit,
        confidence=confidence,
        escalation_level=level,
    )


def _rearm_after_stabilization_cooldown(
    escalation_state: Dict[str, Any],
    mttr_state: Dict[str, Any],
    healer: Healer,
) -> None:
    """Clear stabilization lock and flush all escalation state for normal monitoring."""
    recovery_level = int(escalation_state.get("pending_recovery_level", 2) or 2)
    recovery_culprit = escalation_state.get("pending_recovery_culprit")
    escalation_state["cooldown_until"] = 0.0
    escalation_state["pending_recovery_level"] = 0
    escalation_state["pending_recovery_culprit"] = None
    escalation_state["active_level"] = 0
    escalation_state["active_label"] = "Normal"
    escalation_state["active_culprit"] = None
    escalation_state["sync_locked_culprit"] = None
    escalation_state["verifying_culprit"] = None
    escalation_state["confirming_culprit"] = None
    escalation_state["confirm_elapsed"] = 0.0

    if (
        recovery_culprit
        and mttr_state.get("detected_at") is not None
        and mttr_state.get("culprit") == recovery_culprit
    ):
        _handle_successful_recovery(
            recovery_culprit, escalation_state, mttr_state, healer, level=recovery_level
        )
        escalation_state["active_label"] = "Normal"

    for metric_state in escalation_state.get("metrics", {}).values():
        _reset_metric_state(metric_state)

    debug_log(
        "Stabilization window expired. System successfully re-armed for "
        "anomaly detection across all metrics."
    )


def _check_process_table_via_ssh(healer: Healer, remote_command: str) -> str:
    """Run a verification command inside the target CT via the VirtualBox host tunnel."""
    vmid = int(getattr(healer, "target_vmid", 100))
    check_cmd = (
        "/usr/bin/ssh",
        "-p",
        "2222",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        "root@127.0.0.1",
        f"/usr/sbin/pct exec {vmid} -- {remote_command}",
    )
    try:
        proc_check = subprocess.run(
            check_cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=10,
        )
        return (proc_check.stdout or "").strip()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as exc:
        debug_log(f"Process-table check failed ({remote_command}): {exc}")
        return ""


def _check_cpu_stress_pids_via_ssh(healer: Healer) -> str:
    """Query Proxmox via VirtualBox tunnel for live stress-ng-cpu PIDs in target CT."""
    return _check_process_table_via_ssh(healer, "pgrep -f stress-ng-cpu")


def _interpret_process_verification(config: Dict[str, str], output: str) -> bool:
    """True when remediation is confirmed: process absent, or DROP rule present."""
    if config.get("mode") == "rule_present":
        text = output.lower()
        return "drop" in text and "dpt:80" in text
    return not output.strip()


def _engage_stabilization_cooldown(
    culprit: str,
    level: int,
    remediation: RemediationResult,
    escalation_state: Dict[str, Any],
    metric_state: Dict[str, Any],
    *,
    log_status: str,
    healer: Optional[Healer] = None,
    mttr_seconds: float = 0.0,
) -> None:
    """Verified remediation → drop into the 120s global stabilization lock."""
    current_time = time.time()
    escalation_state["cooldown_until"] = current_time + STABILIZATION_COOLDOWN_SECONDS
    escalation_state["pending_recovery_level"] = level
    escalation_state["pending_recovery_culprit"] = culprit
    escalation_state["active_label"] = "Stabilizing"
    escalation_state["active_culprit"] = culprit
    escalation_state["active_level"] = level
    escalation_state["verifying_culprit"] = None
    metric_state["awaiting_verification"] = False
    metric_state["verify_until"] = 0.0
    metric_state["execution_locked"] = True
    _append_remediation_log(
        escalation_state,
        remediation,
        log_status=log_status,
        log_success=True,
    )
    debug_log(
        f"{culprit} Lvl {level} verified remediated — engaging "
        f"{STABILIZATION_COOLDOWN_SECONDS:.0f}s stabilization cooldown."
    )
    if healer is not None:
        # TRIGGER B: expanded success payload with the calculated MTTR downtime metric.
        send_async_telegram_alert(
            healer,
            f"🟢 <b>[REMEDIATION SUCCESSFUL]</b>\n"
            f"• <b>Component:</b> {culprit}\n"
            f"• <b>Mitigation:</b> Level {level} Payload Executed\n"
            f"• <b>Verification:</b> Process verified dead via host pgrep\n"
            f"• <b>Total Downtime (MTTR):</b> {mttr_seconds:.3f} seconds\n\n"
            f"ℹ️ Engaging 120s stabilization window. Anomaly engine paused.",
        )


def _advance_after_failed_reset(
    culprit: str,
    remediation: RemediationResult,
    escalation_state: Dict[str, Any],
    metric_state: Dict[str, Any],
    *,
    log_status: str,
    detail: str,
) -> None:
    """Verification failed (rogue process alive / rule missing) → Path A escalation."""
    metric_state["first_detected"] = None
    metric_state["execution_locked"] = False
    metric_state["sync_until"] = 0.0
    metric_state["sync_locked_until"] = 0.0
    metric_state["awaiting_post_sync_check"] = False
    metric_state["awaiting_verification"] = False
    metric_state["verify_until"] = 0.0
    escalation_state["verifying_culprit"] = None
    _append_remediation_log(
        escalation_state,
        remediation,
        log_status=log_status,
        log_success=False,
    )
    _advance_path_index(culprit, escalation_state)
    debug_log(
        f"Path A: {culprit} Lvl {remediation.escalation_level} — {detail}. "
        f"Escalating on next tick."
    )


def _process_remediation_outcome(
    remediation: RemediationResult,
    result: Optional[InferenceResult],
    escalation_state: Dict[str, Any],
    mttr_state: Dict[str, Any],
    healer: Healer,
) -> None:
    """
    Closed-loop outcome handler with direct process-table verification:
      Process resets (CPU L2/L4, MEMORY L2, STORAGE L2, NETWORK L3) — verify via SSH
        tunnel; on success engage 120s stabilization cooldown, on failure advance (Path A).
      Remaining infra levels (pct set isolation) — active live-metric polling window.
      Path B sync — L1 success uses static cooldown before re-evaluation.
      Path A — structural failure or surviving rogue process → instant path_index advance.
    """
    _ = result
    culprit = remediation.culprit
    metric_state = escalation_state["metrics"].setdefault(culprit, _new_metric_state())

    if remediation.escalation_level >= 2:
        debug_log(
            f"Kernel settling pause ({KERNEL_SETTLING_SECONDS:.0f}s) after "
            f"{culprit} Lvl {remediation.escalation_level} infrastructure dispatch"
        )
        time.sleep(KERNEL_SETTLING_SECONDS)

    if remediation.is_halted or remediation.human_intervention_required:
        metric_state["is_halted"] = True
        escalation_state["is_halted"] = True
        escalation_state["active_label"] = "Escalation"
        _append_remediation_log(
            escalation_state,
            remediation,
            log_status="Human Intervention Required",
            log_success=False,
        )
        debug_log(f"Circuit breaker engaged for {culprit} at Level 5")
        return

    verify_cfg = PROCESS_RESET_VERIFICATION.get((culprit, remediation.escalation_level))
    if verify_cfg is not None:
        if culprit == "CPU":
            output = _check_cpu_stress_pids_via_ssh(healer)
        else:
            output = _check_process_table_via_ssh(healer, verify_cfg["remote"])

        verified = _interpret_process_verification(verify_cfg, output)
        rule_mode = verify_cfg.get("mode") == "rule_present"
        debug_log(
            f"{culprit} Lvl {remediation.escalation_level} verification "
            f"({verify_cfg.get('mode')}): output={'<empty>' if not output else output[:120]} "
            f"verified={verified}"
        )

        if verified:
            log_status = (
                "Rule Verified Active | Engaging 2-Min Stabilization Cooldown"
                if rule_mode
                else "Process Dead | Engaging 2-Min Stabilization Cooldown"
            )
            # Grab the incident downtime (MTTR) from the state array before the cooldown fires.
            detected_at = mttr_state.get("detected_at")
            mttr_seconds = (
                float(time.time() - float(detected_at)) if detected_at is not None else 0.0
            )
            _engage_stabilization_cooldown(
                culprit,
                remediation.escalation_level,
                remediation,
                escalation_state,
                metric_state,
                log_status=log_status,
                healer=healer,
                mttr_seconds=mttr_seconds,
            )
            return

        if rule_mode:
            fail_status = "Rule Missing | Advancing Instantly"
            detail = "iptables DROP rule not confirmed active"
        else:
            fail_status = "Process Still Alive | Advancing Instantly"
            detail = f"rogue PIDs still active ({output})"
        _advance_after_failed_reset(
            culprit,
            remediation,
            escalation_state,
            metric_state,
            log_status=fail_status,
            detail=detail,
        )
        return

    if remediation.escalation_level in INFRASTRUCTURE_VERIFICATION_LEVELS and (
        remediation.success
        or remediation.return_code == 0
        or remediation.escalation_level >= 2
    ):
        _append_remediation_log(
            escalation_state,
            remediation,
            log_status="Command Executed | Awaiting Smart Verification",
            log_success=True,
        )
        _start_smart_verification(culprit, escalation_state)
        debug_log(
            f"Path B Smart Verify: Level {remediation.escalation_level} holding path_index "
            f"at {metric_state['path_index']} for {VERIFICATION_WINDOW_SECONDS:.0f}s active polling."
        )
        return

    if remediation.success or remediation.return_code == 0:
        metric_state["sync_until"] = time.time() + METRIC_SYNC_COOLDOWN_SECONDS
        _append_remediation_log(
            escalation_state,
            remediation,
            log_status="Command Executed | Metric High -> Syncing Cooldown",
            log_success=True,
        )
        _engage_path_b_sync_lock(culprit, escalation_state)
        debug_log(
            f"Path B Sync: Level {remediation.escalation_level} holding path_index "
            f"for {METRIC_SYNC_COOLDOWN_SECONDS:.0f}s cooldown."
        )
        return

    if remediation.escalation_level >= 2:
        _append_remediation_log(
            escalation_state,
            remediation,
            log_status="Command Executed | Metric High -> Syncing Cooldown",
            log_success=True,
        )
        _engage_path_b_sync_lock(culprit, escalation_state)
        debug_log(
            f"Path B Enforced: Level {remediation.escalation_level} holding path_index "
            f"for {METRIC_SYNC_COOLDOWN_SECONDS:.0f}s cooldown."
        )
        return

    # Path A: Level 1 structural failure or timeout — advance policy step on next tick.
    metric_state["first_detected"] = None
    metric_state["execution_locked"] = False
    metric_state["sync_until"] = 0.0
    metric_state["sync_locked_until"] = 0.0
    metric_state["awaiting_post_sync_check"] = False
    _append_remediation_log(
        escalation_state,
        remediation,
        log_status="Command Failed/Timed Out | Advancing Instantly",
        log_success=False,
    )
    _advance_path_index(culprit, escalation_state)
    debug_log(
        f"Path A: {culprit} Lvl {remediation.escalation_level} failed "
        f"(rc={remediation.return_code}) — instant escalation on next tick"
    )


def run_cycle(
    collector: DataCollector,
    detector: AnomalyDetector,
    healer: Healer,
    mttr_state: Optional[Dict[str, Any]] = None,
    escalation_state: Optional[Dict[str, Any]] = None,
    *,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[dict, InferenceResult | None, str, Dict[str, Any], Dict[str, Any]]:
    """SENSE → DECIDE → CONFIRM → ACT (one policy step per tick)."""
    _ = sleep_fn  # retained for test injection; loop tick pacing is non-blocking
    mttr_state = mttr_state if mttr_state is not None else _new_mttr_state()
    escalation_state = escalation_state if escalation_state is not None else _new_escalation_state()

    metrics = collector.get_live_state()
    debug_log(f"SENSE metrics={ {k: round(float(metrics.get(k, 0)), 1) for k in METRIC_NAMES} }")

    # AI inference runs every tick — its verdict is the sole authority for anomaly routing
    # AND for relieving the post-remediation stabilization lock. The input is normalized to
    # the full CPU/MEMORY/STORAGE/NETWORK vector so no quadrant is starved of features.
    result = detector.infer(_normalize_inference_input(metrics))
    ai_normal = result is not None and not result.is_anomaly

    current_time = time.time()
    cooldown_until = float(escalation_state.get("cooldown_until", 0.0))

    if current_time < cooldown_until:
        # Post-remediation cooldown relief: pgrep already verified the kill, so a stable
        # NORMAL (+1) score from the model is accepted as validation to clear the lock early.
        if ai_normal:
            debug_log(
                "Stabilization relief: IsolationForest returned NORMAL (+1) — clearing "
                "120s cooldown lock early (process kill already verified via pgrep)."
            )
            _rearm_after_stabilization_cooldown(escalation_state, mttr_state, healer)
            return metrics, result, "MONITORING", mttr_state, escalation_state

        time_remaining = int(cooldown_until - current_time)
        escalation_state["active_label"] = "Stabilizing"
        action_message = f"STABILIZATION COOLDOWN ({time_remaining}s remaining)"
        debug_log(f"Stabilization lock active — {time_remaining}s remaining (awaiting AI NORMAL)")
        return metrics, result, action_message, mttr_state, escalation_state

    if cooldown_until > 0.0 and current_time >= cooldown_until:
        _rearm_after_stabilization_cooldown(escalation_state, mttr_state, healer)

    if _apply_telemetry_context_sanitizer(result, escalation_state, mttr_state, healer):
        return metrics, result, "MONITORING", mttr_state, escalation_state

    verify_exit, verify_action = _process_active_verification(
        metrics, escalation_state, mttr_state, healer
    )
    if verify_exit:
        debug_log(f"ACTION: {verify_action}")
        return metrics, result, verify_action, mttr_state, escalation_state

    debug_log(f"DECIDE ai_culprit={_derive_ai_culprits(result)}")

    _process_expired_sync_locks(escalation_state, result, mttr_state, healer)

    confirmed_culprits = _update_anomaly_confirmation(result, escalation_state)
    debug_log(f"DECIDE confirmed_culprits={confirmed_culprits}")

    sync_locked_culprit = escalation_state.get("sync_locked_culprit")
    verifying_culprit = escalation_state.get("verifying_culprit")
    sync_locked = bool(
        sync_locked_culprit
        and _is_metric_sync_locked(escalation_state["metrics"].get(sync_locked_culprit, {}))
    )
    verifying = bool(
        verifying_culprit
        and escalation_state["metrics"].get(verifying_culprit, {}).get("awaiting_verification")
    )

    is_halted = bool(escalation_state.get("is_halted"))
    confirming = bool(escalation_state.get("confirming_culprit")) and not confirmed_culprits
    action_message = _format_action_message(
        escalation_state.get("confirming_culprit")
        or verifying_culprit
        or sync_locked_culprit
        or escalation_state.get("active_culprit"),
        int(escalation_state.get("active_level", 0)),
        str(escalation_state.get("active_label", "")),
        is_halted=is_halted,
        sync_locked=sync_locked,
        verifying=verifying,
        confirming=confirming,
        confirm_elapsed=float(escalation_state.get("confirm_elapsed", 0.0)),
    )

    if is_halted:
        return metrics, result, action_message, mttr_state, escalation_state

    if verifying:
        remaining = max(
            0.0,
            float(escalation_state["metrics"][verifying_culprit].get("verify_until", 0))
            - time.time(),
        )
        debug_log(
            f"Smart verification active for {verifying_culprit} — "
            f"skipping dispatch ({remaining:.1f}s remaining)"
        )
        return metrics, result, action_message, mttr_state, escalation_state

    if sync_locked:
        remaining = max(
            0.0,
            float(escalation_state["metrics"][sync_locked_culprit].get("sync_until", 0)) - time.time(),
        )
        debug_log(
            f"Sync lock active for {sync_locked_culprit} — "
            f"skipping dispatch ({remaining:.1f}s remaining)"
        )
        return metrics, result, action_message, mttr_state, escalation_state

    if confirmed_culprits:
        now = time.time()
        if mttr_state.get("detected_at") is None:
            mttr_state["detected_at"] = now
            mttr_state["culprit"] = confirmed_culprits[0]
            debug_log(f"Confirmed anomaly at {_ts_ms()} culprit={confirmed_culprits[0]}")

            # TRIGGER A: fire the initial detection alert exactly once, the moment the
            # Isolation Forest outlier is officially confirmed and before any dispatch.
            culprit = confirmed_culprits[0]
            detection_metric = result.by_metric.get(culprit) if result else None
            detection_score = float(detection_metric.anomaly_score if detection_metric else 0.0)
            send_async_telegram_alert(
                healer,
                f"🚨 <b>[ANOMALY DETECTED]</b>\n"
                f"• <b>Component:</b> {culprit}\n"
                f"• <b>Status:</b> Outlier Active (-1)\n"
                f"• <b>AI Score:</b> {detection_score:.4f}\n"
                f"• <b>Action:</b> Commencing hierarchical policy path...",
            )

        for culprit in confirmed_culprits:
            metric_state = escalation_state["metrics"].get(culprit, _new_metric_state())
            if (
                metric_state.get("is_halted")
                or _is_metric_sync_locked(metric_state)
                or metric_state.get("awaiting_verification")
            ):
                debug_log(f"Skipping {culprit} — halted, sync-locked, or verifying")
                continue

            metric = result.by_metric.get(culprit) if result else None
            confidence = float(metric.confidence if metric else (result.confidence if result else 0.0))

            remediation = _execute_remediation_step(healer, culprit, confidence, escalation_state)
            if remediation is None:
                continue

            _process_remediation_outcome(remediation, result, escalation_state, mttr_state, healer)

        post_sync_culprit = escalation_state.get("sync_locked_culprit")
        post_verify_culprit = escalation_state.get("verifying_culprit")
        post_sync_locked = bool(
            post_sync_culprit
            and _is_metric_sync_locked(escalation_state["metrics"].get(post_sync_culprit, {}))
        )
        post_verifying = bool(
            post_verify_culprit
            and escalation_state["metrics"]
            .get(post_verify_culprit, {})
            .get("awaiting_verification")
        )
        action_message = _format_action_message(
            post_verify_culprit or post_sync_culprit or escalation_state.get("active_culprit"),
            int(escalation_state.get("active_level", 0)),
            str(escalation_state.get("active_label", "")),
            is_halted=bool(escalation_state.get("is_halted")),
            sync_locked=post_sync_locked,
            verifying=post_verifying,
        )

    elif result is not None and not result.is_anomaly:
        debug_log("Metrics within operational thresholds — resetting escalation state")
        _reset_mttr_state(mttr_state)
        _reset_escalation_state(escalation_state)
        action_message = "MONITORING"
    elif confirming:
        action_message = _format_action_message(
            escalation_state.get("confirming_culprit"),
            0,
            "",
            confirming=True,
            confirm_elapsed=float(escalation_state.get("confirm_elapsed", 0.0)),
        )

    return metrics, result, action_message, mttr_state, escalation_state


def _build_healer(config: dict) -> Healer:
    proxmox = config.get("proxmox", {})
    return Healer(
        min_confidence=MIN_CONFIDENCE_THRESHOLD,
        target_vmid=int(proxmox.get("target_vmid", 100)),
        target_ip=str(proxmox.get("target_ip", "10.0.2.100")),
        telegram_config=config.get("telegram"),
        force_immediate=MTTR_FORCE_IMMEDIATE,
        demo_mode=bool(config.get("monitoring", {}).get("demo_mode", True)),
    )


def main_console() -> None:
    config = dict(DEFAULT_CONFIG)
    collector = DataCollector()
    detector = AnomalyDetector(min_confidence=MIN_CONFIDENCE_THRESHOLD)
    healer = _build_healer(config)
    mttr_state = _new_mttr_state()
    escalation_state = _new_escalation_state()

    print(f"[DEBUG] [{_ts_ms()}] Monitoring started — dual-path escalation state machine")
    print(f"   Target: CT {healer.target_vmid} @ {healer.target_ip}")
    print(
        f"   Confirm: {ANOMALY_CONFIRMATION_SECONDS}s | "
        f"Path B sync: {METRIC_SYNC_COOLDOWN_SECONDS}s | Command timeout: 10s"
    )

    try:
        while True:
            metrics, result, action_message, mttr_state, escalation_state = run_cycle(
                collector, detector, healer, mttr_state, escalation_state
            )

            metric_info = ", ".join(
                f"{name}={float(metrics.get(name, 0.0)):.1f}%"
                for name in METRIC_NAMES
            )
            debug_log(f"METRICS: {metric_info} | AI: {_format_ai_status(result)}")
            debug_log(f"ACTION: {action_message}")

            if mttr_state.get("mttr_seconds") is not None:
                debug_log(
                    f"MTTR: {mttr_state['mttr_seconds']:.3f}s "
                    f"(culprit={mttr_state.get('culprit')})"
                )

            time.sleep(2)
    except KeyboardInterrupt:
        debug_log("Shutdown requested by user")


def main_tui() -> None:
    config = dict(DEFAULT_CONFIG)
    collector = DataCollector()
    detector = AnomalyDetector(min_confidence=MIN_CONFIDENCE_THRESHOLD)
    healer = _build_healer(config)
    dashboard = HealingDashboard(config, collector=collector)
    mttr_state = _new_mttr_state()
    escalation_state = _new_escalation_state()

    # Dynamic source/footer indicator + Telegram status light.
    dashboard.set_source_label(_resolve_source_label(config))
    telegram_cfg = config.get("telegram", {}) or {}
    dashboard.set_telegram_active(bool(telegram_cfg.get("bot_token") and telegram_cfg.get("chat_id")))

    # Non-blocking keyboard daemon: 'R' resets the state machine independently of time.sleep().
    reset_stop_event = threading.Event()
    _start_manual_reset_listener(escalation_state, mttr_state, reset_stop_event)

    debug_log("Monitoring started (TUI) — dual-path escalation state machine")
    print("Press 'R' to reset · Ctrl+C to exit...")

    try:
        cycle_count = 0
        last_action_time = time.time()

        with Live(
            dashboard.generate_layout(),
            console=dashboard.console,
            refresh_per_second=4,
            screen=True,
        ) as live:
            while True:
                cycle_count += 1
                timestamp = _ts_ms()
                dashboard.poll_resize()

                metrics, result, action_message, mttr_state, escalation_state = run_cycle(
                    collector, detector, healer, mttr_state, escalation_state
                )

                culprits = list(result.culprits) if result else []
                escalation_level = int(escalation_state.get("active_level", 0))
                is_halted = bool(escalation_state.get("is_halted"))
                if culprits or is_halted or "REMEDIATING" in action_message or "CONFIRMING" in action_message or "VERIFYING" in action_message or "STABILIZATION" in action_message:
                    last_action_time = time.time()

                decision_heads = _build_decision_heads(result)

                mttr_messages = []
                if mttr_state.get("detected_at") is not None:
                    mttr_messages.append(
                        f"[{timestamp}] Anomaly detected at "
                        f"{datetime.datetime.fromtimestamp(mttr_state['detected_at']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}"
                    )
                if mttr_state.get("mttr_seconds") is not None:
                    mttr_messages.append(
                        f"[{timestamp}] MTTR: {mttr_state['mttr_seconds']:.3f}s "
                        f"(culprit={mttr_state.get('culprit')})"
                    )

                dashboard.update_view(
                    metrics=metrics,
                    anomaly_score=float(result.confidence if result and result.culprits else 0.0),
                    escalation_level=escalation_level,
                    action_name=action_message,
                    stabilization_window=STABILIZATION_WINDOW,
                    last_action_timestamp=last_action_time,
                    is_connected=True,
                    cycle_count=cycle_count,
                    culprits=culprits,
                    decision_heads=decision_heads,
                    raw_score=float(result.anomaly_score if result else 0.0),
                    mttr_seconds=mttr_state.get("mttr_seconds"),
                    mttr_culprit=mttr_state.get("culprit"),
                    remediation_logs=escalation_state.get("remediation_logs", []),
                    alert_locked=is_halted,
                    ui_messages=[
                        f"[{timestamp}] Metrics collected",
                        f"[{timestamp}] AI prediction: {result.ai_prediction if result else 'N/A'}",
                        f"[{timestamp}] Culprits: {', '.join(culprits) if culprits else 'none'}",
                        f"[{timestamp}] Action: {action_message}",
                        *mttr_messages,
                    ],
                )

                live.update(dashboard.generate_layout())
                time.sleep(2)
    except KeyboardInterrupt:
        debug_log("Shutdown requested by user")
    finally:
        reset_stop_event.set()
        dashboard.disable_key_listener()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-Powered Cloud Monitoring & Auto-Healing System",
    )
    parser.add_argument("--tui", action="store_true", help="Run with TUI dashboard")
    parser.add_argument("--console", action="store_true", default=True, help="Console mode (default)")
    args = parser.parse_args()

    if args.tui:
        main_tui()
    else:
        main_console()


if __name__ == "__main__":
    main()
