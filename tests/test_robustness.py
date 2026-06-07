"""Robustness and policy-path verification tests (mocked — no real infrastructure)."""

from __future__ import annotations

import importlib.util
import os
import sys
import time
import types
import unittest
from dataclasses import dataclass
from typing import Dict, Tuple
from unittest.mock import MagicMock, patch

# Ensure src/ is importable when running from project root.
SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _stub_module(name: str, **attrs) -> types.ModuleType:
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    sys.modules[name] = mod
    return mod


# Stub optional/heavy imports before loading main.py.
_stub_module("requests")
_stub_module("rich")
_stub_module("rich.live", Live=MagicMock())
_stub_module("data.collector", DataCollector=MagicMock())
_stub_module("ui.dashboard_tui", HealingDashboard=MagicMock())

_main_path = os.path.join(SRC_ROOT, "main.py")
_spec = importlib.util.spec_from_file_location("main", _main_path)
main = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(main)

from logic.detector import MetricInference  # noqa: E402
from logic.healer import (  # noqa: E402
    MAX_ESCALATION_LEVEL,
    TIMEOUT_RETURN_CODE,
    Healer,
    RemediationResult,
)

_execute_remediation_step = main._execute_remediation_step
_process_remediation_outcome = main._process_remediation_outcome
_new_escalation_state = main._new_escalation_state
_new_mttr_state = main._new_mttr_state
_process_active_verification = main._process_active_verification
_process_expired_sync_locks = main._process_expired_sync_locks
run_cycle = main.run_cycle


@dataclass
class _FakeInferenceResult:
    culprits: Tuple[str, ...]
    by_metric: Dict[str, MetricInference]
    features: Dict[str, float]
    is_anomaly: bool = True

    @property
    def confidence(self) -> float:
        return 1.0

    @property
    def anomaly_score(self) -> float:
        return 0.0

    @property
    def ai_prediction(self) -> int:
        return 1


def _metric_inference(name: str, value: float, *, anomaly: bool = True) -> MetricInference:
    return MetricInference(
        name=name,
        value=value,
        ai_prediction=1 if anomaly else 0,
        is_anomaly=anomaly,
        confidence=1.0 if anomaly else 0.0,
        anomaly_score=0.0,
    )


def _failed(level: int, culprit: str = "CPU") -> RemediationResult:
    return RemediationResult(
        success=False,
        message=f"forced_fail_level_{level}",
        culprit=culprit,
        confidence=1.0,
        completed_at=time.time(),
        escalation_level=level,
        command=f"mock-level-{level}",
        action_label=f"Level {level}",
        return_code=1,
    )


def _success(level: int, culprit: str) -> RemediationResult:
    return RemediationResult(
        success=True,
        message="mock_success",
        culprit=culprit,
        confidence=1.0,
        completed_at=time.time(),
        escalation_level=level,
        command=f"mock-level-{level}",
        action_label=f"Level {level}",
        return_code=0,
    )


def _run_escalation_ticks(
    healer: Healer,
    culprit: str,
    escalation_state: dict,
    side_effect,
    *,
    inference: _FakeInferenceResult | None = None,
    max_ticks: int = 10,
) -> list[int]:
    """Simulate one policy step per tick until halt or path exhausted."""
    levels_called: list[int] = []
    inference = inference or _FakeInferenceResult(
        culprits=(culprit,),
        by_metric={culprit: _metric_inference(culprit, 99.0)},
        features={culprit: 99.0},
    )
    mttr_state = _new_mttr_state()

    with patch.object(healer, "execute_level_remediation", side_effect=side_effect):
        with patch("main.time.sleep", lambda _s: None), patch.object(
            main, "_check_cpu_stress_pids_via_ssh", return_value="1234"
        ), patch.object(
            main, "_check_process_table_via_ssh", return_value=""
        ):
                for _ in range(max_ticks):
                    if escalation_state.get("is_halted"):
                        break
                    metric_state = escalation_state["metrics"][culprit]
                    if metric_state.get("is_halted"):
                        break
                    if metric_state.get("path_index", 0) >= len(healer.get_policy_path(culprit)):
                        break
                    remediation = _execute_remediation_step(healer, culprit, 1.0, escalation_state)
                    if remediation is None:
                        break
                    levels_called.append(remediation.escalation_level)
                    _process_remediation_outcome(
                        remediation, inference, escalation_state, mttr_state, healer
                    )
                    if metric_state.get("awaiting_verification"):
                        metric_state["verify_until"] = time.time() - 1
                        live_metrics = {
                            name: 99.0 for name in ("CPU", "MEMORY", "STORAGE", "NETWORK")
                        }
                        _process_active_verification(
                            live_metrics, escalation_state, mttr_state, healer
                        )
                    elif metric_state.get("execution_locked"):
                        metric_state["sync_until"] = time.time() - 1
                        metric_state["sync_locked_until"] = time.time() - 1
                        _process_expired_sync_locks(
                            escalation_state, inference, mttr_state, healer
                        )
                    if escalation_state.get("is_halted"):
                        break

    return levels_called


class TestCPUEscalationCircuitBreaker(unittest.TestCase):
    """CPU path: L1 x2 → L2 → L4 → L5 halt (one step per tick, Path A on failure)."""

    def test_cpu_escalation_path_and_halt(self):
        healer = Healer(
            target_vmid=100,
            target_ip="10.0.2.100",
            telegram_config={"bot_token": "test-token", "chat_id": "12345"},
            demo_mode=True,
        )
        escalation_state = _new_escalation_state()

        def _side_effect(culprit, confidence=0.0, escalation_level=1, level=None):
            lvl = int(level if level is not None else escalation_level)
            if lvl >= MAX_ESCALATION_LEVEL:
                return RemediationResult(
                    success=False,
                    message="level5_human_intervention_required",
                    culprit="CPU",
                    confidence=1.0,
                    completed_at=time.time(),
                    escalation_level=MAX_ESCALATION_LEVEL,
                    command="HUMAN INTERVENTION REQUIRED",
                    action_label="Escalation",
                    human_intervention_required=True,
                    is_halted=True,
                    return_code=5,
                )
            return _failed(lvl, "CPU")

        levels_called = _run_escalation_ticks(healer, "CPU", escalation_state, _side_effect)

        self.assertEqual(levels_called, [1, 1, 2, 4, 5])
        self.assertTrue(escalation_state["is_halted"])
        self.assertTrue(escalation_state["metrics"]["CPU"]["is_halted"])

        telegram_payloads: list[dict] = []

        def _capture_telegram(message: str) -> bool:
            telegram_payloads.append({"text": message})
            return True

        with patch.object(healer, "_send_telegram_alert", side_effect=_capture_telegram) as tg_mock:
            halt = healer.execute_remediation("CPU", 1.0, escalation_level=5)
            tg_mock.assert_called_once()
        self.assertIn("HUMAN INTERVENTION REQUIRED", telegram_payloads[0]["text"])
        self.assertTrue(halt.is_halted)


class TestMemoryStateClearanceOnSuccess(unittest.TestCase):
    """Memory anomaly clears state after successful L1 + Path B sync + healthy re-check."""

    def test_memory_state_resets_after_recovery(self):
        healer = Healer(demo_mode=True)
        escalation_state = _new_escalation_state()
        mttr_state = {
            "detected_at": time.time() - 5,
            "completed_at": None,
            "mttr_seconds": None,
            "culprit": "MEMORY",
        }
        metric_state = escalation_state["metrics"]["MEMORY"]
        still_high = _FakeInferenceResult(
            culprits=("MEMORY",),
            by_metric={"MEMORY": _metric_inference("MEMORY", 90.0)},
            features={"MEMORY": 90.0},
        )

        with patch.object(
            healer,
            "execute_level_remediation",
            return_value=_success(1, "MEMORY"),
        ):
            with patch("main.time.sleep", lambda _s: None):
                remediation = _execute_remediation_step(healer, "MEMORY", 1.0, escalation_state)
                self.assertIsNotNone(remediation)
                _process_remediation_outcome(
                    _success(1, "MEMORY"), still_high, escalation_state, mttr_state, healer
                )

        self.assertTrue(metric_state["execution_locked"])
        self.assertTrue(metric_state["awaiting_post_sync_check"])

        metric_state["sync_locked_until"] = time.time() - 1
        metric_state["sync_until"] = time.time() - 1
        healthy = _FakeInferenceResult(
            culprits=tuple(),
            by_metric={"MEMORY": _metric_inference("MEMORY", 45.0, anomaly=False)},
            features={"MEMORY": 45.0},
            is_anomaly=False,
        )

        with patch.object(healer, "log_mttr", return_value=1.234):
            _process_expired_sync_locks(escalation_state, healthy, mttr_state, healer)

        self.assertEqual(metric_state["active_level"], 0)
        self.assertEqual(metric_state["path_index"], 0)
        self.assertFalse(metric_state["execution_locked"])
        self.assertFalse(metric_state["awaiting_post_sync_check"])
        self.assertIsNotNone(mttr_state["mttr_seconds"])

    def test_path_a_instant_advance_on_command_failure(self):
        healer = Healer(demo_mode=True)
        escalation_state = _new_escalation_state()
        metric_state = escalation_state["metrics"]["CPU"]
        inference = _FakeInferenceResult(
            culprits=("CPU",),
            by_metric={"CPU": _metric_inference("CPU", 100.0)},
            features={"CPU": 100.0},
        )

        _process_remediation_outcome(
            _failed(1, "CPU"), inference, escalation_state, _new_mttr_state(), healer
        )

        self.assertEqual(metric_state["path_index"], 1)
        self.assertIsNone(metric_state["first_detected"])
        self.assertFalse(metric_state["execution_locked"])


class TestNetworkPathShortcut(unittest.TestCase):
    """Network policy bypasses Level 2: L1 x2 → L3 x2 → L4 → L5."""

    def test_network_skips_level_two(self):
        healer = Healer(demo_mode=True)
        escalation_state = _new_escalation_state()

        def _side_effect(culprit, confidence=0.0, escalation_level=1, level=None):
            lvl = int(level if level is not None else escalation_level)
            if lvl == 3:
                step = healer.get_policy_step("NETWORK", 3)
                self.assertIn("root@127.0.0.1", step.command_display)
                self.assertIn("-p 2222", step.command_display)
                self.assertIn("/usr/sbin/pct exec 100", step.command_display)
                self.assertIn("iptables -A INPUT -p tcp --dport 80 -j DROP", step.command_display)
            return _failed(lvl, "NETWORK")

        levels_called = _run_escalation_ticks(
            healer, "NETWORK", escalation_state, _side_effect, max_ticks=6
        )

        self.assertNotIn(2, levels_called)
        self.assertEqual(levels_called[:4], [1, 1, 3, 3])
        self.assertIn(4, levels_called)

    def test_timeout_advances_policy_path(self):
        healer = Healer(demo_mode=True)
        escalation_state = _new_escalation_state()

        def _side_effect(culprit, confidence=0.0, escalation_level=1, level=None):
            lvl = int(level if level is not None else escalation_level)
            return RemediationResult(
                success=False,
                message="command_timeout",
                culprit="NETWORK",
                confidence=1.0,
                completed_at=time.time(),
                escalation_level=lvl,
                command="mock",
                return_code=TIMEOUT_RETURN_CODE,
            )

        levels_called = _run_escalation_ticks(
            healer, "NETWORK", escalation_state, _side_effect, max_ticks=3
        )

        self.assertGreater(len(levels_called), 1)
        self.assertNotIn(2, levels_called)
        # L3 failures enforce Path B cooldown; path_index advances only after sync expiry.
        self.assertGreaterEqual(escalation_state["metrics"]["NETWORK"]["path_index"], 2)


class TestRunCycleSyncLockGuard(unittest.TestCase):
    """run_cycle must pause re-evaluation while Path B sync lock is active."""

    def test_sync_lock_pauses_remediation(self):
        collector = MagicMock()
        collector.get_live_state.return_value = {
            "CPU": 100.0,
            "MEMORY": 40.0,
            "STORAGE": 30.0,
            "NETWORK": 10.0,
        }
        detector = MagicMock()
        detector.infer.return_value = _FakeInferenceResult(
            culprits=("CPU",),
            by_metric={"CPU": _metric_inference("CPU", 100.0)},
            features={"CPU": 100.0},
        )
        healer = Healer(demo_mode=True)

        escalation_state = _new_escalation_state()
        metric_state = escalation_state["metrics"]["CPU"]
        metric_state["execution_locked"] = True
        metric_state["sync_locked_until"] = time.time() + 30
        metric_state["sync_until"] = time.time() + 30
        metric_state["active_level"] = 1
        escalation_state["sync_locked_culprit"] = "CPU"

        with patch.object(healer, "execute_level_remediation") as mock_exec:
            _, _, action, _, _ = run_cycle(
                collector,
                detector,
                healer,
                escalation_state=escalation_state,
                sleep_fn=lambda _s: None,
            )
            mock_exec.assert_not_called()

        self.assertIn("SYNCING", action)


if __name__ == "__main__":
    unittest.main()
