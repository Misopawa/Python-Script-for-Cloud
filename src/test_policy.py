"""
Granular validation of the PolicyEngine auto-healing escalation matrix.

Simulates persistent AI anomalies per component (CPU, MEMORY, STORAGE, NETWORK),
asserts that each escalation level triggers the exact remediation action defined
in the 5-tier hierarchy, and verifies the heartbeat reset at the end of each run.

Usage (from project root or src/):
    python src/test_policy.py
    python -m pytest src/test_policy.py -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence
from unittest.mock import MagicMock, patch

# Ensure src/ is on the path when executed as a script.
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from healing.auto_healer import PolicyEngine  # noqa: E402


# ---------------------------------------------------------------------------
# Escalation matrix (mirrors PolicyEngine.escalation_paths + Table 3.5)
# ---------------------------------------------------------------------------

COMPONENT_PATHS: Dict[str, List[int]] = {
    "CPU": [1, 2, 4, 5],
    "MEMORY": [1, 2, 4, 5],
    "STORAGE": [1, 2, 4, 5],
    "NETWORK": [1, 3, 4, 5],
}

LEVEL_ACTIONS: Dict[int, Dict[str, object]] = {
    1: {
        "label": "Restart Service",
        "command_markers": ("systemctl", "restart"),
        "forbidden_markers": ("pkill", "traffic_reroute"),
    },
    2: {
        "label": "Process Reset",
        "command_markers": ("pkill", "stress-ng"),
        "forbidden_markers": ("traffic_reroute", "iptables", "haproxy"),
    },
    3: {
        "label": "Traffic Rerouting",
        "command_markers": ("traffic_reroute",),
        "forbidden_markers": ("pkill", "stress-ng"),
    },
    4: {
        "label": "Resource Isolation",
        "command_markers": ("pct", "reboot"),
        "forbidden_markers": ("pkill", "traffic_reroute"),
    },
    5: {
        "label": "Escalation (Log/Alert - Halt)",
        "command_markers": ("pct", "stop"),
        "forbidden_markers": ("pkill", "traffic_reroute"),
    },
}

MAX_RETRIES_PER_LEVEL: Dict[int, int] = {
    1: 2,
    2: 1,
    3: 1,
    4: 1,
    5: 0,
}

TEST_CONFIG = {
    "monitoring": {"demo_mode": True, "service_name": "nginx"},
    "proxmox": {"vmid": 101, "node": "pve", "host": "127.0.0.1", "verify_ssl": False},
    "policies": {"docker_containers": []},
}


@dataclass
class ActionRecord:
    component: str
    level: int
    anomaly_type: str
    action_label: str
    result: str
    commands: List[List[str]] = field(default_factory=list)


def _attempts_for_path(path: Sequence[int]) -> int:
    """Total anomaly cycles required to walk a full escalation path."""
    return sum(MAX_RETRIES_PER_LEVEL[level] + 1 for level in path)


def _cmd_blob(commands: Sequence[Sequence[str]]) -> str:
    return " ".join(" ".join(str(part) for part in cmd) for cmd in commands).lower()


def _result_blob(result: str) -> str:
    return str(result or "").lower()


def _assert_level_action(level: int, result: str, commands: Sequence[Sequence[str]]) -> None:
    spec = LEVEL_ACTIONS[level]
    label = str(spec["label"])
    cmd_text = _cmd_blob(commands)
    res_text = _result_blob(result)
    combined = f"{cmd_text} {res_text}"

    for marker in spec["command_markers"]:
        assert marker in combined, (
            f"Level {level} ({label}): expected marker '{marker}' in "
            f"commands/result, got commands={commands!r}, result={result!r}"
        )

    for forbidden in spec.get("forbidden_markers", ()):
        assert forbidden not in combined, (
            f"Level {level} ({label}): forbidden marker '{forbidden}' found in "
            f"commands/result: {combined!r}"
        )


def _build_anomaly_payload(component: str, value: float = 95.0) -> dict:
    features = {name: 10.0 for name in ("CPU", "MEMORY", "STORAGE", "NETWORK")}
    features[component] = value
    return {
        "anomaly": True,
        "ai_prediction": 1,
        "culprits": [component],
        "score": -0.85,
        "confidence": 0.90,
        "features": features,
    }


class EscalationTestHarness:
    """Wraps PolicyEngine with spies, stubs, and thesis-friendly logging."""

    def __init__(self, tmp_dir: str) -> None:
        self.tmp_dir = tmp_dir
        self.captured_commands: List[List[str]] = []
        self.action_log: List[ActionRecord] = []
        self._patchers: List[unittest.mock._patch] = []

    def __enter__(self) -> "EscalationTestHarness":
        self._fake_clock = 1_000_000.0

        def _fake_time() -> float:
            return self._fake_clock

        self._patchers = [
            patch("healing.auto_healer.time.time", side_effect=_fake_time),
            patch("healing.auto_healer.time.sleep", return_value=None),
            patch("healing.auto_healer.requests.post", return_value=MagicMock(ok=True)),
            patch.object(PolicyEngine, "_load_state", return_value=None),
            patch.object(PolicyEngine, "_load_system_state", return_value=None),
            patch.object(PolicyEngine, "_verify_service_with_backoff", return_value=True),
            patch.object(PolicyEngine, "_verified_docker_restart", return_value=True),
            patch("healing.auto_healer.subprocess.run", side_effect=self._mock_subprocess_run),
        ]
        for patcher in self._patchers:
            patcher.start()

        self.engine = PolicyEngine(config=dict(TEST_CONFIG))
        self.engine.cache_file = os.path.join(self.tmp_dir, "status_cache.json")
        self.engine.system_state_file = os.path.join(self.tmp_dir, "system_state.json")
        self.engine.forensics_file = os.path.join(self.tmp_dir, "forensics.csv")
        self.engine.last_action_timestamp = 0
        self.engine.STABILIZATION_WINDOW = 0
        self.engine.cooldown_period = 0
        self.engine.cooldown_until = 0.0
        self.engine.reset_state()

        self._original_trigger = self.engine._trigger_level_action
        self.engine._trigger_level_action = self._spy_trigger_level_action  # type: ignore[method-assign]
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.engine._trigger_level_action = self._original_trigger  # type: ignore[method-assign]
        for patcher in reversed(self._patchers):
            patcher.stop()

    def _mock_subprocess_run(self, cmd, *args, **kwargs):
        command = [str(part) for part in cmd]
        self.captured_commands.append(command)
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "ok"
        proc.stderr = ""
        return proc

    def _spy_trigger_level_action(self, level: int, anomaly_type: str) -> str:
        cmds_before = len(self.captured_commands)
        result = self._original_trigger(level, anomaly_type)
        cmds_for_action = self.captured_commands[cmds_before:]
        label = str(LEVEL_ACTIONS[level]["label"])
        record = ActionRecord(
            component=anomaly_type.upper(),
            level=level,
            anomaly_type=anomaly_type,
            action_label=label,
            result=result,
            commands=cmds_for_action,
        )
        self.action_log.append(record)
        return result

    def run_persistent_anomalies(self, component: str) -> List[ActionRecord]:
        path = COMPONENT_PATHS[component]
        total_attempts = _attempts_for_path(path)
        component_records: List[ActionRecord] = []

        print(f"\n{'=' * 72}")
        print(f"COMPONENT TEST: {component}")
        print(f"Escalation path: {path}  |  Required anomaly cycles: {total_attempts}")
        print(f"{'=' * 72}")

        for attempt in range(1, total_attempts + 1):
            expected_level = self.engine.current_level
            if expected_level == 0:
                expected_level = path[0]
            expected_label = LEVEL_ACTIONS[expected_level]["label"]

            # Advance simulated clock past stabilization/cooldown windows so
            # persistent anomalies can walk the full escalation path.
            self._fake_clock += 300.0
            self.engine.cooldown_until = 0.0

            print(
                f"[Attempt {attempt:02d}/{total_attempts}] "
                f"Component={component} | "
                f"CurrentLevel={self.engine.current_level} | "
                f"ExpectedAction=Level {expected_level}: {expected_label}"
            )

            before_count = len(self.action_log)
            result = self.engine.execute_remediation(_build_anomaly_payload(component))
            after_count = len(self.action_log)

            assert after_count > before_count, (
                f"Attempt {attempt}: execute_remediation did not trigger _trigger_level_action "
                f"(result={result!r}). Check stabilization/cooldown gates."
            )

            record = self.action_log[-1]
            component_records.append(record)

            print(
                f"  -> Executed Level {record.level}: {record.action_label} | "
                f"result={record.result} | commands={record.commands}"
            )

            _assert_level_action(record.level, record.result, record.commands)

            if component == "NETWORK":
                assert record.level != 2, (
                    "NETWORK path must never execute Level 2 (Process Reset); "
                    f"got Level {record.level}"
                )
                if record.level == 3:
                    assert "traffic_reroute" in _result_blob(record.result), (
                        "NETWORK Level 3 must trigger Traffic Rerouting"
                    )
                    assert "pkill" not in _cmd_blob(record.commands), (
                        "NETWORK Level 3 must NOT trigger Process Reset (pkill)"
                    )

            if component in ("CPU", "MEMORY", "STORAGE"):
                if record.level == 2:
                    assert "pkill" in _cmd_blob(record.commands), (
                        f"{component} Level 2 must trigger Process Reset (pkill)"
                    )
                    assert "traffic_reroute" not in _result_blob(record.result), (
                        f"{component} Level 2 must NOT trigger Traffic Rerouting"
                    )
                assert record.level != 3, (
                    f"{component} path must never execute Level 3 (Traffic Rerouting); "
                    f"got Level {record.level}"
                )

        # Validate the full level sequence matches the component path (ignoring retries).
        observed_levels = [record.level for record in component_records]
        observed_first_entries = []
        for lvl in observed_levels:
            if not observed_first_entries or observed_first_entries[-1] != lvl:
                observed_first_entries.append(lvl)
        assert observed_first_entries == path, (
            f"{component}: expected first-entry level sequence {path}, "
            f"got {observed_first_entries} (full sequence={observed_levels})"
        )

        # Heartbeat: clean inference resets escalation state.
        print(f"[Heartbeat] Component={component} | Sending is_anomaly=False reset")
        self._fake_clock += max(float(self.engine.STABILIZATION_WINDOW) + 1.0, 300.0)
        self.engine.cooldown_until = 0.0
        reset_result = self.engine.execute_remediation({"anomaly": False})
        assert reset_result == "none", f"Heartbeat should return 'none', got {reset_result!r}"
        assert self.engine.current_level == 0, (
            f"Heartbeat should reset current_level to 0, got {self.engine.current_level}"
        )
        assert all(v == 0 for v in self.engine.component_counters.values()), (
            "Heartbeat should zero all component counters"
        )
        print(f"  -> Heartbeat OK: current_level={self.engine.current_level}, result={reset_result}")

        return component_records


class TestPolicyEscalationMatrix(unittest.TestCase):
    """Granular escalation matrix validation for all four monitored components."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = EscalationTestHarness(self._tmp.name)
        self.harness.__enter__()

    def tearDown(self) -> None:
        self.harness.__exit__(None, None, None)
        self._tmp.cleanup()

    def test_cpu_escalation_matrix(self) -> None:
        records = self.harness.run_persistent_anomalies("CPU")
        self.assertEqual([r.level for r in records if r.level == 2][0], 2)
        self.assertNotIn(3, [r.level for r in records])

    def test_memory_escalation_matrix(self) -> None:
        records = self.harness.run_persistent_anomalies("MEMORY")
        self.assertIn(2, [r.level for r in records])
        self.assertNotIn(3, [r.level for r in records])

    def test_storage_escalation_matrix(self) -> None:
        records = self.harness.run_persistent_anomalies("STORAGE")
        self.assertIn(2, [r.level for r in records])
        self.assertNotIn(3, [r.level for r in records])

    def test_network_escalation_matrix(self) -> None:
        records = self.harness.run_persistent_anomalies("NETWORK")
        levels = [r.level for r in records]
        self.assertNotIn(2, levels)
        self.assertIn(3, levels)
        level3 = next(r for r in records if r.level == 3)
        self.assertIn("traffic_reroute", level3.result)
        self.assertFalse(any("pkill" in _cmd_blob(r.commands) for r in records))


def print_thesis_summary() -> None:
    print("\n" + "=" * 72)
    print("ESCALATION MATRIX REFERENCE (Thesis Documentation)")
    print("=" * 72)
    for component, path in COMPONENT_PATHS.items():
        print(f"\n{component}:")
        for level in path:
            spec = LEVEL_ACTIONS[level]
            markers = ", ".join(spec["command_markers"])
            print(f"  Level {level}: {spec['label']}  [{markers}]")
    print("\nRetry policy (Table 3.1):")
    for level, retries in MAX_RETRIES_PER_LEVEL.items():
        print(f"  Level {level}: {retries} retries ({retries + 1} executions before escalate)")
    print("=" * 72)


def main() -> int:
    print_thesis_summary()
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPolicyEscalationMatrix)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print("\n" + "=" * 72)
    if result.wasSuccessful():
        print("ALL ESCALATION MATRIX TESTS PASSED")
    else:
        print(f"FAILURES: {len(result.failures)} | ERRORS: {len(result.errors)}")
    print("=" * 72)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
