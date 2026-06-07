"""Standalone stateful auto-healing module for the AI-Powered Cloud Monitoring system.

This is the simplified, self-contained ``PolicyHealer`` used for the project's
demonstration / report walkthrough. It is intentionally decoupled from the
production engine in ``src/logic/healer.py`` (the ``Healer`` class wired into
``src/main.py``) so it can be reasoned about and executed in isolation.

Target topology
---------------
Nginx runs inside a Docker container *within* a Proxmox LXC (CT 100). Remediation
is therefore issued through the hypervisor using ``pct exec`` / ``pct set`` so the
healer never needs direct network access to the guest.
"""

from __future__ import annotations

import subprocess
from typing import Dict, Tuple

# Hard limit (seconds) for any single hypervisor command. Prevents a hung
# ``pct`` call from blocking the SENSE-LEARN-THINK-ACT loop indefinitely.
COMMAND_TIMEOUT_SECONDS = 15

# Proxmox container that hosts the target Docker workload.
TARGET_VMID = 100


class PolicyHealer:
    """Stateful, non-linear escalation engine for hypervisor-level remediation.

    Each metric (CPU / MEMORY / NETWORK / ...) owns an independent state record so
    that escalation on one resource never advances the ladder of another. The
    matrix is deliberately *non-linear*: it jumps Level 2 -> Level 4, reflecting
    that the lab has no dedicated Level 3 (traffic-rerouting) action for these
    culprits.
    """

    def __init__(self) -> None:
        # Per-metric state: {metric: {"retry_count": int, "is_halted": bool}}.
        self.state: Dict[str, Dict[str, object]] = {}

    def _metric_state(self, culprit: str) -> Dict[str, object]:
        """Return (lazily creating) the mutable state record for a metric."""
        metric = str(culprit).upper()
        if metric not in self.state:
            self.state[metric] = {"retry_count": 0, "is_halted": False}
        return self.state[metric]

    @staticmethod
    def _run_command(command: str) -> Tuple[str, str]:
        """Execute a hypervisor command, returning a ``(status, detail)`` pair.

        Robustness: a timeout or any unexpected OS/subprocess error is converted
        into a status string rather than propagating, so a single failed
        remediation can never crash the orchestration loop.
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                capture_output=True,
                text=True,  # decode stdout/stderr to str for readable messages
            )
            if result.returncode == 0:
                return "SUCCESS", (result.stdout or "").strip()
            # Non-zero exit: surface stderr (falling back to stdout) for diagnosis.
            return "FAILED", (result.stderr or result.stdout or "").strip()

        except subprocess.TimeoutExpired:
            return "TIMEOUT", f"command exceeded {COMMAND_TIMEOUT_SECONDS}s timeout"
        except Exception as exc:  # noqa: BLE001 - healer must never crash the loop
            return "ERROR", str(exc)

    def execute_policy(self, culprit: str, current_value: float) -> Tuple[str, str]:
        """Run the next remediation step for ``culprit`` and update its state.

        Escalation matrix (keyed on the metric's cumulative ``retry_count``):

            retry 0  -> Level 1  Docker service restart   pct exec 100 -- docker restart nginx
            retry 1  -> Level 2  Process reset            pct exec 100 -- pkill -9 stress-ng
            retry 2  -> Level 4  Resource hot-plug        pct set 100 -cores 4 -memory 4096
            retry >=3 -> Level 5  Human escalation (halt auto-healing for this metric)

        Returns:
            (level, action_message) where ``level`` is a label like ``"Level 1"``.
        """
        metric_state = self._metric_state(culprit)
        metric = str(culprit).upper()

        # --- Circuit breaker: already escalated to a human, stop touching it. ---
        if metric_state["is_halted"]:
            return (
                "Level 5",
                f"[HALTED] Auto-healing disabled for {metric}; awaiting manual "
                f"intervention (last reading={current_value:.2f}).",
            )

        retries = int(metric_state["retry_count"])

        # --- Level 5: retries exhausted -> trip the circuit breaker and alert. ---
        if retries >= 3:
            metric_state["is_halted"] = True
            return (
                "Level 5",
                f"CRITICAL ALERT: {metric} anomaly persists after all automated "
                f"remediation tiers (value={current_value:.2f}). Auto-healing "
                f"HALTED — human intervention required.",
            )

        # --- Select the command for the current tier. ---
        if retries == 0:
            level = "Level 1"  # Docker service restart inside the LXC.
            command = f"pct exec {TARGET_VMID} -- docker restart nginx"
        elif retries == 1:
            level = "Level 2"  # Kill the offending (stress) process.
            command = f"pct exec {TARGET_VMID} -- pkill -9 stress-ng"
        else:  # retries == 2
            level = "Level 4"  # Hot-plug additional CPU cores and memory (MB).
            command = f"pct set {TARGET_VMID} -cores 4 -memory 4096"

        # --- Execute, then advance the counter regardless of outcome. ---
        try:
            status, detail = self._run_command(command)
        finally:
            # Increment only after the attempt so the next anomaly escalates.
            metric_state["retry_count"] = retries + 1

        action_message = (
            f"{level} [{status}] {metric}={current_value:.2f} :: {command}"
            + (f" -> {detail}" if detail else "")
        )
        return level, action_message
