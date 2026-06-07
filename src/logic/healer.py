"""Policy-driven auto-healer for Proxmox LXC architecture (CT 101 → CT 100)."""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

MIN_REMEDIATION_CONFIDENCE = 0.10  # MTTR testing — raise to 0.55 for production
MTTR_FORENSICS_FILE = "mttr_forensics.csv"
MAX_ESCALATION_LEVEL = 5
COMMAND_TIMEOUT_SECONDS = 10
TIMEOUT_RETURN_CODE = -1

DEFAULT_TARGET_VMID = 100
DEFAULT_TARGET_IP = "10.0.2.100"
DEFAULT_SSH_USER = "root"

SSH_BIN = "/usr/bin/ssh"
PCT_BIN = "/usr/sbin/pct"

LEVEL_TYPE_LABELS: Dict[int, str] = {
    1: "Restart Service",
    2: "Process Reset",
    3: "Traffic Rerouting",
    4: "Resource Isolation",
    5: "Escalation",
}


@dataclass(frozen=True)
class PolicyStep:
    level: int
    label: str
    argv: Tuple[str, ...]
    command_display: str
    exec_mode: str  # direct | halt | local_fallback
    retry_limit: int = 1


def _ssh_cmd(target_ip: str, remote_command: str) -> Tuple[str, ...]:
    """Hardened SSH invocation with TTY allocation and no host-key prompts."""
    return (
        SSH_BIN,
        "-tt",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        f"{DEFAULT_SSH_USER}@{target_ip}",
        remote_command,
    )

def _ssh_bg_cmd(target_ip: str, remote_command: str) -> Tuple[str, ...]:
    """Fast background SSH execution without pseudo-terminal (TTY) overhead."""
    return (
        SSH_BIN,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        f"{DEFAULT_SSH_USER}@{target_ip}",
        remote_command,
    )

def _build_command_lookup(
    target_vmid: int = DEFAULT_TARGET_VMID,
    target_ip: str = DEFAULT_TARGET_IP,
) -> Dict[str, Dict[int, Tuple[str, ...]]]:
    """
    Hybrid dispatch: Level 1 via guest SSH (target_ip); Levels 2/3/4 via Proxmox
    through VirtualBox NAT port-forward tunnel (127.0.0.1:2222 → 10.0.2.15:22).
    """
    TUNNEL_HOST = "127.0.0.1"
    TUNNEL_PORT = "2222"
    vmid = str(target_vmid)
    guest_ssh = (
        SSH_BIN,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
    )
    tunnel_ssh = (
        SSH_BIN,
        "-p",
        TUNNEL_PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
    )

    def _guest(level1_cmd: str) -> Tuple[str, ...]:
        return (*guest_ssh, f"{DEFAULT_SSH_USER}@{target_ip}", level1_cmd)

    def _tunnel(remote_command: str) -> Tuple[str, ...]:
        return (*tunnel_ssh, f"{DEFAULT_SSH_USER}@{TUNNEL_HOST}", remote_command)

    return {
        "CPU": {
            1: _guest("systemctl restart nginx"),
            2: _tunnel(
                f"{PCT_BIN} exec {vmid} -- sh -c 'pkill -9 -f stress || true'"
            ),
            4: _tunnel(f"{PCT_BIN} set {vmid} --cores 1 --cpulimit 0.5"),
        },
        "MEMORY": {
            1: _guest("systemctl restart nginx"),
            2: _tunnel(
                f"{PCT_BIN} exec {vmid} -- sh -c 'pkill -9 -f leaked_proc || true'"
            ),
            4: _tunnel(f"{PCT_BIN} set {vmid} --memory 2048"),
        },
        "NETWORK": {
            1: _guest("systemctl restart systemd-networkd"),
            3: _tunnel(
                f"{PCT_BIN} exec {vmid} -- sh -c "
                f"'iptables -F && iptables -A INPUT -p tcp --dport 80 -j DROP || true'"
            ),
            4: _tunnel(f"{PCT_BIN} set {vmid} --net0 name=eth0,bridge=vmbr0,link_down=1"),
        },
        "STORAGE": {
            1: _guest("systemctl restart systemd-journald"),
            2: _tunnel(
                f"{PCT_BIN} exec {vmid} -- sh -c 'pkill -9 -f io_heavy_proc || true'"
            ),
            4: _tunnel(f"{PCT_BIN} set {vmid} --disk 8"),
        },
    }


def _argv_display(argv: Sequence[str]) -> str:
    return " ".join(str(part) for part in argv)


def _build_policy_matrix(
    target_vmid: int = DEFAULT_TARGET_VMID,
    target_ip: str = DEFAULT_TARGET_IP,
) -> Dict[str, Dict[int, PolicyStep]]:
    """Build metric → level → policy step lookup from COMMAND_LOOKUP."""
    command_lookup = _build_command_lookup(target_vmid, target_ip)
    labels = {
        "CPU": {1: "Restart Service", 2: "Process Reset", 4: "Resource Isolation", 5: "Escalation"},
        "MEMORY": {1: "Restart Service", 2: "Process Reset", 4: "Resource Isolation", 5: "Escalation"},
        "NETWORK": {1: "Restart Service", 3: "Traffic Rerouting", 4: "Resource Isolation", 5: "Escalation"},
        "STORAGE": {1: "Restart Service", 2: "Process Reset", 4: "Resource Isolation", 5: "Escalation"},
    }
    halt_messages = {
        "CPU": "HUMAN INTERVENTION REQUIRED — CPU auto-healing halted",
        "MEMORY": "HUMAN INTERVENTION REQUIRED — Memory auto-healing halted",
        "NETWORK": "HUMAN INTERVENTION REQUIRED — Network auto-healing halted",
        "STORAGE": "HUMAN INTERVENTION REQUIRED — Storage auto-healing halted",
    }

    matrix: Dict[str, Dict[int, PolicyStep]] = {}
    for metric, levels in command_lookup.items():
        matrix[metric] = {}
        for level, argv in levels.items():
            matrix[metric][level] = PolicyStep(
                level=level,
                label=labels[metric][level],
                argv=tuple(argv),
                command_display=_argv_display(argv),
                exec_mode="direct",
                retry_limit=2 if level == 1 else 1,
            )
        matrix[metric][5] = PolicyStep(
            level=5,
            label="Escalation",
            argv=tuple(),
            command_display=halt_messages[metric],
            exec_mode="halt",
            retry_limit=1,
        )
    return matrix


METRIC_POLICY_PATHS: Dict[str, List[int]] = {
    "CPU": [1, 1, 2, 4, 5],
    "MEMORY": [1, 1, 2, 4, 5],
    "NETWORK": [1, 1, 3, 3, 4, 5],
    "STORAGE": [1, 1, 2, 4, 5],
}


@dataclass(frozen=True)
class RemediationResult:
    success: bool
    message: str
    culprit: str
    confidence: float
    completed_at: float
    escalation_level: int = 1
    command: str = ""
    action_label: str = ""
    human_intervention_required: bool = False
    is_halted: bool = False
    return_code: int = 0
    stdout: str = ""
    stderr: str = ""

    @property
    def level(self) -> int:
        return self.escalation_level

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "message": self.message,
            "culprit": self.culprit,
            "confidence": self.confidence,
            "completed_at": self.completed_at,
            "escalation_level": self.escalation_level,
            "command": self.command,
            "action_label": self.action_label,
            "human_intervention_required": self.human_intervention_required,
            "is_halted": self.is_halted,
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def debug_log(message: str) -> None:
    """Emit synchronous DEBUG output with millisecond-precision timestamps."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[DEBUG] [{ts}] {message}", flush=True)


def stress_cpu(duration_seconds: int = 60, workers: Optional[int] = None) -> Optional[subprocess.Popen]:
    """Spike CPU usage to 90%+ for a defined duration (MTTR test hook)."""
    duration_seconds = max(1, int(duration_seconds))
    worker_count = max(1, int(workers or os.cpu_count() or 2))

    if shutil.which("stress-ng"):
        process = subprocess.Popen(
            [
                "stress-ng",
                "--cpu",
                str(worker_count),
                "--cpu-load",
                "95",
                "--timeout",
                f"{duration_seconds}s",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_log(
            f"stress-ng started ({worker_count} workers, {duration_seconds}s). PID={process.pid}"
        )
        return process

    spin_script = (
        "import time\n"
        f"end = time.time() + {duration_seconds}\n"
        "while time.time() < end:\n"
        "    _ = sum(i * i for i in range(10000))\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", spin_script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    debug_log(f"Python CPU loop started ({duration_seconds}s). PID={process.pid}")
    return process


class Healer:
    """Policy-based remediation executor for Management Node → Target LXC."""

    def __init__(
        self,
        min_confidence: float = MIN_REMEDIATION_CONFIDENCE,
        target_vmid: int = DEFAULT_TARGET_VMID,
        target_ip: str = DEFAULT_TARGET_IP,
        forensics_file: str = MTTR_FORENSICS_FILE,
        telegram_config: Optional[Dict[str, str]] = None,
        *,
        force_immediate: bool = True,
        demo_mode: bool = True,
    ) -> None:
        self.min_confidence = float(min_confidence)
        self.target_vmid = int(target_vmid)
        self.target_ip = str(target_ip)
        self.forensics_file = forensics_file
        self.telegram_config = dict(telegram_config or {})
        self.force_immediate = bool(force_immediate)
        self.demo_mode = bool(demo_mode)
        self.command_lookup = _build_command_lookup(self.target_vmid, self.target_ip)
        self.policy_matrix = _build_policy_matrix(self.target_vmid, self.target_ip)

    def get_policy_path(self, culprit: str) -> List[int]:
        return list(METRIC_POLICY_PATHS.get(str(culprit).upper(), [1, 2, 4, 5]))

    def get_policy_step(self, culprit: str, level: int) -> Optional[PolicyStep]:
        return self.policy_matrix.get(str(culprit).upper(), {}).get(int(level))

    def get_action_label(self, culprit: str, level: int) -> str:
        step = self.get_policy_step(culprit, level)
        if step:
            return step.label
        return LEVEL_TYPE_LABELS.get(level, "Remediate")

    def execute_remediation(
        self,
        culprit: str,
        confidence: float = 0.0,
        *,
        escalation_level: int = 1,
        level: Optional[int] = None,
    ) -> RemediationResult:
        """Dispatch remediation for culprit at the requested escalation level."""
        return self.execute_level_remediation(
            culprit,
            confidence,
            escalation_level=int(level if level is not None else escalation_level),
        )

    def execute_level_remediation(
        self,
        culprit: str,
        confidence: float = 0.0,
        *,
        escalation_level: int = 1,
    ) -> RemediationResult:
        """Parse COMMAND_LOOKUP and execute the hardened argv array for this level."""
        culprit = str(culprit or "").upper()
        confidence = float(confidence or 0.0)
        escalation_level = max(1, min(MAX_ESCALATION_LEVEL, int(escalation_level)))
        started_at = time.time()
        step: Optional[PolicyStep] = None

        try:
            if not self.force_immediate and confidence < self.min_confidence:
                message = f"skipped_low_confidence ({confidence:.0%} < {self.min_confidence:.0%})"
                debug_log(f"{culprit} Lvl {escalation_level}: {message}")
                return RemediationResult(
                    success=False,
                    message=message,
                    culprit=culprit,
                    confidence=confidence,
                    completed_at=time.time(),
                    escalation_level=escalation_level,
                    command="",
                    action_label=self.get_action_label(culprit, escalation_level),
                    return_code=1,
                )

            step = self.get_policy_step(culprit, escalation_level)
            if step is None:
                message = f"no_policy_for_{culprit.lower()}_level_{escalation_level}"
                debug_log(message)
                return RemediationResult(
                    success=False,
                    message=message,
                    culprit=culprit,
                    confidence=confidence,
                    completed_at=time.time(),
                    escalation_level=escalation_level,
                    command="",
                    action_label=LEVEL_TYPE_LABELS.get(escalation_level, "Unknown"),
                    return_code=1,
                )

            if step.exec_mode == "halt" or escalation_level >= MAX_ESCALATION_LEVEL:
                return self._execute_halt(culprit, confidence, step, started_at)

            success, message, return_code, stdout, stderr = self._run_policy_command(step)
            elapsed_ms = (time.time() - started_at) * 1000.0
            # Normalize: structural success strictly requires exit code 0.
            success = bool(success and return_code == 0)
            debug_log(
                f"{culprit} Lvl {escalation_level} ({step.label}): "
                f"cmd='{step.command_display}' rc={return_code} success={success} "
                f"elapsed={elapsed_ms:.1f}ms msg={message}"
            )

            return RemediationResult(
                success=success,
                message=message,
                culprit=culprit,
                confidence=confidence,
                completed_at=time.time(),
                escalation_level=escalation_level,
                command=step.command_display,
                action_label=step.label,
                human_intervention_required=False,
                is_halted=False,
                return_code=return_code,
                stdout=stdout,
                stderr=stderr,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = self._decode_output(getattr(exc, "stdout", ""))
            stderr = self._decode_output(getattr(exc, "stderr", ""))
            self._log_command_failure(step.command_display if step else "", stdout, stderr, TIMEOUT_RETURN_CODE)
            return RemediationResult(
                success=False,
                message="command_timeout",
                culprit=culprit,
                confidence=confidence,
                completed_at=time.time(),
                escalation_level=escalation_level,
                command=step.command_display if step else "",
                action_label=self.get_action_label(culprit, escalation_level),
                return_code=TIMEOUT_RETURN_CODE,
                stdout=stdout,
                stderr=stderr or f"timeout after {COMMAND_TIMEOUT_SECONDS}s",
            )
        except subprocess.SubprocessError as exc:
            debug_log(f"{culprit} Lvl {escalation_level}: subprocess_error={exc}")
            return RemediationResult(
                success=False,
                message=f"subprocess_error:{exc}",
                culprit=culprit,
                confidence=confidence,
                completed_at=time.time(),
                escalation_level=escalation_level,
                command=step.command_display if step else "",
                action_label=self.get_action_label(culprit, escalation_level),
                return_code=TIMEOUT_RETURN_CODE,
                stderr=str(exc),
            )

    @staticmethod
    def _decode_output(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode(errors="replace").strip()
        return str(value).strip()

    @staticmethod
    def _log_command_failure(command: str, stdout: str, stderr: str, return_code: int) -> None:
        debug_log(f"COMMAND FAILED rc={return_code} cmd={command}")
        debug_log(f"STDOUT: {stdout or '<empty>'}")
        debug_log(f"STDERR: {stderr or '<empty>'}")

    def _execute_halt(
        self,
        culprit: str,
        confidence: float,
        step: PolicyStep,
        started_at: float,
    ) -> RemediationResult:
        alert_message = (
            f"🚨 <b>[CRITICAL ESCALATION]</b> Level 5 reached for <b>{culprit}</b> "
            f"on LXC {self.target_vmid}. <b>HUMAN INTERVENTION REQUIRED IMMEDIATELY.</b>"
        )
        debug_log(f"{culprit} Level 5 halt — triggering Telegram alert and circuit breaker")
        self._send_telegram_alert(alert_message)
        elapsed_ms = (time.time() - started_at) * 1000.0
        debug_log(f"Human intervention logged for {culprit} elapsed={elapsed_ms:.1f}ms")
        return RemediationResult(
            success=False,
            message="level5_human_intervention_required",
            culprit=culprit,
            confidence=confidence,
            completed_at=time.time(),
            escalation_level=MAX_ESCALATION_LEVEL,
            command=step.command_display,
            action_label=step.label,
            human_intervention_required=True,
            is_halted=True,
            return_code=5,
        )

    def _run_policy_command(self, step: PolicyStep) -> Tuple[bool, str, int, str, str]:
        debug_log(f"Executing ({step.exec_mode}): {step.command_display}")
        if step.exec_mode == "halt":
            return False, "halt_step", 5, "", ""
        if not step.argv:
            return False, "empty_argv", 1, "", "missing argv"

        if self.demo_mode and not self._command_runner_available(step.argv):
            return self._run_local_fallback(step)

        return self.execute_level_remediation_argv(step.argv, step.command_display)

    @staticmethod
    def _command_runner_available(argv: Sequence[str]) -> bool:
        if not argv:
            return False
        binary = argv[0]
        if binary.startswith("/"):
            return os.path.exists(binary)
        return shutil.which(binary) is not None

    def execute_level_remediation_argv(
        self,
        cmd_array: Sequence[str],
        command_display: str = "",
    ) -> Tuple[bool, str, int, str, str]:
        """Run hardened subprocess dispatch with full stdout/stderr capture."""
        safe_argv = [str(part) for part in cmd_array if str(part)]
        label = command_display or _argv_display(safe_argv)
        if not safe_argv:
            return False, "empty_argv", 1, "", "empty command array"

        debug_log(f"subprocess.run shell=False timeout={COMMAND_TIMEOUT_SECONDS}s argv={safe_argv}")

        try:
            proc = subprocess.run(
                safe_argv,
                shell=False,
                capture_output=True,
                text=True,
                check=False,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
            stdout = (proc.stdout or "").strip()
            stderr = (proc.stderr or "").strip()

            if proc.returncode == 0:
                debug_log(f"COMMAND OK rc=0 cmd={label}")
                if stdout:
                    debug_log(f"STDOUT: {stdout}")
                return True, "command_success", 0, stdout, stderr

            self._log_command_failure(label, stdout, stderr, proc.returncode)
            return False, f"command_failed_rc_{proc.returncode}", int(proc.returncode), stdout, stderr

        except subprocess.TimeoutExpired as exc:
            stdout = self._decode_output(getattr(exc, "stdout", ""))
            stderr = self._decode_output(getattr(exc, "stderr", "")) or f"timeout after {COMMAND_TIMEOUT_SECONDS}s"
            self._log_command_failure(label, stdout, stderr, TIMEOUT_RETURN_CODE)
            return False, "command_timeout", TIMEOUT_RETURN_CODE, stdout, stderr

        except subprocess.SubprocessError as exc:
            stderr = str(exc)
            self._log_command_failure(label, "", stderr, TIMEOUT_RETURN_CODE)
            return False, f"subprocess_error:{exc}", TIMEOUT_RETURN_CODE, "", stderr

    def _execute_argv(self, argv: Sequence[str]) -> Tuple[bool, str, int]:
        success, message, return_code, _, _ = self.execute_level_remediation_argv(argv)
        return success, message, return_code

    def _run_local_fallback(self, step: PolicyStep) -> Tuple[bool, str, int, str, str]:
        """Local execution fallback when absolute binaries are unavailable."""
        debug_log(f"Local fallback (demo): {step.command_display}")
        display = step.command_display.lower()

        try:
            if "stress-ng-cpu" in display:
                proc = subprocess.run(
                    ["sh", "-c", "kill -9 $(pgrep -f stress-ng-cpu)"],
                    shell=False,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=COMMAND_TIMEOUT_SECONDS,
                )
                stdout = (proc.stdout or "").strip()
                stderr = (proc.stderr or "").strip()
                if self.cpu_stress_still_running():
                    self._log_command_failure(step.command_display, stdout, stderr, proc.returncode)
                    return False, "local_fallback_process_still_running", proc.returncode or 1, stdout, stderr
                return True, "local_fallback_success", 0, stdout, stderr

            if "systemctl restart" in display:
                service = display.rsplit("systemctl restart", 1)[-1].strip().split()[0]
                proc = subprocess.run(
                    ["/usr/bin/systemctl", "restart", service],
                    shell=False,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=COMMAND_TIMEOUT_SECONDS,
                )
                stdout = (proc.stdout or "").strip()
                stderr = (proc.stderr or "").strip()
                if proc.returncode != 0:
                    self._log_command_failure(step.command_display, stdout, stderr, proc.returncode)
                    return False, f"local_fallback_rc_{proc.returncode}", proc.returncode, stdout, stderr
                return True, "local_fallback_success", 0, stdout, stderr

            if "iptables" in display:
                rule_argv = [
                    "/usr/sbin/iptables",
                    "-A",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    "80",
                    "-j",
                    "DROP",
                ]
                if os.path.exists(rule_argv[0]):
                    proc = subprocess.run(
                        rule_argv,
                        shell=False,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=COMMAND_TIMEOUT_SECONDS,
                    )
                    stdout = (proc.stdout or "").strip()
                    stderr = (proc.stderr or "").strip()
                    if proc.returncode != 0:
                        self._log_command_failure(step.command_display, stdout, stderr, proc.returncode)
                        return False, f"local_fallback_rc_{proc.returncode}", proc.returncode, stdout, stderr
                    return True, "local_fallback_success", 0, stdout, stderr
                return True, "local_fallback_simulated", 0, "", "iptables binary not present — simulated"

            return True, "local_fallback_simulated", 0, "", "simulated success (demo mode)"
        except subprocess.TimeoutExpired as exc:
            stdout = self._decode_output(getattr(exc, "stdout", ""))
            stderr = self._decode_output(getattr(exc, "stderr", ""))
            self._log_command_failure(step.command_display, stdout, stderr, TIMEOUT_RETURN_CODE)
            return False, "command_timeout", TIMEOUT_RETURN_CODE, stdout, stderr
        except subprocess.SubprocessError as exc:
            self._log_command_failure(step.command_display, "", str(exc), TIMEOUT_RETURN_CODE)
            return False, f"subprocess_error:{exc}", TIMEOUT_RETURN_CODE, "", str(exc)

    @staticmethod
    def stress_ng_running() -> bool:
        try:
            proc = subprocess.run(
                ["/usr/bin/pgrep", "-f", "stress-ng-cpu"],
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=5,
            )
            return proc.returncode == 0 and bool(proc.stdout.strip())
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
            return False

    @staticmethod
    def python_stress_running() -> bool:
        try:
            proc = subprocess.run(
                ["/usr/bin/pgrep", "-f", "sum(i * i for i in range"],
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=5,
            )
            return proc.returncode == 0 and bool(proc.stdout.strip())
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
            return False

    @classmethod
    def cpu_stress_still_running(cls) -> bool:
        return cls.stress_ng_running() or cls.python_stress_running()

    def _send_telegram_alert(self, message: str) -> bool:
        bot_token = self.telegram_config.get("bot_token")
        chat_id = self.telegram_config.get("chat_id")
        if not bot_token or not chat_id:
            debug_log("Telegram config missing — skipping alert")
            return False

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
        try:
            import urllib.parse
            import urllib.request

            data = urllib.parse.urlencode(payload).encode("utf-8")
            request = urllib.request.Request(url, data=data, method="POST")
            with urllib.request.urlopen(request, timeout=10) as response:
                sent = response.status == 200
                debug_log(f"Telegram alert sent={sent}")
                return sent
        except Exception as exc:
            debug_log(f"Telegram alert failed: {exc}")
            return False

    def log_mttr(
        self,
        culprit: str,
        detected_at: float,
        completed_at: float,
        confidence: float,
        success: bool,
        level: int = 1,
    ) -> float:
        """Persist and return MTTR in seconds."""
        mttr_seconds = max(0.0, float(completed_at) - float(detected_at))
        row = {
            "timestamp": datetime.fromtimestamp(completed_at).isoformat(),
            "culprit": culprit,
            "detected_at": datetime.fromtimestamp(detected_at).isoformat(),
            "completed_at": datetime.fromtimestamp(completed_at).isoformat(),
            "mttr_seconds": round(mttr_seconds, 3),
            "confidence": round(confidence, 4),
            "success": int(success),
            "level": int(level),
        }

        file_exists = os.path.isfile(self.forensics_file)
        try:
            with open(self.forensics_file, "a", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=list(row.keys()))
                if not file_exists:
                    writer.writeheader()
                writer.writerow(row)
        except OSError as exc:
            debug_log(f"Failed to write MTTR forensics: {exc}")

        debug_log(f"MTTR recorded: {mttr_seconds:.3f}s culprit={culprit} level={level}")
        return mttr_seconds


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MTTR stress-test hook")
    parser.add_argument("--duration", type=int, default=60, help="Stress duration in seconds")
    parser.add_argument("--workers", type=int, default=None, help="CPU worker count")
    args = parser.parse_args()
    proc = stress_cpu(duration_seconds=args.duration, workers=args.workers)
    if proc is not None:
        proc.wait()
