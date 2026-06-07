import os
import time
import signal
import shutil
import textwrap
from datetime import datetime
from collections import deque
from typing import List, Optional
import sys
import select
import termios
import tty
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich.text import Text
from rich.align import Align
from rich.live import Live

class HealingDashboard:
    def __init__(self, config, collector=None):
        # 1. Basic configuration
        self.config = config
        self.collector = collector
        
        # 2. Initialize ALL state variables BEFORE the UI starts
        # This prevents the "AttributeError" in your header/footer
        self.cycle_count = 0
        self.ui_messages = deque(maxlen=50)
        self.source_label = "UNKNOWN"
        self.is_connected = True
        self.waiting_for_data = False
        self.resume_requested = False
        self.telegram_active = False
        self.net_label = None
        self.stg_label = None
        self.current_healing_level = 0
        self.current_level = 0
        self.ai_confidence = 0.0
        self.ai_prediction = 0
        self.forensics_file = "anomalies_forensics.csv"
        self.mttr_forensics_file = "mttr_forensics.csv"
        self.mttr_seconds = None
        self.mttr_culprit = None
        self.remediation_logs = []
        self.alert_locked = False
        self.is_halted = False
        self._terminal_width = 100
        self._needs_reflow = True
        self._stdin_fd = None
        self._stdin_old_settings = None
        self._install_resize_handler()

        # 3. Finally, initialize the visual layout
        from rich.console import Console
        from rich.layout import Layout
        self.console = Console()
        self.layout = Layout()
        
        # This call now has access to self.cycle_count and self.source_label
        self._setup_layout()

    def _install_resize_handler(self) -> None:
        """Hook SIGWINCH so terminal resizes trigger safe panel reflow."""
        try:
            signal.signal(signal.SIGWINCH, self._on_terminal_resize)
        except (AttributeError, ValueError, OSError):
            pass
        self._refresh_terminal_width()

    def _on_terminal_resize(self, signum, frame) -> None:
        self._needs_reflow = True

    def _refresh_terminal_width(self) -> None:
        try:
            size = shutil.get_terminal_size(fallback=(120, 40))
            self._terminal_width = max(40, int(size.columns))
        except Exception:
            self._terminal_width = max(40, int(self._terminal_width or 100))

    def poll_resize(self) -> None:
        """Called each refresh cycle to apply pending resize reflow."""
        self._refresh_terminal_width()
        if self._needs_reflow:
            self._needs_reflow = False

    def _safe_str(self, value, default: str = "N/A") -> str:
        try:
            text = str(value) if value is not None else default
            return text if text else default
        except Exception:
            return default

    def _wrap_remediation_line(self, line: str, width: Optional[int] = None) -> List[str]:
        """Wrap log lines to terminal width to avoid render/index failures."""
        wrap_width = max(24, int(width or self._terminal_width) - 4)
        safe_line = self._safe_str(line, "")
        if not safe_line:
            return []
        try:
            return textwrap.wrap(
                safe_line,
                width=wrap_width,
                break_long_words=True,
                break_on_hyphens=False,
            ) or [safe_line[:wrap_width]]
        except Exception:
            return [safe_line[:wrap_width]]

    def update_metrics(self):
        """Fetches live data and refreshes the TUI panels."""
        if not self.collector:
            return

        metrics = self.collector.get_metrics()
        cpu_val = metrics.get('CPU', 0.0)
        mem_val = metrics.get('MEMORY', 0.0)
        storage_val = metrics.get('STORAGE', 0.0)
        network_val = metrics.get('NETWORK', 0.0)

        panel_text = Text.from_markup(
            f"[bold cyan]LIVE TELEMETRY[/bold cyan]\n"
            f"CPU Usage: {cpu_val:>5.2f}%\n"
            f"MEM Usage: {mem_val:>5.2f}%\n"
            f"Storage: {storage_val:>5.2f}%\n"
            f"Network: {network_val:>5.2f}%\n"
            f"AI Prediction: {self.ai_prediction}\n"
            f"AI Confidence: {self.ai_confidence:.0%}\n"
            f"[bold yellow]Current Healing Level: {self.current_healing_level}[/bold yellow]"
        )

        panel_body = Table.grid(expand=True)
        panel_body.add_row(panel_text)

        self.ui_messages.append("[INFO] Scraped metrics from 127.0.0.1:9090")

        self.layout["ai_brain"].update(Panel(panel_body, title="AI Decision Logic", border_style="cyan"))
        self.layout["footer"].update(Panel(Align.center(Text("[ SOURCE: 127.0.0.1:9090 ]  [ STATUS: CONNECTED ]", style="bold cyan")), border_style="dim"))
        self.refresh_operations()

    def format_timer(self, seconds: int) -> str:
        seconds = max(0, int(seconds))
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def set_telegram_active(self, active: bool):
        self.telegram_active = bool(active)

    def set_source_label(self, label: str):
        self.source_label = str(label or "UNKNOWN")

    def set_prometheus_labels(self, network_device: str = None, storage_label: str = None):
        self.net_label = str(network_device) if network_device else None
        self.stg_label = str(storage_label) if storage_label else None

    def enable_key_listener(self):
        try:
            if not sys.stdin.isatty():
                return
            self._stdin_fd = sys.stdin.fileno()
            self._stdin_old_settings = termios.tcgetattr(self._stdin_fd)
            tty.setcbreak(self._stdin_fd)
        except Exception:
            self._stdin_fd = None
            self._stdin_old_settings = None

    def disable_key_listener(self):
        try:
            if self._stdin_fd is None or self._stdin_old_settings is None:
                return
            termios.tcsetattr(self._stdin_fd, termios.TCSADRAIN, self._stdin_old_settings)
        except Exception:
            pass
        finally:
            self._stdin_fd = None
            self._stdin_old_settings = None

    def poll_keys(self):
        try:
            if self._stdin_fd is None:
                return
            ready, _, _ = select.select([self._stdin_fd], [], [], 0)
            if not ready:
                return
            ch = os.read(self._stdin_fd, 1).decode(errors="ignore")
            if ch in ("r", "R"):
                self.resume_requested = True
        except Exception:
            return

    def _setup_layout(self):
        self.layout.split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=2),
        )

        self.layout["left"].split(
            Layout(name="header", size=3),
            Layout(name="ai_brain", ratio=6),
            Layout(name="forensics", ratio=2),
            Layout(name="footer", size=3),
        )

        self.layout["header"].update(self._make_header(True))
        self.layout["ai_brain"].update(Panel(Align.center(Text.from_markup("Analyzing...", style="dim")), title="AI Decision Logic", border_style="dim"))
        self.layout["forensics"].update(Panel(Text.from_markup("Waiting for remediation events...", style="dim"), title="Remediation Log", border_style="dim"))
        self.refresh_operations()
        self.layout["footer"].update(self._make_footer())

    def generate_layout(self):
        return self.layout

    def update_view(self, metrics, anomaly_score, escalation_level, action_name, stabilization_window, last_action_timestamp, is_connected=False, ui_messages=None, raw_score=None, decision_heads=None, cycle_count=None, culprits=None, next_calibration_in=None, mttr_seconds=None, mttr_culprit=None, remediation_logs=None, alert_locked=False):
        if ui_messages:
            self.ui_messages.extend(list(ui_messages))
        if cycle_count is not None:
            try:
                self.cycle_count = int(cycle_count)
            except Exception:
                pass
        if mttr_seconds is not None:
            try:
                self.mttr_seconds = float(mttr_seconds)
            except Exception:
                pass
        if mttr_culprit is not None:
            self.mttr_culprit = str(mttr_culprit)
        if remediation_logs is not None:
            try:
                self.remediation_logs = list(remediation_logs)
            except Exception:
                pass
        self.alert_locked = bool(alert_locked)
        self.is_halted = bool(alert_locked)
        if escalation_level is not None:
            try:
                self.current_healing_level = int(escalation_level)
                self.current_level = int(escalation_level)
            except Exception:
                pass
        if decision_heads and isinstance(decision_heads, dict):
            sample = decision_heads.get("CPU") or {}
            try:
                self.ai_confidence = float(sample.get("confidence", self.ai_confidence))
            except Exception:
                pass
            try:
                self.ai_prediction = int(sample.get("ai_prediction", self.ai_prediction))
            except Exception:
                pass
        if culprits is not None:
            try:
                self.culprits = list(culprits)
            except Exception:
                self.culprits = []
        self.layout["header"].update(self._make_header(True))
        try:
            self.layout["ai_brain"].update(
                self._make_ai_brain_panel(
                    decision_heads, escalation_level, action_name,
                    stabilization_window, last_action_timestamp,
                    getattr(self, "culprits", []), raw_score,
                )
            )
            self.layout["forensics"].update(self._make_logs_panel())
            self.layout["right"].update(self._make_background_panel())
            self.layout["footer"].update(self._make_footer())
        except Exception:
            fallback = Panel(Text("UI reflow recovery — retrying next cycle", style="yellow"), title="Status")
            self.layout["forensics"].update(fallback)
        return self.layout

    def _make_header(self, is_connected=False):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        node = self.config.get('proxmox', {}).get('node', 'pve')
        mgmt_vmid = self.config.get('proxmox', {}).get('management_vmid', 101)
        target_vmid = self.config.get('proxmox', {}).get('target_vmid', 100)
        
        if is_connected:
            status_text = Text(" [CONNECTED] ✔", style="bold green")
            title_style = "bold cyan"
        else:
            status_text = Text(" Initializing Connection...", style="bold cyan")
            title_style = "bold cyan"
            
        title = Text("AI-Powered Cloud Monitoring & Auto-Healing System", style=title_style)
        info = Text(
            f" [Time: {current_time}] [Node: {node}] "
            f"[Mgmt CT: {mgmt_vmid}] [Target CT: {target_vmid}] [Cycles: {self.cycle_count}]",
            style="white",
        )
        
        header_content = title + status_text + info
        return Panel(Align.center(header_content), style="blue")

    def _make_ai_brain_panel(self, decision_heads, level, action, window, last_action, culprits, raw_score=None):
        current_time = time.time()
        time_diff = current_time - last_action
        remaining = max(0, int(window - time_diff)) if last_action > 0 else 0

        if level >= 5 or self.alert_locked or self.is_halted or "ALERT" in str(action):
            content = Text("!!! HUMAN INTERVENTION REQUIRED: PRESS 'R' TO RESUME !!!", style="bold white on bright_red blink")
            return Panel(Align.center(content, vertical="middle"), title="System Status — ALERT", border_style="bright_red")

        heads = decision_heads or {}
        table = Table(title="Health Grid (Isolation Forest)", expand=True, title_style="bold blue")
        table.add_column("Component", style="cyan")
        table.add_column("Status")
        table.add_column("Current", justify="right")
        table.add_column("AI Score", justify="right")
        table.add_column("Confidence", justify="right")

        global_anomaly = any(bool((heads.get(name) or {}).get("anomaly", False)) for name in ("CPU", "MEMORY", "STORAGE", "NETWORK"))

        if not heads:
            wait = Text("WAIT...", style="dim")
            na = Text("N/A", style="dim")
            table.add_row(Text("[CPU]", style="cyan"), Text("[ NORMAL ]", style="dim"), wait, na, na)
            table.add_row(Text("[MEMORY]", style="cyan"), Text("[ NORMAL ]", style="dim"), wait, na, na)
            table.add_row(Text("[STORAGE]", style="cyan"), Text("[ NORMAL ]", style="dim"), wait, na, na)
            table.add_row(Text("[NETWORK]", style="cyan"), Text("[ NORMAL ]", style="dim"), wait, na, na)
            state_text = Text(f"\nEscalation State: Level {level}\nAction: {action}", style="bold green")
            panel_content = Table.grid(expand=True)
            panel_content.add_row(table)
            panel_content.add_row(Align.center(state_text))
            return Panel(panel_content, title="AI Inference", border_style="blue")

        def row_for(name, label, formatter):
            info = heads.get(name) or {}
            is_anomaly = bool(info.get("anomaly", False))
            value = info.get("value", 0.0)
            ai_score = info.get("ai_score", raw_score if raw_score is not None else 0.0)
            confidence = info.get("confidence", 0.0)
            try:
                value = float(value)
            except Exception:
                value = 0.0
            try:
                ai_score = float(ai_score)
            except Exception:
                ai_score = 0.0
            try:
                confidence = float(confidence)
            except Exception:
                confidence = 0.0

            if is_anomaly:
                current_style = "bold red"
                status_style = "bold red"
                comp_style = "bold red"
                status = Text("[ ANOMALY ]", style=status_style)
            else:
                current_style = "green"
                status_style = "bold green"
                comp_style = "cyan"
                status = Text("[ NORMAL ]", style=status_style)

            table.add_row(
                Text(f"[{label}]", style=comp_style),
                status,
                Text(formatter(value), style=current_style),
                Text(f"{ai_score:.4f}", style="dim"),
                Text(f"{confidence:.0%}", style="yellow" if is_anomaly else "dim"),
            )

        row_for("CPU", "CPU", lambda v: f"{v:.1f}%")
        row_for("MEMORY", "MEM", lambda v: f"{v:.1f}%")
        row_for("STORAGE", "STG", lambda v: f"{v:.1f}%")
        row_for("NETWORK", "NET", lambda v: f"{v:.1f}%")

        state_style = "bold white"
        if "REMEDIATING" in str(action):
            state_style = "bold yellow blink"
        if "ALERT" in str(action):
            state_style = "bold white on red blink"
        if "VERIFYING" in str(action) or "WARNING" in str(action):
            state_style = "bold yellow"
        if "WARMING UP" in str(action):
            state_style = "bold cyan"
        state_text = Text(f"\nEscalation State: Level {level}\nAction: {action}", style=state_style)

        stab_style = "bold yellow" if remaining > 0 else "dim green"
        stab_text = Text(f"\nStabilization Window: {remaining}s remaining", style=stab_style)

        prediction_line = Text(
            f"\nAI Prediction: {1 if global_anomaly else 0}  |  Model: Isolation Forest",
            style="bold cyan" if not global_anomaly else "bold red",
        )

        culprits_list = list(culprits or [])
        if culprits_list:
            culprits_text = " ".join([f"[{c}]" for c in culprits_list])
            culprits_line = Text(f"\nCulprits: {culprits_text}", style="bold red")
        else:
            culprits_line = Text("\nCulprits: -", style="dim")

        panel_content = Table.grid(expand=True)
        panel_content.add_row(table)
        panel_content.add_row(Align.center(prediction_line))
        panel_content.add_row(Align.center(state_text))
        panel_content.add_row(Align.center(culprits_line))
        panel_content.add_row(Align.center(stab_text))

        return Panel(panel_content, title="AI Inference", border_style="white")

    def _make_logs_panel(self):
        logs_text = Text()
        max_entries = max(1, min(12, (shutil.get_terminal_size(fallback=(80, 24)).lines // 3)))

        try:
            if self.remediation_logs:
                entries = list(self.remediation_logs)[-max_entries:]
                for entry in entries:
                    status = "Success" if entry.get("success") else "Fail"
                    metric = self._safe_str(entry.get("metric") or entry.get("culprit"))
                    level = self._safe_str(entry.get("level", "?"))
                    command = self._safe_str(entry.get("command"))
                    timestamp = self._safe_str(entry.get("timestamp"))
                    base_line = (
                        f"[{timestamp}] | {metric} | Level {level} | {command} | {status}"
                    )
                    style = "bold green" if entry.get("success") else "bold red"
                    wrapped = self._wrap_remediation_line(base_line)
                    for idx, chunk in enumerate(wrapped):
                        suffix = "\n" if idx == len(wrapped) - 1 else "\n"
                        logs_text.append(chunk + suffix, style=style)
            elif self.alert_locked or self.is_halted:
                logs_text.append(
                    "[HALT] Human Intervention Required — auto-healing circuit breaker engaged\n",
                    style="bold white on red",
                )
            else:
                logs_text.append("No remediation actions recorded yet.", style="dim")

            if self.mttr_seconds is not None:
                culprit = self.mttr_culprit or "UNKNOWN"
                mttr_line = f"Latest MTTR: {float(self.mttr_seconds):.3f}s (culprit={culprit})"
                for chunk in self._wrap_remediation_line(mttr_line):
                    logs_text.append("\n" + chunk, style="bold cyan")
        except Exception:
            logs_text = Text("Remediation log reflow guard active.", style="dim")

        return Panel(logs_text, title="Remediation Log", border_style="yellow")

    def _make_background_panel(self):
        logs = "\n".join(list(self.ui_messages)[-20:])
        logs_text = Text(logs if logs else "No background operations yet.", style="dim green")
        return Panel(logs_text, title="Background Operations", border_style="green")

    def refresh_operations(self):
        self.layout["right"].update(self._make_background_panel())

    def _make_footer(self):
        content = Text()
        content.append(f"[ SOURCE: {self.source_label} ]", style="bold cyan")
        if self.net_label:
            content.append("  ")
            content.append(f"[ NET: {self.net_label} ]", style="cyan")
        if self.stg_label:
            content.append("  ")
            content.append(f"[ STG: {self.stg_label} ]", style="cyan")
        content.append("  ")
        if self.telegram_active:
            content.append("[ TELEGRAM: ACTIVE ]", style="bold green")
        else:
            content.append("[ TELEGRAM: INACTIVE ]", style="dim")
        return Panel(Align.center(content), border_style="dim")

if __name__ == "__main__":
    # 1. Create a basic dummy configuration so the dashboard doesn't crash
    dummy_config = {"proxmox": {"node": "local-node", "vmid": "100"}}
    
    # 2. Initialize the dashboard blueprint
    dashboard = HealingDashboard(config=dummy_config)
    
    # 3. Launch the visual interface and keep it open
    with Live(dashboard.generate_layout(), refresh_per_second=4, screen=True) as live:
        try:
            while True:
                # Keep the screen alive and running
                time.sleep(1)
        except KeyboardInterrupt:
            # Allow the user to close it gracefully with Ctrl+C
            pass
