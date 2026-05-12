import os
import time
import pandas as pd
from datetime import datetime
from collections import deque
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
        self.study_timer = 172800  # 48 hours in seconds
        
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
        self.current_thresholds = {"CPU": 70.0, "MEMORY": 70.0, "STORAGE": 70.0, "NETWORK": 70.0}
        self.culprits = []
        self.next_calibration_in = None
        self.forensics_file = "anomalies_forensics.csv"
        self._stdin_fd = None
        self._stdin_old_settings = None

        # 3. Finally, initialize the visual layout
        from rich.console import Console
        from rich.layout import Layout
        self.console = Console()
        self.layout = Layout()
        
        # This call now has access to self.cycle_count and self.source_label
        self._setup_layout()

    def update_metrics(self):
        """Fetches live data and refreshes the TUI panels."""
        if not self.collector:
            return

        metrics = self.collector.get_metrics()
        cpu_val = metrics.get('CPU', 0.0)
        mem_val = metrics.get('MEMORY', 0.0)
        storage_val = metrics.get('STORAGE', 0.0)
        network_val = metrics.get('NETWORK', 0.0)

        suffix = "(I)" if self.study_timer > 0 else "(AI)"
        panel_text = Text.from_markup(
            f"[bold cyan]LIVE TELEMETRY[/bold cyan]\n"
            f"CPU Usage: {cpu_val:>5.2f}%\n"
            f"MEM Usage: {mem_val:>5.2f}%\n"
            f"Storage: {storage_val:>5.2f}%\n"
            f"Network: {network_val:>5.2f}%\n"
            f"Calibration: {self.format_timer(self.study_timer)}\n"
            f"[bold yellow]Current Healing Level: {self.current_healing_level}[/bold yellow]"
        )

        threshold_table = Table.grid(expand=True)
        threshold_table.add_column("Component", style="cyan")
        threshold_table.add_column("Threshold", justify="right", style="bold white")
        for name in ("CPU", "MEMORY", "STORAGE", "NETWORK"):
            threshold_table.add_row(f"{name}", f"{self.current_thresholds.get(name, 70.0):.1f}%{suffix}")

        panel_body = Table.grid(expand=True)
        panel_body.add_row(panel_text)
        panel_body.add_row(Text("Current Thresholds:", style="bold white"))
        panel_body.add_row(threshold_table)

        self.ui_messages.append("[INFO] Scraped metrics from 127.0.0.1:9090")

        self.layout["ai_brain"].update(Panel(panel_body, title="AI Decision Logic", border_style="cyan"))
        self.layout["footer"].update(Panel(Align.center(Text("[ SOURCE: 127.0.0.1:9090 ]  [ STATUS: CONNECTED ]", style="bold cyan")), border_style="dim"))
        self.refresh_operations()

        if self.study_timer > 0:
            self.study_timer -= 5

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
        self.layout["forensics"].update(Panel(Text.from_markup("System boot sequence initiated...", style="dim"), title="Anomaly Forensics (Last 10)", border_style="dim"))
        self.refresh_operations()
        self.layout["footer"].update(self._make_footer())

    def generate_layout(self):
        return self.layout

    def update_view(self, metrics, anomaly_score, threshold, escalation_level, action_name, stabilization_window, last_action_timestamp, is_connected=False, ui_messages=None, raw_score=None, decision_heads=None, cycle_count=None, culprits=None, next_calibration_in=None):
        if ui_messages:
            self.ui_messages.extend(list(ui_messages))
        if cycle_count is not None:
            try:
                self.cycle_count = int(cycle_count)
            except Exception:
                pass
        if escalation_level is not None:
            try:
                self.current_healing_level = int(escalation_level)
                self.current_level = int(escalation_level)
            except Exception:
                pass
        if decision_heads and isinstance(decision_heads, dict):
            for name in ("CPU", "MEMORY", "STORAGE", "NETWORK"):
                self.current_thresholds[name] = float((decision_heads.get(name) or {}).get("threshold", self.current_thresholds.get(name, 70.0)))
        elif threshold is not None:
            for name in ("CPU", "MEMORY", "STORAGE", "NETWORK"):
                self.current_thresholds[name] = float(threshold)
        if culprits is not None:
            try:
                self.culprits = list(culprits)
            except Exception:
                self.culprits = []
        if next_calibration_in is not None:
            try:
                self.next_calibration_in = int(next_calibration_in)
            except Exception:
                self.next_calibration_in = None
        self.layout["header"].update(self._make_header(True))
        self.layout["ai_brain"].update(self._make_ai_brain_panel(decision_heads, escalation_level, action_name, stabilization_window, last_action_timestamp, self.culprits, self.next_calibration_in))
        self.layout["forensics"].update(self._make_logs_panel())
        self.layout["right"].update(self._make_background_panel())
        self.layout["footer"].update(self._make_footer())
        return self.layout

    def _make_header(self, is_connected=False):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        node = self.config.get('proxmox', {}).get('node', 'pve')
        vmid = self.config.get('proxmox', {}).get('vmid', '101')
        
        if is_connected:
            status_text = Text(" [CONNECTED] ✔", style="bold green")
            title_style = "bold cyan"
        else:
            status_text = Text(" Initializing Connection...", style="bold cyan")
            title_style = "bold cyan"
            
        title = Text("AI-Powered Cloud Monitoring & Auto-Healing System", style=title_style)
        info = Text(f" [Time: {current_time}] [Node: {node}] [VMID: {vmid}] [Cycles: {self.cycle_count}]", style="white")
        
        header_content = title + status_text + info
        return Panel(Align.center(header_content), style="blue")

    def _make_ai_brain_panel(self, decision_heads, level, action, window, last_action, culprits, next_calibration_in):
        current_time = time.time()
        time_diff = current_time - last_action
        remaining = max(0, int(window - time_diff)) if last_action > 0 else 0

        if level >= 5:
            content = Text("!!! MANUAL INTERVENTION REQUIRED: PRESS 'R' TO RESUME !!!", style="bold white on bright_red blink")
            return Panel(Align.center(content, vertical="middle"), title="System Status", border_style="bright_red")

        heads = decision_heads or {}
        table = Table(title="Health Grid", expand=True, title_style="bold blue")
        table.add_column("Component", style="cyan")
        table.add_column("Status")
        table.add_column("Current", justify="right")
        table.add_column("Baseline", justify="right")
        table.add_column("Deviation", justify="right")
        table.add_column("Thresh", justify="right")

        if not heads:
            wait = Text("WAIT...", style="dim")
            na = Text("N/A", style="dim")
            thresh = Text("70.0(I)", style="dim")
            table.add_row(Text("[CPU]", style="cyan"), Text("[ NORMAL ]", style="dim"), wait, na, na, thresh)
            table.add_row(Text("[MEMORY]", style="cyan"), Text("[ NORMAL ]", style="dim"), wait, na, na, thresh)
            table.add_row(Text("[STORAGE]", style="cyan"), Text("[ NORMAL ]", style="dim"), wait, na, na, thresh)
            table.add_row(Text("[NETWORK]", style="cyan"), Text("[ NORMAL ]", style="dim"), wait, na, na, thresh)
            state_text = Text(f"\nEscalation State: Level {level}\nAction: {action}", style="bold green")
            threshold_summary = Table.grid(expand=True)
            threshold_summary.add_column("Metric", style="cyan")
            threshold_summary.add_column("Threshold", justify="right", style="bold white")
            for name in ("CPU", "MEMORY", "STORAGE", "NETWORK"):
                threshold_summary.add_row(name, f"{self.current_thresholds.get(name, 70.0):.1f}%")
            panel_content = Table.grid(expand=True)
            panel_content.add_row(table)
            panel_content.add_row(Text("Current Thresholds:", style="bold white"))
            panel_content.add_row(threshold_summary)
            panel_content.add_row(Align.center(state_text))
            return Panel(panel_content, title="System Status", border_style="blue")

        def row_for(name, label, formatter):
            info = heads.get(name) or {}
            is_anomaly = bool(info.get("anomaly", False))
            value = info.get("value", 0.0)
            baseline = info.get("baseline", 0.0)
            deviation = info.get("deviation", 0.0)
            threshold = info.get("threshold", 0.0)
            in_study_zone = bool(info.get("in_study_zone", False))
            study_active = bool(info.get("study_active", False))
            init_mode = bool(info.get("init_mode", False))
            if self.study_timer <= 0:
                init_mode = False
            site_down = bool(info.get("site_down", False)) if name == "NETWORK" else False
            try:
                value = float(value)
            except Exception:
                value = 0.0
            try:
                baseline = float(baseline)
            except Exception:
                baseline = 0.0
            try:
                deviation = float(deviation)
            except Exception:
                deviation = abs(value - baseline)
            try:
                threshold = float(threshold)
            except Exception:
                threshold = 0.0
            if init_mode:
                thresh_label = f"{threshold:.1f}(I)"
            elif study_active and threshold > 70.0:
                thresh_label = f"{threshold:.1f}(S)"
            else:
                thresh_label = f"{threshold:.1f}"

            current_style = "green"
            status_style = "bold green"
            comp_style = "cyan"
            if float(value) > float(threshold):
                current_style = "bold red"
                status_style = "bold red"
                comp_style = "bold red"
            elif float(value) > 70.0 and in_study_zone:
                current_style = "bold yellow"
                status_style = "bold yellow"
                comp_style = "bold yellow"

            if name == "NETWORK":
                latency_ms = 0.0
                retrans = 0.0
                speed_mbps = 0.0
                try:
                    latency_ms = float(info.get("latency_ms", 0.0) or 0.0)
                except Exception:
                    latency_ms = 0.0
                try:
                    retrans = float(info.get("retrans_per_sec", 0.0) or 0.0)
                except Exception:
                    retrans = 0.0
                try:
                    speed_mbps = float(info.get("speed_mbps", 0.0) or 0.0)
                except Exception:
                    speed_mbps = 0.0
                if site_down:
                    row_style = "bold white on bright_red blink"
                    status = Text("[ SITE DOWN ]", style=row_style)
                    current_text = Text("Unreachable", style=row_style)
                    baseline_text = Text("-", style=row_style)
                    deviation_text = Text("-", style=row_style)
                    threshold_text = Text("-", style=row_style)
                    comp = Text(f"[{label}]", style=row_style)
                else:
                    status = Text("[ ANOMALY ]" if float(value) > float(threshold) else "[ NORMAL ]", style=status_style)
                    if speed_mbps < 1.0:
                        pulse_value = speed_mbps * 1024.0
                        pulse_unit = "Kbps"
                    else:
                        pulse_value = speed_mbps
                        pulse_unit = "Mbps"
                    activity_style = current_style
                    if activity_style in ("green", "bold green") and speed_mbps > 0.0:
                        activity_style = "bold green"
                    current_text = Text(
                        f"Load: {value:.1f}% | Lat: {latency_ms:.0f}ms | Ret: {retrans:.2f}/s | Pulse: {pulse_value:.2f} {pulse_unit}",
                        style=activity_style,
                    )
                    baseline_text = Text(f"{baseline:.1f}%", style="dim")
                    deviation_text = Text(f"{abs(float(deviation)):.1f}%", style="yellow")
                    threshold_text = Text(f"{thresh_label}%", style="dim")
                    comp = Text(f"[{label}]", style=comp_style)
            else:
                status = Text("[ ANOMALY ]" if float(value) > float(threshold) else "[ NORMAL ]", style=status_style)
                current_text = Text(formatter(value), style=current_style)
                baseline_text = Text(formatter(baseline), style="dim")
                deviation_text = Text(f"{abs(float(deviation)):.1f}%", style="yellow")
                threshold_text = Text(f"{thresh_label}%", style="dim")
                comp = Text(f"[{label}]", style=comp_style)
            table.add_row(comp, status, current_text, baseline_text, deviation_text, threshold_text)

        row_for("CPU", "CPU", lambda v: f"{v:.1f}%")
        row_for("MEMORY", "MEM", lambda v: f"{v:.1f}%")
        row_for("STORAGE", "STG", lambda v: f"{v:.1f}%")
        row_for("NETWORK", "NET", lambda v: f"{v:.1f}%")

        state_style = "bold white"
        if "VERIFYING" in str(action) or "WARNING" in str(action):
            state_style = "bold yellow"
        if "WARMING UP" in str(action):
            state_style = "bold cyan"
        state_text = Text(f"\nEscalation State: Level {level}\nAction: {action}", style=state_style)

        stab_style = "bold yellow" if remaining > 0 else "dim green"
        stab_text = Text(f"\nStabilization Window: {remaining}s remaining", style=stab_style)

        if next_calibration_in is None:
            calib_line = Text("\nNext Calibration: -", style="dim")
        else:
            hours = int(next_calibration_in // 3600)
            minutes = int((next_calibration_in % 3600) // 60)
            seconds = int(next_calibration_in % 60)
            calib_line = Text(f"\nNext Calibration: {hours:02d}:{minutes:02d}:{seconds:02d}", style="dim cyan")

        culprits_list = list(culprits or [])
        if culprits_list:
            culprits_text = " ".join([f"[{c}]" for c in culprits_list])
            culprits_line = Text(f"\nCulprits: {culprits_text}", style="bold red")
        else:
            culprits_line = Text("\nCulprits: -", style="dim")

        threshold_summary = Table.grid(expand=True)
        threshold_summary.add_column("Metric", style="cyan")
        threshold_summary.add_column("Threshold", justify="right", style="bold white")
        for name in ("CPU", "MEMORY", "STORAGE", "NETWORK"):
            threshold_summary.add_row(name, f"{self.current_thresholds.get(name, 70.0):.1f}%")

        panel_content = Table.grid(expand=True)
        panel_content.add_row(table)
        panel_content.add_row(Text("Current Thresholds:", style="bold white"))
        panel_content.add_row(threshold_summary)
        panel_content.add_row(Align.center(state_text))
        panel_content.add_row(Align.center(calib_line))
        panel_content.add_row(Align.center(culprits_line))
        panel_content.add_row(Align.center(stab_text))

        return Panel(panel_content, title="Decision Heads", border_style="white")

    def _make_logs_panel(self):
        logs_text = Text()
        if self.ui_messages:
            for msg in list(self.ui_messages)[-10:]:
                logs_text.append(str(msg) + "\n", style="dim white")
            logs_text.append("\n")
        if os.path.exists(self.forensics_file):
            try:
                df = pd.read_csv(self.forensics_file).tail(10)
                for _, row in df.iterrows():
                    ts = row['timestamp']
                    score = row['anomaly_score']
                    level = int(row['executed_level'])
                    line = f"[{ts}] Score: {score:.4f} | Executed Level {level}\n"
                    logs_text.append(line, style="dim white")
            except Exception:
                logs_text = Text("Waiting for forensic data...", style="dim")
        else:
            logs_text = Text("No anomalies recorded yet.", style="dim")
            
        return Panel(logs_text, title="Anomaly Forensics (Last 10)", border_style="white")

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
