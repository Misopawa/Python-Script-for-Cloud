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
        self.layout["forensics"].update(Panel(Text.from_markup("System boot sequence initiated...", style="dim"), title="Anomaly Forensics (Last 10)", border_style="dim"))
        self.refresh_operations()
        self.layout["footer"].update(self._make_footer())

    def generate_layout(self):
        return self.layout

    def update_view(self, metrics, anomaly_score, escalation_level, action_name, stabilization_window, last_action_timestamp, is_connected=False, ui_messages=None, raw_score=None, decision_heads=None, cycle_count=None, culprits=None, next_calibration_in=None):
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
        self.layout["ai_brain"].update(self._make_ai_brain_panel(decision_heads, escalation_level, action_name, stabilization_window, last_action_timestamp, self.culprits, raw_score))
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

    def _make_ai_brain_panel(self, decision_heads, level, action, window, last_action, culprits, raw_score=None):
        current_time = time.time()
        time_diff = current_time - last_action
        remaining = max(0, int(window - time_diff)) if last_action > 0 else 0

        if level >= 5:
            content = Text("!!! MANUAL INTERVENTION REQUIRED: PRESS 'R' TO RESUME !!!", style="bold white on bright_red blink")
            return Panel(Align.center(content, vertical="middle"), title="System Status", border_style="bright_red")

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
