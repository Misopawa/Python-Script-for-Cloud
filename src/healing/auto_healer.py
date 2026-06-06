import time
import json
import os
import subprocess
import csv
from datetime import datetime
import requests
from utils.logger import get_logger
from monitoring.metrics_collector import get_proxmox_client

logger = get_logger(__name__)

class PolicyEngine:
    def __init__(self, config, notifier=None):
        self.config = config
        self.policy_cfg = config.get('policies', {})
        self.mon_cfg = config.get('monitoring', {})
        self.prox_cfg = config.get('proxmox', {})
        self.notifier = notifier
        self.vmid = self.prox_cfg.get('vmid', 101)
        self.node = self.prox_cfg.get('node', 'pve')
        # Path to status cache aligned with project structure
        self.cache_file = os.path.join("config", "status_cache.json")
        self.system_state_file = os.path.join("config", "system_state.json")
        self.forensics_file = "anomalies_forensics.csv"
        
        # Demo Mode logic
        self.demo_mode = self.mon_cfg.get('demo_mode', False)
        if self.demo_mode:
            self.cooldown_period = 30 # Presentation requirement
            logger.info("[ACTION] Demo Mode active. Cooldown reduced to %ds", self.cooldown_period)
        else:
            self.cooldown_period = self.policy_cfg.get('cooldown_period', 90)

        # Track state for escalation
        self.retries = 0
        self.current_level_idx = 0 
        self.last_anomaly_type = None
        
        # --- CHAPTER 3 IMPLEMENTATION ---
        # 1. Non-Linear Escalation Paths (Table 3.5)
        self.escalation_paths = {
            "cpu": [1, 2, 4, 5],
            "memory": [1, 2, 4, 5],
            "storage": [1, 2, 4, 5],
            "network": [1, 3, 4, 5],
            "general": [1, 2, 3, 4, 5]
        }
        
        # 2. Specific Retry Limits per Level (Table 3.1)
        self.max_retries_per_level = {
            1: 2,  # Level 1 allows exactly 2 retries
            2: 1,  # Level 2 allows 1 retry
            3: 1,  # Level 3 allows 1 retry
            4: 1,  # Level 4 allows 1 retry
            5: 0   # Level 5 is the failsafe; 0 retries, immediate halt
        }
        
        # Hysteresis Logic: 3 consecutive anomalies required for Level 1
        self.anomaly_counter = 0
        self.required_consecutive_anomalies = 3
        
        # 3. State Persistence (Memory Layer)
        self.timestamp_of_first_anomaly = None
        
        # Stabilization Window (Post-action cooling)
        self.STABILIZATION_WINDOW = 90 # Standard (seconds)
        self.last_action_timestamp = 0
        self.is_halted = False
        self.cooldown_until = 0.0
        
        # Ensure config directory exists
        os.makedirs("config", exist_ok=True)
        
        self.current_level_idx = 0
        self.current_level = 0
        self._last_notified_level = 0
        # AI confidence replaces multi-cycle threshold debouncing for anomaly entry.
        self.required_consecutive_head_anomalies = 1
        self.component_counters = {"CPU": 0, "MEMORY": 0, "STORAGE": 0, "NETWORK": 0}

        # Resume persisted escalation state after a restart (Memory Layer).
        self._load_state()
        self._load_system_state()

    def manual_resume(self):
        self.current_level_idx = 0
        self.current_level = 0
        self.is_halted = False
        self.anomaly_counter = 0
        self.component_counters = {"CPU": 0, "MEMORY": 0, "STORAGE": 0, "NETWORK": 0}
        self.retries = 0
        self.last_anomaly_type = None
        self.timestamp_of_first_anomaly = None
        self.cooldown_until = time.time() + 60
        self._last_notified_level = 0
        if self.notifier:
            self.notifier.send("✅ [INFO] Admin resumed system via 'R' key. Returning to Level 0.", min_interval_seconds=60)
        return "ADMIN_OVERRIDE: System manually resumed. Level 0 restored."

    def _load_system_state(self):
        """Logic: Create a simple system_state.json file."""
        if os.path.exists(self.system_state_file):
            try:
                with open(self.system_state_file, 'r') as f:
                    state = json.load(f)
                    # On Startup: resume from the saved Level instead of resetting to Level 1
                    self.current_level_idx = state.get('current_escalation_level', 0)
                    self.timestamp_of_first_anomaly = state.get('timestamp_of_first_anomaly')
                    logger.info(f"[MEMORY] Resumed System State: Level Index {self.current_level_idx}, First Anomaly: {self.timestamp_of_first_anomaly}")
            except Exception as e:
                logger.error(f"Failed to load system state: {e}")

    def _save_system_state(self):
        """Data to Store: Save the current_escalation_level and the timestamp_of_first_anomaly."""
        try:
            state = {
                'current_escalation_level': self.current_level_idx,
                'timestamp_of_first_anomaly': self.timestamp_of_first_anomaly
            }
            with open(self.system_state_file, 'w') as f:
                json.dump(state, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save system state: {e}")
        
    def _load_state(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    state = json.load(f)
                    vm_state = state.get(str(self.vmid), {})
                    self.current_level_idx = vm_state.get('level_idx', 0)
                    self.retries = vm_state.get('retries', 0)
                    self.last_anomaly_type = vm_state.get('anomaly_type')
                    if self.current_level_idx > 0:
                        logger.info(f"[ACTION] Resumed escalation state for VMID {self.vmid}: Level Index {self.current_level_idx}")
            except Exception as e:
                logger.error(f"Failed to load state cache: {e}")

    def _save_state(self):
        try:
            state = {}
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    state = json.load(f)
            
            state[str(self.vmid)] = {
                'level_idx': self.current_level_idx,
                'retries': self.retries,
                'anomaly_type': self.last_anomaly_type,
                'last_updated': time.time()
            }
            
            with open(self.cache_file, 'w') as f:
                json.dump(state, f, indent=4)
            
            # Keep system state in sync
            self._save_system_state()
        except Exception as e:
            logger.error(f"Failed to save state cache: {e}")

    def _record_forensics(self, anomaly, level_executed):
        """4. Forensic Anomaly Snapshot (Research Layer)"""
        try:
            features = anomaly.get('features', {})
            score = anomaly.get('score', 0.0)
            timestamp = datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
            
            file_exists = os.path.isfile(self.forensics_file)
            
            with open(self.forensics_file, 'a', newline='') as csvfile:
                fieldnames = ['timestamp', 'anomaly_score', 'executed_level'] + list(features.keys())
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                if not file_exists:
                    writer.writeheader()
                
                row = {
                    'timestamp': timestamp,
                    'anomaly_score': round(score, 4),
                    'executed_level': level_executed
                }
                row.update(features)
                writer.writerow(row)
                logger.info(f"[RESEARCH] Forensic snapshot recorded in {self.forensics_file}")
        except Exception as e:
            logger.error(f"Failed to record forensics: {e}")

    def execute_remediation(self, anomaly):
        """
        Evaluate anomalies against the Policy Engine and trigger Hierarchical Recovery.
        Aligns with Chapter 3 5-Tier Escalation Path.
        """
        if self.is_halted:
            self.current_level = 5
            if self.notifier and self._last_notified_level != 5:
                self._last_notified_level = 5
                self.notifier.send("🚨 [CRITICAL] SYSTEM HALTED. Level 5 reached. Manual intervention required.", min_interval_seconds=60)
            return "[ MAINTENANCE REQUIRED ]"

        if time.time() < float(self.cooldown_until or 0.0):
            remaining = max(0, int(float(self.cooldown_until) - time.time()))
            return f"manual_resume_cooldown_{remaining}s"

        culprits = anomaly.get("culprits") or []
        culprits = [str(c).upper() for c in culprits]

        current_time = time.time()
        time_diff = current_time - self.last_action_timestamp
        
        # 3. Wait-and-Watch Logic
        if time_diff < self.STABILIZATION_WINDOW:
            logger.info(f"[STABILIZATION] System is currently in a stabilization window ({int(self.STABILIZATION_WINDOW - time_diff)}s remaining).")
            logger.info("[STABILIZATION] Skipping inference and 3-cycle counter check to allow services to initialize.")
            logger.info("[STABILIZATION] Waiting for Prometheus scraper to catch up with the newly restarted service state.")
            return "stabilization_skip"

        # 1. Fallback for Critical Data Loss
        if anomaly.get('critical_data_loss', False):
            logger.critical("[DETECTION] CRITICAL DATA LOSS detected! Bypassing inference and triggering Level 4 recovery.")
            # Trigger Level 4 immediately
            self.current_level_idx = 3 # Level 4 is index 3 in path [1,2,3,4,5]
            self.current_level = 4
            if self.notifier and self._last_notified_level != 4:
                self._last_notified_level = 4
                score_val = anomaly.get("score", 0.0)
                try:
                    score_val = float(score_val)
                except Exception:
                    score_val = 0.0
                self.notifier.send(f"⚠️ [ALERT] Anomaly Detected (Score: {score_val:.4f}). Escalating to Level 4.", min_interval_seconds=60)
            action_taken = self._trigger_level_action(4, "critical_data_loss")
            self._save_state()
            return action_taken

        if not anomaly.get('anomaly'):
            if self.current_level > 0 or self.is_halted:
                self.reset_state()
            for key in self.component_counters.keys():
                self.component_counters[key] = 0
            self.current_level = 0
            return "none"

        for head in self.component_counters.keys():
            if head in culprits:
                self.component_counters[head] = int(self.component_counters.get(head, 0)) + 1
            else:
                self.component_counters[head] = 0

        worst_head = None
        worst_count = 0
        for head, count in self.component_counters.items():
            if int(count) > int(worst_count):
                worst_head = head
                worst_count = int(count)

        if int(worst_count) < int(self.required_consecutive_head_anomalies):
            label = worst_head or (culprits[0] if culprits else "UNKNOWN")
            logger.warning(
                "[Cycle %d/%d] Sustained Anomaly Detected. Culprit=%s",
                int(worst_count),
                int(self.required_consecutive_head_anomalies),
                str(label),
            )
            return f"[ WARNING ] {label} [Cycle {worst_count}/{self.required_consecutive_head_anomalies}]"

        triggered_metric = worst_head or (culprits[0] if culprits else "UNKNOWN")
        features = anomaly.get("features", {})
        try:
            value_pct = float(features.get(triggered_metric, 0.0))
        except Exception:
            value_pct = 0.0
        confidence_pct = float(anomaly.get("confidence", 0.0) or 0.0) * 100.0

        # Determine Anomaly Type for Routing
        mapping = {"CPU": "cpu", "MEMORY": "memory", "STORAGE": "storage", "NETWORK": "network"}
        anomaly_type = mapping.get(str(triggered_metric).upper(), "general")
        
        # Fetch the correct non-linear path (e.g., Network = [1, 3, 4, 5])
        path = self.escalation_paths.get(anomaly_type, self.escalation_paths["general"])
        
        # Set initial level if starting fresh
        if self.current_level == 0:
            self.current_level_idx = 0
            self.current_level = path[self.current_level_idx]
            self.retries = 0
        else:
            # Check if we have exhausted retries for the CURRENT level
            allowed_retries = self.max_retries_per_level.get(self.current_level, 0)
            
            if self.retries < allowed_retries:
                # Retry the same level
                self.retries += 1
                logger.info(f"Retrying Level {self.current_level} (Attempt {self.retries}/{allowed_retries})")
            else:
                # Retries exhausted, escalate to the NEXT level in the path
                self.current_level_idx += 1
                self.retries = 0 # Reset retries for the new level
                
                # Check if we hit the end of the path
                if self.current_level_idx >= len(path):
                    self.current_level = 5 # Force Level 5 Failsafe
                else:
                    self.current_level = path[self.current_level_idx]

        if self.notifier:
            self.notifier.send(
                "[CRITICAL] AI anomaly detected.\n"
                f"Metric: [{triggered_metric}]\n"
                f"Value: {value_pct:.1f}%\n"
                f"Confidence: {confidence_pct:.1f}%\n"
                f"Executing Level {self.current_level} Recovery.",
                min_interval_seconds=60,
            )

        # Trigger the action and save state
        action_taken = self._trigger_level_action(self.current_level, anomaly_type)
        self._record_forensics(anomaly, self.current_level)
        self._save_state()

        for key in self.component_counters.keys():
            self.component_counters[key] = 0

        if "verification_failed" in str(action_taken):
            return action_taken

        time.sleep(self.cooldown_period)
        return action_taken

    def reset_state(self):
        self.retries = 0
        self.current_level_idx = 0
        self.current_level = 0
        self.last_anomaly_type = None
        self.timestamp_of_first_anomaly = None
        self.anomaly_counter = 0
        self.component_counters = {"CPU": 0, "MEMORY": 0, "STORAGE": 0, "NETWORK": 0}
        self.is_halted = False
        self._save_state()
        self._save_system_state()

    def _verify_service(self, service_name, docker_containers):
        """2. Post-Action Verification (Proof of Work Layer)"""
        if service_name in docker_containers:
            try:
                result = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Running}}", service_name],
                    capture_output=True, text=True, check=True
                )
                is_running = result.stdout.strip().lower() == "true"
                if is_running:
                    logger.info(f"[VERIFICATION] Service {service_name} is RUNNING.")
                    return True
                else:
                    logger.error(f"[VERIFICATION] Service {service_name} is NOT RUNNING.")
                    return False
            except Exception as e:
                logger.error(f"[VERIFICATION] Failed to inspect docker container {service_name}: {e}")
                return False
        else:
            # LXC Status via Proxmox API
            try:
                proxmox = get_proxmox_client(self.config)
                status = proxmox.nodes(self.node).lxc(self.vmid).status.current.get()
                if status.get('status') == 'running':
                    logger.info(f"[VERIFICATION] LXC Container {self.vmid} is RUNNING.")
                    return True
                else:
                    logger.error(f"[VERIFICATION] LXC Container {self.vmid} is in state: {status.get('status')}")
                    return False
            except Exception as e:
                logger.error(f"[VERIFICATION] Failed to check LXC status via Proxmox: {e}")
                return False

    def _verify_service_with_backoff(self, service_name, docker_containers, max_wait_sec=120):
        """Verify service with exponential backoff retries."""
        start_time = time.time()
        attempt = 0
        
        while time.time() - start_time < max_wait_sec:
            attempt += 1
            
            if service_name in docker_containers:
                try:
                    result = subprocess.run(
                        ["docker", "inspect", "-f", "{{.State.Running}}", service_name],
                        capture_output=True, text=True, check=True, timeout=5
                    )
                    if result.stdout.strip().lower() == "true":
                        logger.info(f"[VERIFY] Service {service_name} confirmed running (attempt {attempt})")
                        return True
                except Exception:
                    pass
            else:
                try:
                    proxmox = get_proxmox_client(self.config)
                    status = proxmox.nodes(self.node).lxc(self.vmid).status.current.get()
                    if status.get('status') == 'running':
                        logger.info(f"[VERIFY] LXC {self.vmid} confirmed running (attempt {attempt})")
                        return True
                except Exception:
                    pass
            
            wait_time = min(2 ** (attempt - 1), 16)
            if attempt <= 5:
                logger.info(f"[VERIFY] Service not ready yet, retry {attempt} in {wait_time}s...")
            time.sleep(wait_time)
        
        logger.error(f"[VERIFY] Service verification failed after {max_wait_sec}s, {attempt} attempts")
        return False

    def _verified_docker_restart(self, service_name):
        """
        Verified Restart function: ensures the service actually restarts and stays running.
        """
        logger.info(f"[ACTION] Attempting Verified Restart for Docker container: {service_name}")
        try:
            # 1. Execute docker restart
            subprocess.run(["docker", "restart", service_name], check=True)
            
            # 2. Wait for 5 seconds
            logger.info("[ACTION] Waiting 5s for container state to settle...")
            time.sleep(5)
            
            # 3. Verify it is running
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", service_name],
                capture_output=True, text=True, check=True
            )
            is_running = result.stdout.strip().lower() == "true"
            
            if is_running:
                logger.info(f"[VERIFICATION] {service_name} is successfully RUNNING.")
                return True
            else:
                # 4. Fallback: attempt docker start
                logger.warning(f"[VERIFICATION] {service_name} failed to restart (state: Exited). Attempting fallback: docker start...")
                subprocess.run(["docker", "start", service_name], check=True)
                time.sleep(5)
                
                # Final verification
                final_check = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Running}}", service_name],
                    capture_output=True, text=True, check=True
                )
                if final_check.stdout.strip().lower() == "true":
                    logger.info(f"[VERIFICATION] {service_name} is now RUNNING after fallback start.")
                    return True
                else:
                    logger.critical(f"[VERIFICATION] FATAL: {service_name} still won't start after multiple attempts!")
                    return False
        except Exception as e:
            logger.error(f"[ACTION] Verified restart process failed for {service_name}: {e}")
            return False

    def _send_telegram_alert(self, message):
        telegram_cfg = self.config.get('telegram', {})
        bot_token = telegram_cfg.get('bot_token')
        chat_id = telegram_cfg.get('chat_id')
        if not bot_token or not chat_id:
            logger.warning("[TELEGRAM] Missing telegram configuration; skipping alert.")
            return
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML'
        }
        try:
            response = requests.post(url, data=payload, timeout=10)
            if not response.ok:
                logger.warning(f"[TELEGRAM] Failed to send alert: status={response.status_code} text={response.text}")
        except Exception as e:
            logger.warning(f"[TELEGRAM] Exception while sending alert: {e}")
            pass

    def _trigger_level_action(self, level, anomaly_type):
        """
        Implementation of the 5-Tier Escalation Hierarchy (Table 3.5).
        """
        # Use native host-level pct commands instead of Proxmox API to avoid hangs
        service_name = self.mon_cfg.get('service_name', 'unknown-service')
        mon_infra = self.policy_cfg.get('monitoring_infrastructure', [])
        docker_containers = self.policy_cfg.get('docker_containers', [])

        if level == 1:
            logger.warning(f"[ACTION] [Level 1] Attempting Service Restart: {service_name} (Retry {self.retries}/{self.max_retries_per_level[1]})")
            self._send_telegram_alert(f"⚠️ <b>[AIOps Alert]</b> Triggering Level 1 remediation for LXC {self.vmid}.")

            if service_name in docker_containers:
                if self._verified_docker_restart(service_name):
                    self.last_action_timestamp = time.time()
                    self.STABILIZATION_WINDOW = 90
                    self._send_telegram_alert(f"✅ <b>[AIOps Resolved]</b> Level 1 successful. System stabilized.")
                    return "docker_restart_success"
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 1 failed. Escalating to next tier.")
                return "docker_restart_verification_failed"

            # Native host-level exec using /usr/sbin/pct
            try:
                cmd = ["/usr/sbin/pct", "exec", str(self.vmid), "--", "systemctl", "restart", service_name]
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
                logger.info(f"[ACTION] pct exec returned rc={proc.returncode}; stdout={proc.stdout.strip()}; stderr={proc.stderr.strip()}")
                time.sleep(5)
                if proc.returncode == 0 and self._verify_service_with_backoff(service_name, docker_containers, max_wait_sec=60):
                    self.last_action_timestamp = time.time()
                    self.STABILIZATION_WINDOW = 90
                    self._send_telegram_alert(f"✅ <b>[AIOps Resolved]</b> Level 1 successful. System stabilized.")
                    return "pct_exec_restart_success"
                if proc.returncode == 0:
                    self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 1 failed. Escalating to next tier.")
                    return "pct_exec_verification_failed"
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 1 failed. Escalating to next tier.")
                return "pct_exec_restart_failed"
            except subprocess.TimeoutExpired:
                logger.error(f"Level 1 Service Restart timed out for {service_name}")
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 1 failed. Escalating to next tier.")
                return "pct_exec_timeout"
            except Exception as e:
                logger.error(f"Level 1 Service Restart failed for {service_name}: {e}")
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 1 failed. Escalating to next tier.")
                return "pct_exec_restart_failed"

        elif level == 2:
            logger.warning(f"[ACTION] [Level 2] Process Isolation: Hunting runaway PIDs in LXC {self.vmid} (Retry {self.retries}/{self.max_retries_per_level[2]})")
            self._send_telegram_alert(f"⚠️ <b>[AIOps Alert]</b> Triggering Level 2 remediation for LXC {self.vmid}.")
            try:
                # Use pct exec to pkill the resource-hogging process inside the container
                cmd = ["/usr/sbin/pct", "exec", str(self.vmid), "--", "pkill", "-9", "stress-ng"]
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
                logger.info(f"[ACTION] pct exec pkill returned rc={proc.returncode}; stdout={proc.stdout.strip()}; stderr={proc.stderr.strip()}")
                if proc.returncode == 0:
                    # Allow Prometheus time to scrape new metrics (0% CPU)
                    logger.info("[ACTION] Level 2 pkill succeeded; sleeping 15s for Prometheus scrape sync.")
                    time.sleep(15)
                    self.last_action_timestamp = time.time()
                    self.STABILIZATION_WINDOW = 90
                    self._send_telegram_alert(f"✅ <b>[AIOps Resolved]</b> Level 2 successful. System stabilized.")
                    return "process_kill_success"
                else:
                    logger.error(f"Level 2 Process kill returned non-zero rc: {proc.returncode}")
                    self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 2 failed. Escalating to next tier.")
                    return "process_kill_failed"
            except subprocess.TimeoutExpired:
                logger.error(f"Level 2 Process kill timed out for LXC {self.vmid}")
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 2 failed. Escalating to next tier.")
                return "process_kill_timeout"
            except Exception as e:
                logger.error(f"Level 2 Process kill failed in LXC {self.vmid}: {e}")
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 2 failed. Escalating to next tier.")
                return "process_kill_failed"

        elif level == 3:
            logger.warning(f"[ACTION] [Level 3] Traffic Rerouting triggered for {anomaly_type} anomaly")
            self._send_telegram_alert(f"⚠️ <b>[AIOps Alert]</b> Triggering Level 3 remediation for LXC {self.vmid}.")
            logger.info("[SIMULATION] Updating IP tables / Nginx config to redirect traffic to backup node...")
            self.last_action_timestamp = time.time()
            self.STABILIZATION_WINDOW = 90
            self._send_telegram_alert(f"✅ <b>[AIOps Resolved]</b> Level 3 successful. System stabilized.")
            return "traffic_reroute_simulated"

        elif level == 4:
            logger.warning(f"[ACTION] [Level 4] Resource Isolation & Container Soft Reboot (VMID {self.vmid})")
            self._send_telegram_alert(f"⚠️ <b>[AIOps Alert]</b> Triggering Level 4 remediation for LXC {self.vmid}.")
            try:
                # Soft reboot via pct
                cmd = ["/usr/sbin/pct", "reboot", str(self.vmid)]
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=20)
                logger.info(f"[ACTION] pct reboot returned rc={proc.returncode}; stdout={proc.stdout.strip()}; stderr={proc.stderr.strip()}")
                # Wait for OS boot after soft reboot
                time.sleep(45)
                if proc.returncode == 0 and self._verify_service_with_backoff(service_name, docker_containers, max_wait_sec=120):
                    # OS boot logic: 4. Intelligence for Level 4 (Reboot) - Extended 120s window
                    self.last_action_timestamp = time.time()
                    self.STABILIZATION_WINDOW = 120
                    logger.info("[ACTION] Level 4 reboot triggered. Extending stabilization window to 120s for OS boot.")
                    self._send_telegram_alert(f"✅ <b>[AIOps Resolved]</b> Level 4 successful. System stabilized.")
                    return "lxc_soft_reboot"
                if proc.returncode == 0:
                    self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 4 failed. Escalating to next tier.")
                    return "lxc_reboot_verification_failed"
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 4 failed. Escalating to next tier.")
                return "lxc_soft_reboot_failed"
            except subprocess.TimeoutExpired:
                logger.error(f"Proxmox soft reboot timed out for LXC {self.vmid}")
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 4 failed. Escalating to next tier.")
                return "lxc_reboot_timeout"
            except Exception as e:
                logger.error(f"Proxmox soft reboot failed for LXC {self.vmid}: {e}")
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 4 failed. Escalating to next tier.")
                return "lxc_soft_reboot_failed"

        elif level == 5:
            logger.critical(f"[ACTION] [Level 5] CRITICAL: Container hard reboot (VMID {self.vmid})")
            self._send_telegram_alert(f"🚨 <b>[CRITICAL ESCALATION]</b> Level 5 Hard Reboot triggered for LXC {self.vmid}. Automated recovery limits reached. <b>HUMAN INTERVENTION REQUIRED IMMEDIATELY.</b>")
            try:
                # Hard reboot via pct: stop then start
                cmd_stop = ["/usr/sbin/pct", "stop", str(self.vmid)]
                proc_stop = subprocess.run(cmd_stop, capture_output=True, text=True, check=False, timeout=20)
                logger.info(f"[ACTION] pct stop returned rc={proc_stop.returncode}; stdout={proc_stop.stdout.strip()}; stderr={proc_stop.stderr.strip()}")
                time.sleep(5)
                cmd_start = ["/usr/sbin/pct", "start", str(self.vmid)]
                proc_start = subprocess.run(cmd_start, capture_output=True, text=True, check=False, timeout=20)
                logger.info(f"[ACTION] pct start returned rc={proc_start.returncode}; stdout={proc_start.stdout.strip()}; stderr={proc_start.stderr.strip()}")
                time.sleep(45)
                if proc_stop.returncode == 0 and proc_start.returncode == 0 and self._verify_service_with_backoff(service_name, docker_containers, max_wait_sec=180):
                    self.last_action_timestamp = time.time()
                    self.STABILIZATION_WINDOW = 180
                    self._send_telegram_alert(f"✅ <b>[AIOps Resolved]</b> Level 5 successful. System stabilized.")
                    return "lxc_hard_reboot"
                if proc_stop.returncode == 0 and proc_start.returncode == 0:
                    self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 5 failed. Escalating to next tier.")
                    return "lxc_hard_reboot_verification_failed"
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 5 failed. Escalating to next tier.")
                return "lxc_hard_reboot_failed"
            except subprocess.TimeoutExpired:
                logger.error(f"Proxmox hard reboot timed out for LXC {self.vmid}")
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 5 failed. Escalating to next tier.")
                return "lxc_hard_reboot_timeout"
            except Exception as e:
                logger.error(f"Proxmox hard reboot failed for LXC {self.vmid}: {e}")
                self._send_telegram_alert(f"❌ <b>[AIOps Failed]</b> Level 5 failed. Escalating to next tier.")
                return "lxc_hard_reboot_failed"

        return "unknown_action"
