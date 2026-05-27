import time
import json
import os
import subprocess
import csv
from datetime import datetime
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
        self.threshold_file = os.path.join("config", "threshold.json")
        self.threshold = self._load_threshold()
        
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
        self.required_consecutive_head_anomalies = 5
        self.component_counters = {"CPU": 0, "MEMORY": 0, "STORAGE": 0, "NETWORK": 0}

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

    def _load_threshold(self):
        try:
            if os.path.exists(self.threshold_file):
                with open(self.threshold_file, "r") as f:
                    data = json.load(f) or {}
                if "threshold" in data:
                    return float(data["threshold"])
        except Exception as e:
            logger.error(f"Failed to load dynamic threshold: {e}")
        return float(self.config.get("ai", {}).get("anomaly_threshold", -0.75))

    def update_dynamic_threshold(self, history_file=None):
        if not history_file:
            history_file = os.path.join("data", "historical_scores.csv")
        if not os.path.exists(history_file):
            return None

        scores = []
        try:
            with open(history_file, "r", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        scores.append(float(row.get("score", 0) or 0))
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"Failed to read historical scores: {e}")
            return None

        if not scores:
            return None

        avg_score = sum(scores) / len(scores)
        max_score = max(scores)
        new_threshold = min(max_score * 0.90, avg_score * 0.80)
        self.threshold = float(new_threshold)

        try:
            os.makedirs(os.path.dirname(self.threshold_file), exist_ok=True)
            payload = {
                "threshold": self.threshold,
                "updated_at": time.time(),
                "avg_score": float(avg_score),
                "max_score": float(max_score),
                "n": int(len(scores)),
            }
            with open(self.threshold_file, "w") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save dynamic threshold: {e}")

        return self.threshold
        
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
        head_info = (heads.get(triggered_metric) or {}) if isinstance(heads, dict) else {}
        value_pct = head_info.get("value", None)
        threshold_pct = head_info.get("threshold", None)
        study_active = bool(head_info.get("study_active", False))
        try:
            value_pct = float(value_pct)
        except Exception:
            value_pct = 0.0
        try:
            threshold_pct = float(threshold_pct)
        except Exception:
            threshold_pct = 70.0

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
            learned_text = "Learned from high-load study" if study_active else "Fixed floor"
            self.notifier.send(
                "[CRITICAL] Anomaly Sustained for 5 cycles.\n"
                f"Metric: [{triggered_metric}]\n"
                f"Value: {value_pct:.1f}%\n"
                f"Limit: {threshold_pct:.1f}% ({learned_text})\n"
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

    def _trigger_level_action(self, level, anomaly_type):
        """
        Implementation of the 5-Tier Escalation Hierarchy (Table 3.5).
        """
        proxmox = get_proxmox_client(self.config)
        service_name = self.mon_cfg.get('service_name', 'unknown-service')
        mon_infra = self.policy_cfg.get('monitoring_infrastructure', [])
        docker_containers = self.policy_cfg.get('docker_containers', [])

        if level == 1:
            logger.warning(f"[ACTION] [Level 1] Attempting Service Restart: {service_name} (Retry {self.retries}/{self.max_retries_per_level[1]})")
            
            if service_name in docker_containers:
                if self._verified_docker_restart(service_name):
                    self.last_action_timestamp = time.time()
                    self.STABILIZATION_WINDOW = 90
                    return "docker_restart_success"
                return "docker_restart_verification_failed"
            
            try:
                # Remote SSH / Proxmox execution to restart the service gently
                proxmox.nodes(self.node).lxc(self.vmid).exec.post(command=f"systemctl restart {service_name}")
                time.sleep(5)
                if self._verify_service(service_name, docker_containers):
                    self.last_action_timestamp = time.time()
                    self.STABILIZATION_WINDOW = 90
                    return "pct_exec_restart_success"
                return "pct_exec_verification_failed"
            except Exception as e:
                logger.error(f"Level 1 Service Restart failed for {service_name}: {e}")
                return "pct_exec_restart_failed"
            
        elif level == 2:
            logger.warning(f"[ACTION] [Level 2] Process Isolation: Hunting runaway PIDs in LXC {self.vmid} (Retry {self.retries}/{self.max_retries_per_level[2]})")
            try:
                # Aggressive bash command to find and kill the highest CPU consumer
                cmd = "ps -eo pid,ppid,%cpu,%mem,comm --sort=-%cpu | head -n 2 | tail -n 1 | awk '{print $1}'"
                proxmox.nodes(self.node).lxc(self.vmid).exec.post(command=f"bash -c \"kill -9 $({cmd})\"")
                
                logger.info(f"[ACTION] Level 2 Process Kill executed successfully.")
                self.last_action_timestamp = time.time()
                self.STABILIZATION_WINDOW = 90
                return "process_kill_success"
            except Exception as e:
                logger.error(f"Level 2 Process kill failed in LXC {self.vmid}: {e}")
                return "process_kill_failed"
            
        elif level == 3:
            logger.warning(f"[ACTION] [Level 3] Traffic Rerouting triggered for {anomaly_type} anomaly")
            logger.info("[SIMULATION] Updating IP tables / Nginx config to redirect traffic to backup node...")
            self.last_action_timestamp = time.time()
            self.STABILIZATION_WINDOW = 90
            return "traffic_reroute_simulated"
            
        elif level == 4:
            logger.warning(f"[ACTION] [Level 4] Resource Isolation & Container Soft Reboot (VMID {self.vmid})")
            try:
                # Trigger a soft reboot via Proxmox API
                proxmox.nodes(self.node).lxc(self.vmid).status.reboot.post()
                logger.info(f"[ACTION] Soft reboot initiated for LXC {self.vmid}")
                
                # 2. Verification (Wait for container to at least start rebooting/accessible)
                time.sleep(10)
                if self._verify_service(service_name, docker_containers):
                    # OS boot logic: 4. Intelligence for Level 4 (Reboot) - Extended 120s window
                    self.last_action_timestamp = time.time()
                    self.STABILIZATION_WINDOW = 120
                    logger.info("[ACTION] Level 4 reboot triggered. Extending stabilization window to 120s for OS boot.")
                    return "lxc_soft_reboot"
                else:
                    return "lxc_reboot_verification_failed"
            except Exception as e:
                logger.error(f"Proxmox soft reboot failed for LXC {self.vmid}: {e}")
                return "lxc_soft_reboot_failed"
            
        elif level == 5:
            logger.critical(f"[ACTION] [Level 5] CRITICAL: Container hard reboot (VMID {self.vmid})")
            try:
                proxmox.nodes(self.node).lxc(self.vmid).status.stop.post()
                time.sleep(5)
                proxmox.nodes(self.node).lxc(self.vmid).status.start.post()
                time.sleep(10)
                if self._verify_service(service_name, docker_containers):
                    self.last_action_timestamp = time.time()
                    self.STABILIZATION_WINDOW = 180
                    return "lxc_hard_reboot"
                return "lxc_hard_reboot_verification_failed"
            except Exception as e:
                logger.error(f"Proxmox hard reboot failed for LXC {self.vmid}: {e}")
                return "lxc_hard_reboot_failed"
            
        return "unknown_action"
            
        return "unknown_action"
