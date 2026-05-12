from typing import Dict, Tuple


class PolicyHealer:
    def __init__(self):
        self.state: Dict[str, Dict[str, object]] = {
            "CPU": {"current_level": 0, "retry_count": 0, "is_halted": False},
            "MEMORY": {"current_level": 0, "retry_count": 0, "is_halted": False},
            "STORAGE": {"current_level": 0, "retry_count": 0, "is_halted": False},
            "NETWORK": {"current_level": 0, "retry_count": 0, "is_halted": False},
        }

    def execute_policy(self, metric_name: str, value: float) -> Tuple[int, str]:
        metric_name = str(metric_name or "").upper()
        metric_state = self.state.get(metric_name)
        if metric_state is None:
            message = f"No policy available for metric '{metric_name}'"
            print(message)
            return 0, message

        if metric_state["is_halted"]:
            message = f"{metric_name} is halted. Manual intervention required. No further auto-healing will be performed."
            print(message)
            return int(metric_state["current_level"] or 0), message

        if metric_name == "CPU":
            return self._handle_cpu_policy(value)
        if metric_name == "MEMORY":
            return self._handle_memory_policy(value)
        if metric_name == "STORAGE":
            return self._handle_storage_policy(value)
        if metric_name == "NETWORK":
            return self._handle_network_policy(value)

        message = f"No policy available for metric '{metric_name}'"
        print(message)
        return 0, message

    def _execute_level(self, metric_name: str, desired_level: int, retry_limit: int, action_text: str, next_level: int = None) -> Tuple[int, str]:
        metric_state = self.state[metric_name]
        current_level = int(metric_state["current_level"])
        retry_count = int(metric_state["retry_count"])

        if current_level != desired_level:
            current_level = desired_level
            retry_count = 0

        if retry_count >= retry_limit:
            if next_level is not None:
                current_level = next_level
                retry_count = 0
            metric_state["current_level"] = current_level
            metric_state["retry_count"] = retry_count
            return self.execute_policy(metric_name, 0.0)

        retry_count += 1
        metric_state["current_level"] = current_level
        metric_state["retry_count"] = retry_count

        message = (
            f"{metric_name} Level {current_level}: Attempt {retry_count}/{retry_limit}. {action_text}"
        )
        print(message)
        return current_level, message

    def _halt_metric(self, metric_name: str, alert_text: str) -> Tuple[int, str]:
        metric_state = self.state[metric_name]
        metric_state["current_level"] = 5
        metric_state["retry_count"] = 0
        metric_state["is_halted"] = True
        message = f"{metric_name} Level 5: Escalation triggered. {alert_text}"
        print(message)
        return 5, message

    def _handle_cpu_policy(self, value: float) -> Tuple[int, str]:
        metric_name = "CPU"
        metric_state = self.state[metric_name]
        current_level = int(metric_state["current_level"])

        if current_level in (0, 1):
            return self._execute_level(
                metric_name,
                desired_level=1,
                retry_limit=2,
                action_text="Restarting service to recover CPU stability.",
                next_level=2,
            )
        if current_level == 2:
            return self._execute_level(
                metric_name,
                desired_level=2,
                retry_limit=1,
                action_text="Killing runaway CPU processes.",
                next_level=4,
            )
        if current_level == 4:
            return self._execute_level(
                metric_name,
                desired_level=4,
                retry_limit=1,
                action_text="Applying cgroups/Proxmox CPU resource limits.",
                next_level=5,
            )

        return self._halt_metric(metric_name, "Critical CPU threshold exceeded. Sending Critical Telegram Alert.")

    def _handle_memory_policy(self, value: float) -> Tuple[int, str]:
        metric_name = "MEMORY"
        metric_state = self.state[metric_name]
        current_level = int(metric_state["current_level"])

        if current_level in (0, 1):
            return self._execute_level(
                metric_name,
                desired_level=1,
                retry_limit=2,
                action_text="Restarting service to recover memory stability.",
                next_level=2,
            )
        if current_level == 2:
            return self._execute_level(
                metric_name,
                desired_level=2,
                retry_limit=1,
                action_text="Killing runaway memory processes.",
                next_level=4,
            )
        if current_level == 4:
            return self._execute_level(
                metric_name,
                desired_level=4,
                retry_limit=1,
                action_text="Applying cgroups/Proxmox memory resource limits.",
                next_level=5,
            )

        return self._halt_metric(metric_name, "Critical MEMORY threshold exceeded. Sending Critical Telegram Alert.")

    def _handle_storage_policy(self, value: float) -> Tuple[int, str]:
        metric_name = "STORAGE"
        metric_state = self.state[metric_name]
        current_level = int(metric_state["current_level"])

        if current_level in (0, 1):
            return self._execute_level(
                metric_name,
                desired_level=1,
                retry_limit=2,
                action_text="Restarting service to recover storage stability.",
                next_level=2,
            )
        if current_level == 2:
            return self._execute_level(
                metric_name,
                desired_level=2,
                retry_limit=1,
                action_text="Killing runaway storage processes.",
                next_level=4,
            )
        if current_level == 4:
            return self._execute_level(
                metric_name,
                desired_level=4,
                retry_limit=1,
                action_text="Applying cgroups/Proxmox storage resource limits.",
                next_level=5,
            )

        return self._halt_metric(metric_name, "Critical STORAGE threshold exceeded. Sending Critical Telegram Alert.")

    def _handle_network_policy(self, value: float) -> Tuple[int, str]:
        metric_name = "NETWORK"
        metric_state = self.state[metric_name]
        current_level = int(metric_state["current_level"])

        if current_level in (0, 1):
            return self._execute_level(
                metric_name,
                desired_level=1,
                retry_limit=2,
                action_text="Restarting network service to recover connectivity.",
                next_level=3,
            )
        if current_level == 3:
            return self._execute_level(
                metric_name,
                desired_level=3,
                retry_limit=2,
                action_text="Rerouting traffic using HAProxy/iptables.",
                next_level=4,
            )
        if current_level == 4:
            return self._execute_level(
                metric_name,
                desired_level=4,
                retry_limit=1,
                action_text="Isolating the network interface.",
                next_level=5,
            )

        return self._halt_metric(metric_name, "Critical NETWORK threshold exceeded. Sending Critical Telegram Alert.")
