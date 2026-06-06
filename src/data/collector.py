import json
import os
import time
from typing import Any, Dict, Optional

import requests


class DataCollector:
    PROMQL_QUERIES = {
        "CPU": 'scalar(node_load1{job="CT100-Web-Server"}) * 100 / count(count(node_cpu_seconds_total{job="CT100-Web-Server"}) by (cpu))',
        "MEMORY": 'clamp_min((1 - (node_memory_MemAvailable_bytes{job="CT100-Web-Server"} / node_memory_MemTotal_bytes{job="CT100-Web-Server"})) * 100, 0)',
        "STORAGE": '((node_filesystem_size_bytes{mountpoint="/", fstype!="rootfs", job="CT100-Web-Server"} - node_filesystem_avail_bytes{mountpoint="/", fstype!="rootfs", job="CT100-Web-Server"}) / node_filesystem_size_bytes{mountpoint="/", fstype!="rootfs", job="CT100-Web-Server"}) * 100',
        "NETWORK": 'sum(irate(node_network_receive_bytes_total{device=~"veth.*|eth.*|ens.*"}[1m]))',
    }

    def __init__(self, prometheus_url: str = "http://127.0.0.1:9090", timeout_seconds: int = 8):
        self.prometheus_url = str(prometheus_url or "").rstrip("/") or "http://127.0.0.1:9090"
        self.timeout_seconds = int(timeout_seconds)

    def fetch_raw_metrics(self) -> Dict[str, float]:
        endpoint = f"{self.prometheus_url}/api/v1/query"
        metrics: Dict[str, float] = {}

        for metric_name, promql in self.PROMQL_QUERIES.items():
            try:
                response = requests.get(endpoint, params={"query": promql}, timeout=self.timeout_seconds)
                response.raise_for_status()
                payload = response.json()
                if payload.get("status") != "success":
                    metrics[metric_name] = 0.0
                    continue

                result = ((payload.get("data") or {}).get("result")) or []
                if not result or not isinstance(result, list):
                    metrics[metric_name] = 0.0
                    continue

                value = (result[0].get("value") or [None, None])[1]
                metrics[metric_name] = float(value) if value is not None else 0.0
            except Exception:
                metrics[metric_name] = 0.0

        return metrics

    def get_live_state(self) -> Dict[str, float]:
        try:
            raw_metrics = self.fetch_raw_metrics()
            return {
                "CPU": float(raw_metrics.get("CPU", 0.0) or 0.0),
                "MEMORY": float(raw_metrics.get("MEMORY", 0.0) or 0.0),
                "STORAGE": float(raw_metrics.get("STORAGE", 0.0) or 0.0),
                "NETWORK": float(raw_metrics.get("NETWORK", 0.0) or 0.0),
            }
        except Exception:
            return {"CPU": 0.0, "MEMORY": 0.0, "STORAGE": 0.0, "NETWORK": 0.0}


class PrometheusCollector:
    METRIC_LIST = ["CPU", "MEMORY", "STORAGE", "NETWORK"]

    def __init__(self, config_path: str = None, timeout_seconds: int = 8):
        self.config_path = config_path or os.path.join("config", "prometheus_config.json")
        self.timeout_seconds = int(timeout_seconds)
        self.cfg = self._load_config()
        self.url = "http://127.0.0.1:9090"
        self.prometheus_url = self.url
        try:
            self.cfg["prometheus_url"] = self.url
        except Exception:
            self.cfg = {"prometheus_url": self.url}
        self.expected_metrics = list(self.METRIC_LIST)
        self._last_values = {}
        self._last_cpu_print_ts = 0.0
        self.connection_ok = self.check_connection()
        self.connection_status = "ONLINE" if self.connection_ok else "OFFLINE"
        self.source_status = "CONNECTED" if self.connection_ok else "OFFLINE (Check Prometheus)"

    def _load_config(self) -> Dict[str, Any]:
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f) or {}
        except Exception:
            return {}
        return {}

    def _query(self, promql: str) -> Optional[float]:
        url = str(self.url or "").rstrip("/")
        if not url or "<PROMETHEUS_IP>" in url:
            return None
        endpoint = f"{url}/api/v1/query"

        try:
            resp = requests.get(endpoint, params={"query": promql}, timeout=self.timeout_seconds)
            data = resp.json() if resp.ok else None
            if not data or data.get("status") != "success":
                return None
            results = ((data.get("data") or {}).get("result")) or []
            if not results:
                return None
            value = (results[0].get("value") or [None, None])[1]
            if value is None:
                return None
            return float(value)
        except Exception:
            return None

    def check_connection(self) -> bool:
        url = str(self.url or "").rstrip("/")
        if not url or "<PROMETHEUS_IP>" in url:
            return False
        try:
            resp = requests.get(f"{url}/-/ready", timeout=min(3, self.timeout_seconds))
            if 200 <= int(resp.status_code) < 300:
                return True
        except Exception:
            pass
        try:
            resp = requests.get(f"{url}/api/v1/status/buildinfo", timeout=min(3, self.timeout_seconds))
            data = resp.json() if resp.ok else None
            return bool(data and data.get("status") == "success")
        except Exception:
            return False

    def _query_with_raw(self, promql: str):
        url = str(self.url or "").rstrip("/")
        if not url or "<PROMETHEUS_IP>" in url:
            return None, None, False
        endpoint = f"{url}/api/v1/query"

        try:
            resp = requests.get(endpoint, params={"query": promql}, timeout=self.timeout_seconds)
            data = resp.json() if resp.ok else None
            os.makedirs("logs", exist_ok=True)
            with open(os.path.join("logs", "prometheus_debug.log"), "a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": time.time(), "query": promql, "response": data}, ensure_ascii=False) + "\n")
            if not data or data.get("status") != "success":
                return None, data, False
            results = ((data.get("data") or {}).get("result")) or []
            if not results:
                return None, data, False
            value = (results[0].get("value") or [None, None])[1]
            if value is None:
                return None, data, False
            return float(value), data, True
        except Exception:
            return None, None, False

    def get_network_metrics(self, job_name: str, network_device: str, base_selector: str, instance_regex: str = None) -> Optional[float]:
        base_selector = (base_selector or "").strip().strip("{}").strip()
        instance_regex = (instance_regex or "").strip()

        def sel(extra: str = "") -> str:
            if base_selector and extra:
                return "{" + base_selector + "," + extra + "}"
            if base_selector:
                return "{" + base_selector + "}"
            if extra:
                return "{" + extra + "}"
            return ""

        if job_name and network_device:
            inst = ''
            if instance_regex:
                inst = ', instance=~"' + instance_regex + '"'
            primary = (
                'sum(irate(node_network_receive_bytes_total{device!="lo", interface="' + network_device + '", job="' + job_name + '"' + inst + '}[5m])) + '
                'sum(irate(node_network_transmit_bytes_total{device!="lo", interface="' + network_device + '", job="' + job_name + '"' + inst + '}[5m]))'
            )
            value, _, ok = self._query_with_raw(primary)
            if ok:
                return value

            fallback = (
                'sum(irate(node_network_receive_bytes_total{device!="lo", job="' + job_name + '"' + inst + '}[5m])) + '
                'sum(irate(node_network_transmit_bytes_total{device!="lo", job="' + job_name + '"' + inst + '}[5m]))'
            )
            value, _, ok = self._query_with_raw(fallback)
            if ok:
                return value

        generic = (
            'sum(irate(node_network_receive_bytes_total{device=~"eth.*|ens.*|veth.*"}' + sel() + '[1m])) + '
            'sum(irate(node_network_transmit_bytes_total{device=~"eth.*|ens.*|veth.*"}' + sel() + '[1m]))'
        )
        value, _, ok = self._query_with_raw(generic)
        if ok:
            return value

        if job_name and network_device:
            inst = ''
            if instance_regex:
                inst = ', instance=~"' + instance_regex + '"'
            fallback = (
                'sum(rate(net_bytes_recv{interface="' + network_device + '", job="' + job_name + '"' + inst + '}[1m])) + '
                'sum(rate(net_bytes_sent{interface="' + network_device + '", job="' + job_name + '"' + inst + '}[1m]))'
            )
            value, _, ok = self._query_with_raw(fallback)
            if ok:
                return value

        fallback_generic = (
            'sum(rate(net_bytes_recv{device!="lo"}' + sel() + '[1m])) + '
            'sum(rate(net_bytes_sent{device!="lo"}' + sel() + '[1m]))'
        )
        value, _, ok = self._query_with_raw(fallback_generic)
        if ok:
            return value
        return None

    def collect(self) -> Optional[Dict[str, float]]:
        base_selector = str(self.cfg.get("label_selector") or "").strip()
        base_selector = base_selector.strip()
        base_selector = base_selector.strip("{}").strip()
        url = str(self.url or "").rstrip("/")
        try:
            if url and "<PROMETHEUS_IP>" not in url:
                resp = requests.get(f"{url}/api/v1/status/buildinfo", timeout=min(3, self.timeout_seconds))
                self.source_status = "CONNECTED" if int(resp.status_code) == 200 else "OFFLINE (Check Prometheus)"
                try:
                    raw = resp.json() if resp.ok else {"status_code": int(resp.status_code), "text": resp.text}
                except Exception:
                    raw = {"status_code": int(resp.status_code), "text": resp.text}
                os.makedirs("logs", exist_ok=True)
                with open(os.path.join("logs", "prometheus_debug.log"), "a", encoding="utf-8") as f:
                    f.write(json.dumps({"ts": time.time(), "query": "BUILDINFO", "response": raw}, ensure_ascii=False) + "\n")
            else:
                self.source_status = "OFFLINE (Check Prometheus)"
        except Exception as e:
            self.source_status = "OFFLINE (Check Prometheus)"
            try:
                os.makedirs("logs", exist_ok=True)
                with open(os.path.join("logs", "prometheus_debug.log"), "a", encoding="utf-8") as f:
                    f.write(json.dumps({"ts": time.time(), "query": "BUILDINFO", "error": str(e)}, ensure_ascii=False) + "\n")
            except Exception:
                pass
        instance_regex = str(self.cfg.get("instance_regex") or "10.0.2.100.*").strip()
        if instance_regex and "instance=" not in base_selector:
            if base_selector:
                base_selector = base_selector + ',instance=~"' + instance_regex + '"'
            else:
                base_selector = 'instance=~"' + instance_regex + '"'

        def sel(extra: str = "") -> str:
            if base_selector and extra:
                return "{" + base_selector + "," + extra + "}"
            if base_selector:
                return "{" + base_selector + "}"
            if extra:
                return "{" + extra + "}"
            return ""

        cpu_q = "avg(cpu_usage_active" + sel('cpu=\"cpu-total\"') + ")"
        mem_q = "avg(mem_used_percent" + sel() + ")"
        job_name = str(self.cfg.get("job_name") or "").strip()
        network_device = str(self.cfg.get("network_device") or "").strip()
        website_url = str(self.cfg.get("website_url") or "").strip()
        latency_threshold_ms = float(self.cfg.get("network_latency_threshold_ms") or 500.0)
        retrans_threshold = float(self.cfg.get("network_retrans_threshold") or 5.0)
        network_max = float(self.cfg.get("network_max_bytes_per_sec") or 125000000)
        if network_max <= 0:
            network_max = 125000000.0

        latency_ms_q = None
        probe_success_q = None
        if website_url:
            latency_ms_q = 'avg(probe_duration_seconds{instance="' + website_url + '"}) * 1000'
            probe_success_q = 'min(probe_success{instance="' + website_url + '"})'
        if not latency_ms_q:
            if job_name:
                latency_ms_q = 'avg(node_netstat_Tcp_RtoAlgorithm{job="' + job_name + '"}) * 1000'
            else:
                latency_ms_q = "avg(node_netstat_Tcp_RtoAlgorithm) * 1000"

        if job_name:
            retrans_q = 'rate(node_netstat_Tcp_RetransSegs{job="' + job_name + '"}[1m])'
        else:
            retrans_q = "rate(node_netstat_Tcp_RetransSegs[1m])"

        mountpoint = str(self.cfg.get("storage_mountpoint") or "/")
        storage_device = str(self.cfg.get("storage_device") or "").strip()
        storage_q = "avg(disk_used_percent" + sel() + ")"

        cpu_pct = self._query(cpu_q)
        mem_pct = self._query(mem_q)
        latency_ms = self._query(latency_ms_q) if latency_ms_q else None
        retrans_per_sec = self._query(retrans_q)
        probe_success = self._query(probe_success_q) if probe_success_q else None
        net_bps = self.get_network_metrics(
            job_name=job_name,
            network_device=network_device,
            base_selector=base_selector,
            instance_regex=instance_regex,
        )
        storage_pct = self._query(storage_q)

        if cpu_pct is None:
            cpu_pct = self._last_values.get("cpu_pct")
        if mem_pct is None:
            mem_pct = self._last_values.get("mem_pct")
        if cpu_pct is None:
            cpu_pct = 0.0
        if mem_pct is None:
            mem_pct = 0.0
        self._last_values["cpu_pct"] = float(cpu_pct or 0.0)
        self._last_values["mem_pct"] = float(mem_pct or 0.0)
        now_ts = time.time()
        if float(now_ts - float(self._last_cpu_print_ts)) >= 5.0:
            self._last_cpu_print_ts = float(now_ts)

        def clamp01(x: float) -> float:
            try:
                return max(0.0, min(1.0, float(x)))
            except Exception:
                return 0.0

        if latency_ms is None:
            latency_ms = self._last_values.get("net_latency_ms")
        if retrans_per_sec is None:
            retrans_per_sec = self._last_values.get("net_retrans_per_sec")
        if probe_success is None:
            probe_success = self._last_values.get("probe_success")
        if net_bps is None:
            net_bps = self._last_values.get("net_bps")
        if storage_pct is None:
            storage_pct = self._last_values.get("storage_pct")

        network_health_ratio = 1.0
        if probe_success is not None and float(probe_success) <= 0.0:
            network_health_ratio = 0.0
        elif latency_ms is not None and float(latency_ms) > 0:
            network_health_ratio = clamp01(float(latency_threshold_ms) / float(latency_ms))

        throughput_ratio = 0.0
        if net_bps is not None and network_max > 0:
            throughput_ratio = clamp01(float(net_bps) / float(network_max))
        network_speed_mbps = 0.0
        if net_bps is not None:
            network_speed_mbps = max(0.0, (float(net_bps) * 8.0) / 1_000_000.0)

        if latency_ms is not None:
            self._last_values["net_latency_ms"] = float(latency_ms)
        if retrans_per_sec is not None:
            self._last_values["net_retrans_per_sec"] = float(retrans_per_sec)
        if probe_success is not None:
            self._last_values["probe_success"] = float(probe_success)
        if net_bps is not None:
            self._last_values["net_bps"] = float(net_bps)
        if storage_pct is not None:
            self._last_values["storage_pct"] = float(storage_pct)

        cpu_ratio = clamp01(float(cpu_pct) / 100.0)
        mem_ratio = clamp01(float(mem_pct) / 100.0)
        storage_ratio = clamp01(float(storage_pct or 0.0) / 100.0)

        metrics = {
            "timestamp": float(time.time()),
            "cpu_usage_ratio": float(cpu_ratio),
            "cpu_usage_pct": float(max(0.0, min(100.0, float(cpu_pct)))),
            "mem_used_ratio": float(mem_ratio),
            "mem_used_pct": float(max(0.0, min(100.0, float(mem_pct)))),
            "storage_used_ratio": float(storage_ratio),
            "storage_used_pct": float(max(0.0, min(100.0, float(storage_pct or 0.0)))),
            "network_ratio": clamp01(throughput_ratio),
            "network_pct": float(clamp01(throughput_ratio) * 100.0),
            "network_health_ratio": clamp01(network_health_ratio),
            "network_bytes_per_sec": float(net_bps or 0.0),
            "network_speed_mbps": float(network_speed_mbps),
            "network_max_bytes_per_sec": float(network_max),
            "network_latency_ms": float(latency_ms or 0.0),
            "network_retrans_per_sec": float(retrans_per_sec or 0.0),
            "probe_success": float(probe_success) if probe_success is not None else 1.0,
            "network_latency_threshold_ms": float(latency_threshold_ms),
            "network_retrans_threshold": float(retrans_threshold),
            "critical_data_loss": False,
        }
        self._last_metrics = metrics
        return metrics

    def scrape(self) -> Optional[Dict[str, Any]]:
        metrics = self.collect()
        if metrics is not None:
            self._last_metrics = metrics
        return metrics

    def get_metrics(self) -> Dict[str, float]:
        metrics = getattr(self, "_last_metrics", None)
        if metrics is None:
            metrics = self.collect() or {}
        return {
            "CPU": float(metrics.get("cpu_usage_pct", 0.0) or 0.0),
            "MEMORY": float(metrics.get("mem_used_pct", 0.0) or 0.0),
            "STORAGE": float(metrics.get("storage_used_pct", 0.0) or 0.0),
            "NETWORK": float(metrics.get("network_pct", 0.0) or 0.0),
        }
