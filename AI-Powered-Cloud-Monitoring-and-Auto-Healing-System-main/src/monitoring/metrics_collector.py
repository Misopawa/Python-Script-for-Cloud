from proxmoxer import ProxmoxAPI
import time
import urllib3
import math

# Suppress SSL warnings for local Proxmox connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_LAST_NET_TOTAL_BYTES = {}
_LAST_POLL_TS = {}

def _looks_like_auth_error(exc):
    msg = str(exc)
    return "401" in msg or "Unauthorized" in msg or "authentication" in msg.lower()

def _looks_like_connection_error(exc):
    msg = str(exc).lower()
    return "timeout" in msg or "timed out" in msg or "connection" in msg or "max retries" in msg

def get_proxmox_client(config):
    """
    Initialize and return a Proxmox API client.
    """
    prox_cfg = config.get('proxmox', {})
    return ProxmoxAPI(
        prox_cfg.get('host'),
        user=prox_cfg.get('user'),
        password=prox_cfg.get('password'),
        verify_ssl=prox_cfg.get('verify_ssl', False)
    )

def collect_metrics(config):
    """
    Collect real-time telemetry from Proxmox for LXC 101.
    Aligns with Westermo system-1.csv feature vector requirements.
    Handles the 'Boot-up Gap' where API returns None or 0 for CPU/Memory.
    """
    prox_cfg = config.get('proxmox', {})
    node = prox_cfg.get('node', 'pve')
    vmid = prox_cfg.get('vmid', 101)
    
    proxmox = get_proxmox_client(config)

    try:
        status = proxmox.nodes(node).lxc(vmid).status.current.get()
    except Exception as e:
        if _looks_like_auth_error(e) or _looks_like_connection_error(e):
            try:
                proxmox = get_proxmox_client(config)
                status = proxmox.nodes(node).lxc(vmid).status.current.get()
            except Exception:
                return None
        else:
            return None
    
    # Robust Parsing (The "Null" Guard)
    cpu_raw = status.get('cpu')
    mem_raw = status.get('mem')
    max_mem = status.get('maxmem', 1)
    disk_raw = status.get("disk")
    max_disk = status.get("maxdisk", 1)
    net_in = status.get("netin")
    net_out = status.get("netout")
    
    # If API returns None (during reboot), skip this cycle
    if cpu_raw is None or mem_raw is None:
        return None
    
    # Decimal Normalization [0,1]
    # CPU: Proxmox returns value in decimal (e.g. 0.5 for 50%). Use directly.
    # High-precision scaling for idle values (e.g., 0.0024)
    cpu_usage_ratio = round(float(cpu_raw), 6)
    
    # Memory/Swap: Convert absolute byte values into ratios
    # Memory Ratio = current_usage / total_capacity
    sys_mem_total = float(max_mem)
    sys_mem_free = float(max_mem - mem_raw)
    sys_mem_available = sys_mem_free # Approximation
    
    # Normalized features (ratios)
    mem_ratio = round(mem_raw / max_mem, 6)
    free_ratio = round(sys_mem_free / max_mem, 6)
    available_ratio = round(sys_mem_available / max_mem, 6)

    storage_used_ratio = 0.0
    if disk_raw is not None and max_disk:
        try:
            storage_used_ratio = round(float(disk_raw) / float(max_disk), 6)
        except Exception:
            storage_used_ratio = 0.0

    now_ts = time.time()
    key = (str(node), str(vmid))
    network_bytes_per_sec = 0.0
    if net_in is not None and net_out is not None:
        try:
            total_bytes = float(net_in) + float(net_out)
            prev_total = _LAST_NET_TOTAL_BYTES.get(key)
            prev_ts = _LAST_POLL_TS.get(key)
            if prev_total is not None and prev_ts is not None:
                dt = max(1e-6, float(now_ts - prev_ts))
                delta = max(0.0, float(total_bytes - prev_total))
                network_bytes_per_sec = round(delta / dt, 6)
            _LAST_NET_TOTAL_BYTES[key] = float(total_bytes)
            _LAST_POLL_TS[key] = float(now_ts)
        except Exception:
            network_bytes_per_sec = 0.0

    # Required Features Alignment (Exactly 12 features in specific order)
    # 1. load1_norm 2. load5_norm 3. load15_norm 
    # 4. mem_free_ratio 5. mem_available_ratio 6. mem_total_ratio 
    # 7. mem_cache_ratio 8. mem_buffered_ratio 
    # 9. swap_total_ratio 10. swap_free_ratio 
    # 11. fork_rate 12. intr_rate
    vector = {
        'timestamp': now_ts,
        'cpu_usage_ratio': cpu_usage_ratio,
        'mem_used_ratio': mem_ratio,
        'storage_used_ratio': storage_used_ratio,
        'network_bytes_per_sec': network_bytes_per_sec,

        'load1_norm': cpu_usage_ratio,
        'load5_norm': 0.0,
        'load15_norm': 0.0,
        'mem_free_ratio': free_ratio,
        'mem_available_ratio': available_ratio,
        'mem_total_ratio': 1.0, # Capacity as denominator for ratios
        'mem_cache_ratio': 0.0,
        'mem_buffered_ratio': 0.0,
        'swap_total_ratio': 1.0, # Placeholder ratio denominator
        'swap_free_ratio': 1.0,   # Placeholder ratio
        'fork_rate': 0.0,
        'intr_rate': 0.0
    }

    # 1. Data Sanitization (Anti-Crash Layer)
    for key, value in vector.items():
        if key == 'timestamp': continue
        if value is None or (isinstance(value, float) and math.isnan(value)):
            return {**vector, 'critical_data_loss': True}
            
    return {**vector, 'critical_data_loss': False}
