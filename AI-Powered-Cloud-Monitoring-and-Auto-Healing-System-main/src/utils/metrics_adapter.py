def adapt_metrics_for_ai(metrics: dict):
    cpu = metrics.get("cpu_usage_percent", 0.0)
    memory = metrics.get("memory_usage_percent", 0.0)

    return {
        "load": {
            "1m": cpu,
            "5m": cpu,
            "15m": cpu,
        },
        "memory": {
            "available": max(0.0, 100.0 - memory),
        },
        "cpu": {
            "user": cpu,
            "system": cpu * 0.6,
            "iowait": cpu * 0.1,
        },
        "system": {
            "fork_rate": 10.0,
            "interrupt_rate": 200.0,
            "context_switch": 300.0,
        },
    }
