def check_thresholds(metrics, config):
    exceeded = []
    if metrics.get('cpu_usage_percent', 0) > config.get('cpu_threshold', 100):
        exceeded.append('cpu')
    if metrics.get('memory_usage_percent', 0) > config.get('memory_threshold', 100):
        exceeded.append('memory')
    if metrics.get('disk_usage_percent', 0) > config.get('disk_threshold', 100):
        exceeded.append('disk')
    return {'threshold_exceeded': bool(exceeded), 'exceeded_resources': exceeded}
