_HIST_SIZE = 5
_hist = {
    'errin': [],
    'errout': [],
    'dropin': [],
    'dropout': [],
}

def _avg_push(key, value):
    buf = _hist[key]
    buf.append(float(value or 0))
    if len(buf) > _HIST_SIZE:
        buf.pop(0)
    return sum(buf) / len(buf) if buf else 0.0

def check_network_thresholds(metrics, config):
    """
    Check network error/drop counters against thresholds using rolling average.
    Only evaluates errin, errout, dropin, dropout from psutil.net_io_counters().
    """
    # Extract network counters from current sample
    net_sample = metrics.get('network') or {}
    # If metrics doesn't include network, try collecting here to avoid coupling
    if not net_sample:
        try:
            import psutil
            io = psutil.net_io_counters()
            net_sample = {
                'errin': io.errin,
                'errout': io.errout,
                'dropin': io.dropin,
                'dropout': io.dropout,
            }
        except Exception:
            net_sample = {}

    cfg = (config or {}).get('network_thresholds') or {}
    exceeded = {}
    avg_errin = _avg_push('errin', net_sample.get('errin', 0))
    avg_errout = _avg_push('errout', net_sample.get('errout', 0))
    avg_dropin = _avg_push('dropin', net_sample.get('dropin', 0))
    avg_dropout = _avg_push('dropout', net_sample.get('dropout', 0))

    if avg_errin >= float(cfg.get('max_errin', float('inf'))):
        exceeded['errin'] = {'value': avg_errin, 'max': cfg.get('max_errin')}
    if avg_errout >= float(cfg.get('max_errout', float('inf'))):
        exceeded['errout'] = {'value': avg_errout, 'max': cfg.get('max_errout')}
    if avg_dropin >= float(cfg.get('max_dropin', float('inf'))):
        exceeded['dropin'] = {'value': avg_dropin, 'max': cfg.get('max_dropin')}
    if avg_dropout >= float(cfg.get('max_dropout', float('inf'))):
        exceeded['dropout'] = {'value': avg_dropout, 'max': cfg.get('max_dropout')}

    if exceeded:
        return {'threshold_exceeded': True, 'resource': 'network', 'details': exceeded}
    return {'threshold_exceeded': False, 'resource': 'network', 'details': {}}
