import pytest
from metrics import collect_metrics

def test_collect_metrics():
    metrics = collect_metrics()
    assert 'cpu' in metrics
    assert 'memory' in metrics
    assert 'disk' in metrics
