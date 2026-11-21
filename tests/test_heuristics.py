from src.heuristics import calculate_shannon_entropy, HeuristicsEngine

def test_shannon_entropy():
    low = calculate_shannon_entropy("google")
    assert low < 2.5

    high = calculate_shannon_entropy("x7zq9b2k1l8v0p3m")
    assert high >= 3.85

def test_heuristics_dga_detection(heuristics):
    # Benign domain bypass
    is_dga, ent, _ = heuristics.evaluate_entropy("google.com")
    assert not is_dga

    # Algorithmic DGA domain
    is_dga, ent, _ = heuristics.evaluate_entropy("x7zq9b2k1l8v0p3m.biz")
    assert is_dga
    assert ent >= 3.85

    # Algorithmic subdomain under generic CDN
    is_dga, ent, label = heuristics.evaluate_entropy("d3g7k9m2x4q8p1wz.trafficmanager.net")
    assert is_dga
    assert "d3g7k9m2x4q8p1wz" in label

def test_rate_burst_tracking(heuristics):
    client = "192.168.1.210"
    domain = "telemetry.lge.com"

    for _ in range(4):
        is_burst, count = heuristics.record_query_and_check_burst(client, domain)
        assert not is_burst

    is_burst, count = heuristics.record_query_and_check_burst(client, domain)
    assert is_burst
    assert count == 5
