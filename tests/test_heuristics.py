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

    # Algorithmic DGA domain (long)
    is_dga, ent, _ = heuristics.evaluate_entropy("x7zq9b2k1l8v0p3m.biz")
    assert is_dga
    assert ent >= 3.85

    # Algorithmic DGA domain (short 10 chars with high normalized entropy)
    is_dga_short, ent_short, _ = heuristics.evaluate_entropy("xk92lms08a.biz")
    assert is_dga_short

    # Natural 10-12 char dictionary words (should not trigger DGA triage)
    for natural_word in ("newsletter.com", "california.biz", "photography.net", "accountant.org", "development.io", "university.edu"):
        is_word, _, _ = heuristics.evaluate_entropy(natural_word)
        assert not is_word, f"False positive: natural word {natural_word} was flagged as DGA!"

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
