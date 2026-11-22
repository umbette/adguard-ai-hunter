import pytest
from src.dynamic_pricing import evaluate_dynamic_pricing_tracker

def test_dynamic_pricing_airline_and_hotel_trackers():
    # 1. Criteo tracking domains
    m1 = evaluate_dynamic_pricing_tracker("static.criteo.com")
    assert m1 is not None
    assert m1.tracker_name == "Criteo Retargeting"
    assert m1.category == "AIRLINE_HOTEL_DISCRIMINATION"

    m2 = evaluate_dynamic_pricing_tracker("bidder.criteo.net")
    assert m2 is not None

    # 2. Mobile cross-app attribution & purchasing power fingerprinting
    m3 = evaluate_dynamic_pricing_tracker("app.appsflyer.com")
    assert m3 is not None
    assert m3.tracker_name == "AppsFlyer"
    assert m3.category == "CROSS_APP_FINGERPRINTING"

    m4 = evaluate_dynamic_pricing_tracker("control.kochava.com")
    assert m4 is not None

    m5 = evaluate_dynamic_pricing_tracker("api.adjust.com")
    assert m5 is not None

    # 3. Behavioral session recording on ticket booking
    m6 = evaluate_dynamic_pricing_tracker("recorder.sessioncam.com")
    assert m6 is not None
    assert m6.category == "BEHAVIORAL_SESSION_RECORDING"

    m7 = evaluate_dynamic_pricing_tracker("script.hotjar.com")
    assert m7 is not None

    # 4. Dynamic Pricing & Yield Optimization
    m8 = evaluate_dynamic_pricing_tracker("fast.demdex.net")
    assert m8 is not None
    assert m8.category == "DYNAMIC_PRICING_ENABLER"

def test_dynamic_pricing_benign_domains_not_flagged():
    assert evaluate_dynamic_pricing_tracker("google.com") is None
    assert evaluate_dynamic_pricing_tracker("ryanair.com") is None
    assert evaluate_dynamic_pricing_tracker("booking.com") is None
    assert evaluate_dynamic_pricing_tracker("easyjet.com") is None
    assert evaluate_dynamic_pricing_tracker("github.com") is None
