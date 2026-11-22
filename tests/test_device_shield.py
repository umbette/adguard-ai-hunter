import pytest
from src.device_shield import (
    evaluate_nintendo_telemetry,
    evaluate_vacuum_telemetry,
    evaluate_bambu_telemetry,
    evaluate_gaming_jitter_telemetry,
    evaluate_device_shield,
    DeviceShieldMatch
)

def test_nintendo_90dns_anti_ban():
    # 1. Official 90DNS telemetry endpoints
    m1 = evaluate_nintendo_telemetry("receive-lp1.er.srv.nintendo.net")
    assert m1 is not None
    assert m1.shield_type == "NINTENDO_90DNS"
    assert m1.target_category == "GAMING_CONSOLE"
    assert "2124-4007" in m1.description

    # 2. Authentication & Ticket validation endpoints
    m2 = evaluate_nintendo_telemetry("dauth-lp1.ndas.srv.nintendo.net")
    assert m2 is not None
    assert m2.shield_type == "NINTENDO_90DNS"

    m3 = evaluate_nintendo_telemetry("aauth-lp1.ndas.srv.nintendo.net")
    assert m3 is not None

    # 3. System update daemons
    m4 = evaluate_nintendo_telemetry("sun.hac.lp1.d4c.srv.nintendo.net")
    assert m4 is not None

    # 4. Suffix wildcard matching (*.srv.nintendo.net)
    m5 = evaluate_nintendo_telemetry("custom-subdomain.srv.nintendo.net")
    assert m5 is not None


def test_vacuum_privacy_shield():
    # Ecovacs open API / telemetry
    m1 = evaluate_vacuum_telemetry("open.ecovacs.com")
    assert m1 is not None
    assert m1.shield_type == "VACUUM_PRIVACY"
    assert m1.target_category == "VACUUM_ROBOT"

    m2 = evaluate_vacuum_telemetry("gl-iot-media.ecouser.net")
    assert m2 is not None
    assert m2.shield_type == "VACUUM_PRIVACY"

    # Dreame telemetry
    m3 = evaluate_vacuum_telemetry("log.dreame.tech")
    assert m3 is not None

    # Roborock tracking & telemetry
    m4 = evaluate_vacuum_telemetry("tracking.roborock.com")
    assert m4 is not None

    m5 = evaluate_vacuum_telemetry("api-telemetry.roborock.com")
    assert m5 is not None


def test_bambu_ip_shield():
    # Bambu Lab diagnostics and log uploaders
    m1 = evaluate_bambu_telemetry("log.bambulab.com")
    assert m1 is not None
    assert m1.shield_type == "BAMBU_IP_SHIELD"
    assert m1.target_category == "3D_PRINTER"

    m2 = evaluate_bambu_telemetry("analytics.bambulab.com")
    assert m2 is not None

    m3 = evaluate_bambu_telemetry("crash.bambulab.com")
    assert m3 is not None


def test_gaming_jitter_optimizer():
    # Steam telemetry & crash reporter
    m1 = evaluate_gaming_jitter_telemetry("crash.steampowered.com")
    assert m1 is not None
    assert m1.shield_type == "GAMING_JITTER"
    assert m1.target_category == "COMPUTER"

    m2 = evaluate_gaming_jitter_telemetry("telemetry.steampowered.com")
    assert m2 is not None

    # Epic Games datarouter
    m3 = evaluate_gaming_jitter_telemetry("datarouter.ol.epicgames.com")
    assert m3 is not None

    # EA telemetry
    m4 = evaluate_gaming_jitter_telemetry("pin-river.data.ea.com")
    assert m4 is not None

    # Blizzard telemetry
    m5 = evaluate_gaming_jitter_telemetry("blizzard-telemetry.com")
    assert m5 is not None


def test_benign_domains_not_intercepted():
    # Core gaming services (store, matchmaking, official apex) must NOT be blocked
    assert evaluate_device_shield("steampowered.com") is None
    assert evaluate_device_shield("store.steampowered.com") is None
    assert evaluate_device_shield("epicgames.com") is None
    assert evaluate_device_shield("nintendo.com") is None
    assert evaluate_device_shield("bambulab.com") is None
    assert evaluate_device_shield("roborock.com") is None
    assert evaluate_device_shield("ecovacs.com") is None
    assert evaluate_device_shield("google.com") is None


def test_evaluate_device_shield_unified_dispatcher():
    # Verifies all 4 categories resolve properly via evaluate_device_shield()
    r_nintendo = evaluate_device_shield("receive-lp1.er.srv.nintendo.net")
    assert r_nintendo is not None
    assert r_nintendo.shield_type == "NINTENDO_90DNS"

    r_bambu = evaluate_device_shield("log.bambulab.com")
    assert r_bambu is not None
    assert r_bambu.shield_type == "BAMBU_IP_SHIELD"

    r_vacuum = evaluate_device_shield("log.dreame.tech")
    assert r_vacuum is not None
    assert r_vacuum.shield_type == "VACUUM_PRIVACY"

    r_gaming = evaluate_device_shield("telemetry.steampowered.com")
    assert r_gaming is not None
    assert r_gaming.shield_type == "GAMING_JITTER"
