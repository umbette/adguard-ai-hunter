import pytest
from src.device_shield import (
    evaluate_nintendo_telemetry,
    evaluate_vacuum_telemetry,
    evaluate_bambu_telemetry,
    evaluate_gaming_jitter_telemetry,
    evaluate_appliance_telemetry,
    evaluate_camera_p2p_telemetry,
    evaluate_youth_safeguard_telemetry,
    evaluate_automotive_telemetry,
    evaluate_smart_toy_telemetry,
    evaluate_badbox_malware,
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

    m6 = evaluate_vacuum_telemetry("bigdata-europe.ecovacs.com")
    assert m6 is not None

    # CRITICAL: Official companion app control APIs must NOT be blocked
    assert evaluate_vacuum_telemetry("api-app.ww.ecouser.net") is None
    assert evaluate_vacuum_telemetry("api-app.dc-eu.ww.ecouser.net") is None
    assert evaluate_vacuum_telemetry("iot-api-nlp.dc-eu.ww.ecouser.net") is None
    assert evaluate_vacuum_telemetry("gl-es-api.ecovacs.com") is None


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


def test_appliance_privacy_shield():
    # Smart Air Fryer & Multicooker telemetry to ad-networks (Xiaomi, ByteDance, Baidu)
    m1 = evaluate_appliance_telemetry("ad.intl.xiaomi.com")
    assert m1 is not None
    assert m1.shield_type == "APPLIANCE_PRIVACY"
    assert m1.target_category == "SMART_APPLIANCE"

    m2 = evaluate_appliance_telemetry("log.byteoversea.com")
    assert m2 is not None
    assert m2.shield_type == "APPLIANCE_PRIVACY"

    m3 = evaluate_appliance_telemetry("tracking.vesync.com")
    assert m3 is not None
    assert m3.shield_type == "APPLIANCE_PRIVACY"

    m4 = evaluate_appliance_telemetry("telemetry.cosori.com")
    assert m4 is not None

    m5 = evaluate_appliance_telemetry("sub.ctobsnssdk.com")
    assert m5 is not None


def test_camera_p2p_isolation_shield():
    # Cheap IP camera P2P hole-punching and relay tunnels (ThroughTek Kalay, V380, Xiongmai)
    m1 = evaluate_camera_p2p_telemetry("iotcplatform.com")
    assert m1 is not None
    assert m1.shield_type == "CAMERA_P2P_ISOLATION"
    assert m1.target_category == "IP_CAMERA"

    m2 = evaluate_camera_p2p_telemetry("relay-01.iotcplatform.com")
    assert m2 is not None

    m3 = evaluate_camera_p2p_telemetry("v380.net")
    assert m3 is not None

    m4 = evaluate_camera_p2p_telemetry("xmeye.net")
    assert m4 is not None

    m5 = evaluate_camera_p2p_telemetry("cs2-network.com")
    assert m5 is not None


def test_youth_safeguard_shield():
    # 1. AI Deepfake / Nudify tools
    m1 = evaluate_youth_safeguard_telemetry("nudify.online")
    assert m1 is not None
    assert m1.shield_type == "YOUTH_SAFEGUARD"
    assert m1.target_category == "YOUTH_DEVICE"
    assert m1.risk_score >= 0.95

    m2 = evaluate_youth_safeguard_telemetry("app.undress.app")
    assert m2 is not None

    # 2. Predatory anonymous videochat platforms (Grooming / Sextortion)
    m3 = evaluate_youth_safeguard_telemetry("ome.tv")
    assert m3 is not None
    assert m3.shield_type == "YOUTH_SAFEGUARD"

    m4 = evaluate_youth_safeguard_telemetry("chatext.com")
    assert m4 is not None

    # 3. Predatory skins gambling targeting youth
    m5 = evaluate_youth_safeguard_telemetry("csgoempire.com")
    assert m5 is not None


def test_automotive_telemetry_shield():
    # LexisNexis driving score telemetry
    m1 = evaluate_automotive_telemetry("telemetry.lexisnexis.com")
    assert m1 is not None
    assert m1.shield_type == "AUTOMOTIVE_TELEMETRY"
    assert m1.target_category == "CONNECTED_CAR"

    m2 = evaluate_automotive_telemetry("driver-scoring.lexisnexis.com")
    assert m2 is not None

    # Verisk telematics
    m3 = evaluate_automotive_telemetry("telematics.verisk.com")
    assert m3 is not None

    # Otonomo vehicle data broker
    m4 = evaluate_automotive_telemetry("telemetry.otonomo.io")
    assert m4 is not None


def test_smart_toy_audio_shield():
    # Chinese voice cloud processing for smart toys
    m1 = evaluate_smart_toy_telemetry("turingos.cn")
    assert m1 is not None
    assert m1.shield_type == "SMART_TOY_AUDIO"
    assert m1.target_category == "SMART_TOY"

    m2 = evaluate_smart_toy_telemetry("child-voice.voicecloud.cn")
    assert m2 is not None


def test_badbox_malware_shield():
    # Badbox / Peachpit AOSP C2 & Click-fraud domains
    m1 = evaluate_badbox_malware("cbty2021.com")
    assert m1 is not None
    assert m1.shield_type == "BADBOX_MALWARE"
    assert m1.target_category == "BUDGET_AOSP_DEVICE"

    m2 = evaluate_badbox_malware("b2c.aospbox.net")
    assert m2 is not None

    m3 = evaluate_badbox_malware("mykingbox.com")
    assert m3 is not None


def test_benign_domains_not_intercepted():
    # Core gaming services, legitimate automotive apex, and search must NOT be blocked
    assert evaluate_device_shield("steampowered.com") is None
    assert evaluate_device_shield("store.steampowered.com") is None
    assert evaluate_device_shield("epicgames.com") is None
    assert evaluate_device_shield("nintendo.com") is None
    assert evaluate_device_shield("bambulab.com") is None
    assert evaluate_device_shield("roborock.com") is None
    assert evaluate_device_shield("ecovacs.com") is None
    assert evaluate_device_shield("xiaomi.com") is None
    assert evaluate_device_shield("tuya.com") is None
    assert evaluate_device_shield("vesync.com") is None
    assert evaluate_device_shield("tesla.com") is None
    assert evaluate_device_shield("bmw.com") is None
    assert evaluate_device_shield("volkswagen.com") is None
    assert evaluate_device_shield("google.com") is None


def test_evaluate_device_shield_unified_dispatcher():
    # Verifies all 10 categories resolve properly via evaluate_device_shield()
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

    r_appliance = evaluate_device_shield("ad.intl.xiaomi.com")
    assert r_appliance is not None
    assert r_appliance.shield_type == "APPLIANCE_PRIVACY"

    r_cam = evaluate_device_shield("relay.iotcplatform.com")
    assert r_cam is not None
    assert r_cam.shield_type == "CAMERA_P2P_ISOLATION"

    r_youth = evaluate_device_shield("nudify.online")
    assert r_youth is not None
    assert r_youth.shield_type == "YOUTH_SAFEGUARD"

    r_car = evaluate_device_shield("telemetry.lexisnexis.com")
    assert r_car is not None
    assert r_car.shield_type == "AUTOMOTIVE_TELEMETRY"

    r_toy = evaluate_device_shield("turingos.cn")
    assert r_toy is not None
    assert r_toy.shield_type == "SMART_TOY_AUDIO"

    r_badbox = evaluate_device_shield("b2c.aospbox.net")
    assert r_badbox is not None
    assert r_badbox.shield_type == "BADBOX_MALWARE"
