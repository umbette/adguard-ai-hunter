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
    evaluate_public_venue_shield,
    is_essential_companion_domain,
    evaluate_device_shield,
    DeviceShieldMatch
)

def test_gaming_console_telemetry():
    # 1. Error & Diagnostic telemetry endpoints are blocked
    m1 = evaluate_nintendo_telemetry("receive-lp1.er.srv.nintendo.net")
    assert m1 is not None
    assert m1.shield_type == "CONSOLE_TELEMETRY"
    assert m1.target_category == "GAMING_CONSOLE"
    assert "Console Telemetry" in m1.description

    # 2. PlayStation / Xbox telemetry is blocked
    m_psn = evaluate_nintendo_telemetry("telemetry.playstation.com")
    assert m_psn is not None

    # 3. Critical store & online play authentication must NOT be blocked (SysNAND Safe)
    assert evaluate_nintendo_telemetry("dauth-lp1.ndas.srv.nintendo.net") is None
    assert evaluate_nintendo_telemetry("aauth-lp1.ndas.srv.nintendo.net") is None
    assert evaluate_nintendo_telemetry("ctest.cdn.nintendo.net") is None


def test_shield_toggle_and_snooze():
    from src.device_shield import set_shield_status, is_shield_active, get_shield_status

    # 1. Set to PAUSED_1H
    res = set_shield_status("console_telemetry", "PAUSED_1H")
    assert res["status"] == "PAUSED_1H"
    assert is_shield_active("console_telemetry") is False

    # 2. Evaluation should bypass when paused
    assert evaluate_device_shield("receive-lp1.er.srv.nintendo.net") is None

    # 3. Reactivate
    set_shield_status("console_telemetry", "ACTIVE")
    assert is_shield_active("console_telemetry") is True
    assert evaluate_device_shield("receive-lp1.er.srv.nintendo.net") is not None



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
    assert r_nintendo.shield_type == "CONSOLE_TELEMETRY"

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


def test_essential_companion_allowlist_preemption():
    # Ecovacs companion app APIs
    assert is_essential_companion_domain("api-app.ww.ecouser.net") is True
    assert is_essential_companion_domain("api-app.dc-eu.ww.ecouser.net") is True
    assert evaluate_device_shield("api-app.ww.ecouser.net") is None

    # Roborock companion app APIs
    assert is_essential_companion_domain("api-eu.roborock.com") is True
    assert is_essential_companion_domain("mqtt-eu.roborock.com") is True
    assert evaluate_device_shield("api-eu.roborock.com") is None

    # Dreame companion app APIs
    assert is_essential_companion_domain("api.dreame.tech") is True
    assert evaluate_device_shield("api.dreame.tech") is None

    # Bambu Lab login & account pairing
    assert is_essential_companion_domain("api.bambulab.com") is True
    assert evaluate_device_shield("api.bambulab.com") is None

    # Tesla & BMW mobile app controls
    assert is_essential_companion_domain("owner-api.teslamotors.com") is True
    assert evaluate_device_shield("owner-api.teslamotors.com") is None
    assert is_essential_companion_domain("b2vapi.bmwgroup.com") is True
    assert evaluate_device_shield("b2vapi.bmwgroup.com") is None


def test_device_profiles_yaml_catalog_loading():
    from src.device_shield import load_device_profiles, add_runtime_allowlist_domain
    devices = load_device_profiles()
    assert len(devices) > 0
    device_ids = [d["id"] for d in devices]
    assert "ecovacs_deebot" in device_ids
    assert "bambulab_printer" in device_ids
    assert "connected_automotive" in device_ids
    assert "cosori_vesync_airfryer" in device_ids

    # Check that iRobot and smart tv domains were loaded
    assert is_essential_companion_domain("api.irobot.com") is True
    assert is_essential_companion_domain("api.smartthings.com") is True
    assert is_essential_companion_domain("thinq.com") is True
    assert is_essential_companion_domain("api.sumup.com") is True
    assert "public_venue_guest" in device_ids

    # Check runtime addition
    custom_dom = "runtime-companion-api.brand.io"
    assert is_essential_companion_domain(custom_dom) is False
    add_runtime_allowlist_domain(custom_dom)
    assert is_essential_companion_domain(custom_dom) is True


def test_public_venue_guest_shield():
    # 1. Blocks torrent bootstrap trackers
    m1 = evaluate_public_venue_shield("tracker.opentrackr.org")
    assert m1 is not None
    assert m1.shield_type == "PUBLIC_VENUE_GUEST"
    assert m1.target_category == "HOSPITALITY_NETWORK"
    assert m1.risk_score == 0.90

    # 2. Blocks background cryptomining
    m2 = evaluate_public_venue_shield("coinhive.com")
    assert m2 is not None
    assert m2.shield_type == "PUBLIC_VENUE_GUEST"

    # 3. Blocks aggressive video ad networks
    m3 = evaluate_public_venue_shield("adcolony.com")
    assert m3 is not None
    assert m3.shield_type == "PUBLIC_VENUE_GUEST"

    # 4. Suffix matching
    m4 = evaluate_public_venue_shield("sub.openbittorrent.com")
    assert m4 is not None

    # 5. Pre-emption: Essential POS and delivery apps must NOT be blocked
    assert evaluate_device_shield("api.sumup.com") is None
    assert evaluate_device_shield("pos.nexi.it") is None
    assert evaluate_device_shield("api.satispay.com") is None
    assert evaluate_device_shield("api.deliveroo.com") is None
    assert evaluate_device_shield("api.justeat.com") is None
    assert evaluate_device_shield("glovoapp.com") is None
