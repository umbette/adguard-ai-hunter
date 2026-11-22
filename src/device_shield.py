"""
Sentinel Device Shield
======================
Specialized, zero-latency deterministic privacy and protection shields for:
1. 🎮 Nintendo Switch Anti-Ban & 90DNS Local Guard (prevents Error 2124-4007 hardware ban).
2. 🧹 Robot Vacuum Floorplan & Camera Privacy Guard (prevents video/LiDAR leaks on Roborock, Dreame, Ecovacs).
3. 🖨️ Bambu Lab Stealth & Maker IP Shield (blocks cloud telemetry & crash uploads, preserves LAN MQTT).
4. ⚡ Steam & PC Gaming Latency / Jitter Optimizer (silences launcher telemetry bursts).
"""

import re
import os
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Any

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger("ai_hunter.device_shield")

@dataclass
class DeviceShieldMatch:
    domain: str
    shield_type: str  # "NINTENDO_90DNS", "VACUUM_PRIVACY", "BAMBU_IP_SHIELD", "GAMING_JITTER"
    target_category: str  # "GAMING_CONSOLE", "VACUUM_ROBOT", "3D_PRINTER", "COMPUTER"
    rule_pattern: str
    risk_score: float
    description: str

# ---------------------------------------------------------------------------
# 0. 🛡️ Essential Companion App Control Allowlist (Pre-emption)
# (Prevents blocking of mobile companion app control, login, pairing & state sync)
# ---------------------------------------------------------------------------
ESSENTIAL_COMPANION_ALLOWLIST: Set[str] = {
    # Ecovacs Vacuums
    "api-app.ww.ecouser.net",
    "api-app.dc-eu.ww.ecouser.net",
    "iot-api-nlp.dc-eu.ww.ecouser.net",
    "codepush-base.dc-na.ww.ecouser.net",
    "gl-es-api.ecovacs.com",
    # Roborock Vacuums
    "api-eu.roborock.com",
    "api.roborock.com",
    "mqtt-eu.roborock.com",
    "rrc-eu.roborock.com",
    # Dreame Vacuums
    "api.dreame.tech",
    "iot.dreame.tech",
    "dreamehome-api.dreame.tech",
    # iRobot
    "api.irobot.com",
    # Bambu Lab 3D Printers
    "api.bambulab.com",
    "user-cloud.bambulab.com",
    # Prusa 3D Printers
    "connect.prusa3d.com",
    # Smart Kitchen / Cosori / Vesync
    "smart-api.vesync.com",
    "api.vesync.com",
    # Smart Home Relays & Hubs
    "shelly-cloud.com",
    "shelly.cloud",
    "api.coolkit.cc",
    "openapi.tuyaeu.com",
    "m2.tuyaeu.com",
    # Connected Vehicles Essential APIs
    "owner-api.teslamotors.com",
    "b2vapi.bmwgroup.com",
    # Hospitality POS, Payments & Food Delivery Essential APIs
    "api.sumup.com",
    "pos.nexi.it",
    "mpos.nexi.it",
    "api.satispay.com",
    "auth.satispay.com",
    "api.stripe.com",
    "api.deliveroo.com",
    "consumer-ow.deliveroo.com",
    "api.justeat.com",
    "consumer.just-eat.it",
    "api.glovoapp.com",
    "glovoapp.com",
    "ubereats.com",
    "leggimenu.it",
    "qrmenu.net",
    "dish.co",
}


DEVICE_PROFILES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sources", "device_profiles.yaml"
)


def load_device_profiles(filepath: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads device profiles from sources/device_profiles.yaml and populates ESSENTIAL_COMPANION_ALLOWLIST."""
    if yaml is None:
        return []
    target_path = filepath or DEVICE_PROFILES_PATH
    if not os.path.exists(target_path):
        return []
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            devices = data.get("devices", [])
            for dev in devices:
                control = dev.get("control_plane", {})
                for domain in control.get("allowed_domains", []):
                    if domain:
                        ESSENTIAL_COMPANION_ALLOWLIST.add(domain.lower().strip())
            return devices
    except Exception as e:
        logger.warning(f"Failed to load device profiles from {target_path}: {e}")
        return []


def add_runtime_allowlist_domain(domain: str) -> None:
    """Dynamically adds a domain to the in-memory essential companion allowlist at runtime."""
    if domain:
        cleaned = domain.lower().strip().lstrip(".").rstrip(".")
        if cleaned:
            ESSENTIAL_COMPANION_ALLOWLIST.add(cleaned)


# Populate allowlist with crowdsourced profiles on initial import
load_device_profiles()


def is_essential_companion_domain(hostname: str) -> bool:
    """Checks whether a domain is a critical companion app control channel that must not be blocked."""
    if not hostname:
        return False
    return hostname.lower().strip() in ESSENTIAL_COMPANION_ALLOWLIST


# ---------------------------------------------------------------------------
# 1. 🎮 Nintendo Switch 90DNS Anti-Ban Catalog
# ---------------------------------------------------------------------------
NINTENDO_EXACT_BLOCKS: Set[str] = {
    "receive-lp1.er.srv.nintendo.net",
    "receive-lp1.dg.srv.nintendo.net",
    "dauth-lp1.ndas.srv.nintendo.net",
    "aauth-lp1.ndas.srv.nintendo.net",
    "sun.hac.lp1.d4c.srv.nintendo.net",
    "sun.hac.lp1.services.nintendo.net",
    "beach.hac.lp1.eshop.srv.nintendo.net",
    "ctest.cdn.nintendo.net",
}

NINTENDO_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".srv.nintendo.net",
    ".ndas.srv.nintendo.net",
    ".sun.nintendo.net",
)

# ---------------------------------------------------------------------------
# 2. 🧹 Robot Vacuum Floorplan & Camera Privacy Catalog
# ---------------------------------------------------------------------------
VACUUM_EXACT_BLOCKS: Set[str] = {
    "open.ecovacs.com",
    "sa-eu-datasink.ecovacs.com",
    "bigdata-europe.ecovacs.com",
    "gl-iot-media.ecouser.net",
    "log.dreame.tech",
    "tracking.dreame.tech",
    "log.roborock.com",
    "tracking.roborock.com",
    "api-telemetry.roborock.com",
}

VACUUM_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".open.ecovacs.com",
    ".datasink.ecovacs.com",
    ".bigdata.ecovacs.com",
    ".gl-iot-media.ecouser.net",
    ".tracking.roborock.com",
    ".log.dreame.tech",
)

# ---------------------------------------------------------------------------
# 3. 🖨️ Bambu Lab 3D Printer IP & Telemetry Shield
# ---------------------------------------------------------------------------
BAMBU_EXACT_BLOCKS: Set[str] = {
    "log.bambulab.com",
    "analytics.bambulab.com",
    "tracking.bambulab.com",
    "crash.bambulab.com",
    "e.bambulab.com",
}

# ---------------------------------------------------------------------------
# 4. ⚡ Steam & PC Gaming Latency / Jitter Optimizer Catalog
# ---------------------------------------------------------------------------
GAMING_JITTER_EXACT_BLOCKS: Set[str] = {
    "crash.steampowered.com",
    "telemetry.steampowered.com",
    "valve-telemetry.steampowered.com",
    "datarouter.ol.epicgames.com",
    "telemetry-public-service-prod.ol.epicgames.com",
    "tracking.epicgames.com",
    "pin-river.data.ea.com",
    "telemetry.ea.com",
    "blizzard-telemetry.com",
    "telemetry.battle.net",
    "telemetry.riotgames.com",
}

GAMING_JITTER_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".telemetry.steampowered.com",
    ".datarouter.ol.epicgames.com",
    ".telemetry.battle.net",
)

# ---------------------------------------------------------------------------
# 5. 🍳 Smart Appliance & Connected Kitchen Privacy Catalog
# (Air Fryers, Smart Multicookers, Smart Fridges leaking to ad-brokers)
# ---------------------------------------------------------------------------
APPLIANCE_EXACT_BLOCKS: Set[str] = {
    "ad.intl.xiaomi.com",
    "data.mistat.intl.xiaomi.com",
    "tracking.miui.com",
    "log.byteoversea.com",
    "toblog.ctobsnssdk.com",
    "hm.baidu.com",
    "analytics.tuyaeu.com",
    "analytics.tuyaus.com",
    "log.tuya.com",
    "tracking.vesync.com",
    "telemetry.cosori.com",
}

APPLIANCE_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".byteoversea.com",
    ".ctobsnssdk.com",
    ".mistat.intl.xiaomi.com",
)

# ---------------------------------------------------------------------------
# 6. 📷 Low-Cost IP Camera P2P Hole-Punching & Video Relay Catalog
# (ThroughTek Kalay, V380, Xiongmai, CS2 P2P tunneling through foreign relays)
# ---------------------------------------------------------------------------
CAMERA_P2P_EXACT_BLOCKS: Set[str] = {
    "tutk.com",
    "iotcplatform.com",
    "p2pcam.net",
    "v380.net",
    "xmeye.net",
    "cs2-network.com",
    "eye4.so",
    "dvr163.com",
}

CAMERA_P2P_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".iotcplatform.com",
    ".p2pcam.net",
    ".v380.net",
    ".xmeye.net",
    ".tutk.com",
    ".cs2-network.com",
    ".eye4.so",
)

# ---------------------------------------------------------------------------
# 7. 🧒 Youth Safeguard: Anti-Grooming, Deepfake AI Nudify & Predatory Videochats
# (Child protection from online predators, anonymous videochats, predatory gambling)
# ---------------------------------------------------------------------------
YOUTH_EXACT_BLOCKS: Set[str] = {
    "nudify.online",
    "undress.app",
    "deepnude.to",
    "nudify.top",
    "clothoff.io",
    "undress.cc",
    "ome.tv",
    "chatext.com",
    "monkey.app",
    "chatrandom.com",
    "bazoocam.org",
    "chatspin.com",
    "csgoempire.com",
    "hellcase.com",
    "datdrop.com",
    "roblox-trade.com",
}

YOUTH_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".nudify.online",
    ".undress.app",
    ".deepnude.to",
    ".ome.tv",
    ".chatrandom.com",
    ".csgoempire.com",
)

# ---------------------------------------------------------------------------
# 8. 🚗 Connected Car Telemetry & Insurance Broker Shield
# (LexisNexis, Verisk, Otonomo selling driver braking/speed data to insurers)
# ---------------------------------------------------------------------------
AUTOMOTIVE_EXACT_BLOCKS: Set[str] = {
    "telemetry.lexisnexis.com",
    "risk.lexisnexis.com",
    "auto.lexisnexis.com",
    "telematics.verisk.com",
    "api.otonomo.io",
    "telemetry.otonomo.io",
    "telemetry.connected-car.io",
    "telemetry.bmw.com",
    "telemetry.mercedes-benz.com",
}

AUTOMOTIVE_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".lexisnexis.com",
    ".otonomo.io",
)

# ---------------------------------------------------------------------------
# 9. 🧸 Smart Toy Audio & Child Microphone Leak Shield
# (Unencrypted microphone beacons & third-party voice cloud uploads)
# ---------------------------------------------------------------------------
SMART_TOY_EXACT_BLOCKS: Set[str] = {
    "linglong.com",
    "turingos.cn",
    "voicecloud.cn",
    "api.ai-toy.net",
}

SMART_TOY_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".turingos.cn",
    ".voicecloud.cn",
)

# ---------------------------------------------------------------------------
# 10. 📦 Budget AOSP & Android TV Box Badbox Malware C2 Shield
# (Peachpit / Badbox botnet preinstalled on budget Allwinner/Amlogic TV boxes)
# ---------------------------------------------------------------------------
BADBOX_EXACT_BLOCKS: Set[str] = {
    "cbty2021.com",
    "b2c.aospbox.net",
    "mykingbox.com",
    "update.tvboxapi.com",
    "vip.aospota.com",
}

BADBOX_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".aospbox.net",
    ".mykingbox.com",
    ".tvboxapi.com",
)


def evaluate_nintendo_telemetry(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets Nintendo telemetry or certification servers."""
    h_lower = hostname.lower().strip()
    if h_lower in NINTENDO_EXACT_BLOCKS or any(h_lower.endswith(s) for s in NINTENDO_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="NINTENDO_90DNS",
            target_category="GAMING_CONSOLE",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.95,
            description="Nintendo Anti-Ban: blocco telemetria e verifica certificati (previene Errore 2124-4007 su Atmosphere CFW)."
        )
    return None


def evaluate_vacuum_telemetry(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets vacuum video, LiDAR, or floorplan cloud uploaders."""
    h_lower = hostname.lower().strip()
    if h_lower in VACUUM_EXACT_BLOCKS or any(h_lower.endswith(s) for s in VACUUM_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="VACUUM_PRIVACY",
            target_category="VACUUM_ROBOT",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.85,
            description="Vacuum Privacy: blocco upload streaming video, foto e mappe LiDAR su cloud cinese; controllo locale preservato."
        )
    return None


def evaluate_bambu_telemetry(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets Bambu Lab cloud diagnostic & telemetry uploads."""
    h_lower = hostname.lower().strip()
    if h_lower in BAMBU_EXACT_BLOCKS:
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="BAMBU_IP_SHIELD",
            target_category="3D_PRINTER",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.80,
            description="Bambu Lab Stealth: blocco invio log diagnostici e telemetria CAD cloud; LAN MQTT e Home Assistant preservati."
        )
    return None


def evaluate_gaming_jitter_telemetry(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets PC gaming launcher telemetry causing bufferbloat."""
    h_lower = hostname.lower().strip()
    if h_lower in GAMING_JITTER_EXACT_BLOCKS or any(h_lower.endswith(s) for s in GAMING_JITTER_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="GAMING_JITTER",
            target_category="COMPUTER",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.60,
            description="Gaming Jitter Optimizer: silenziamento diagnostica launcher in background per azzerare micro-lag e packet jitter."
        )
    return None


def evaluate_appliance_telemetry(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets smart appliance profiling and ad tracking networks."""
    h_lower = hostname.lower().strip()
    if h_lower in APPLIANCE_EXACT_BLOCKS or any(h_lower.endswith(s) for s in APPLIANCE_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="APPLIANCE_PRIVACY",
            target_category="SMART_APPLIANCE",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.85,
            description="Smart Appliance Privacy: blocco profilazione ad/tracker su friggitrici ad aria, multicooker e frigoriferi connessi."
        )
    return None


def evaluate_camera_p2p_telemetry(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets unencrypted P2P relay servers or IP camera hole punching."""
    h_lower = hostname.lower().strip()
    if h_lower in CAMERA_P2P_EXACT_BLOCKS or any(h_lower.endswith(s) for s in CAMERA_P2P_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="CAMERA_P2P_ISOLATION",
            target_category="IP_CAMERA",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.90,
            description="Camera P2P Isolation: blocco tunnel P2P e relay cloud vulnerabili; streaming locale RTSP/WebRTC preservato."
        )
    return None


def evaluate_youth_safeguard_telemetry(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets child grooming, predatory videochats, or deepfake AI generators."""
    h_lower = hostname.lower().strip()
    if h_lower in YOUTH_EXACT_BLOCKS or any(h_lower.endswith(s) for s in YOUTH_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="YOUTH_SAFEGUARD",
            target_category="YOUTH_DEVICE",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.99,
            description="Youth Safeguard: blocco piattaforme di grooming, videochat anonime non moderate e generatori deepfake AI."
        )
    return None


def evaluate_automotive_telemetry(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets driving telemetry data brokers or insurance profiling."""
    h_lower = hostname.lower().strip()
    if h_lower in AUTOMOTIVE_EXACT_BLOCKS or any(h_lower.endswith(s) for s in AUTOMOTIVE_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="AUTOMOTIVE_TELEMETRY",
            target_category="CONNECTED_CAR",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.85,
            description="Automotive Sovereignty: blocco profilazione di guida per broker assicurativi (LexisNexis/Verisk); aggiornamenti OTA preservati."
        )
    return None


def evaluate_smart_toy_telemetry(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets unencrypted child voice recordings or smart toy leaks."""
    h_lower = hostname.lower().strip()
    if h_lower in SMART_TOY_EXACT_BLOCKS or any(h_lower.endswith(s) for s in SMART_TOY_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="SMART_TOY_AUDIO",
            target_category="SMART_TOY",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.95,
            description="Smart Toy Privacy: blocco upload registrazioni audio e microfono cameretta verso cloud esteri non conformi COPPA/GDPR."
        )
    return None


def evaluate_badbox_malware(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets Badbox / Peachpit AOSP malware command & control."""
    h_lower = hostname.lower().strip()
    if h_lower in BADBOX_EXACT_BLOCKS or any(h_lower.endswith(s) for s in BADBOX_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="BADBOX_MALWARE",
            target_category="BUDGET_AOSP_DEVICE",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.98,
            description="Badbox & Peachpit Neutralizer: blocco C2 malware e click-fraud preinstallati su TV Box e Smart TV cinesi low-cost."
        )
    return None


# ---------------------------------------------------------------------------
# 11. 🍕 Public Venue & Guest Network Policy Guard
# (Blocks BitTorrent trackers, crypto mining scripts, heavy video ads; preserves POS & delivery)
# ---------------------------------------------------------------------------
PUBLIC_VENUE_EXACT_BLOCKS: Set[str] = {
    "tracker.opentrackr.org",
    "open.stealth.si",
    "tracker.torrent.eu.org",
    "retracker.net",
    "tracker.openbittorrent.com",
    "coinhive.com",
    "coin-hive.com",
    "crypto-loot.com",
    "minr.pw",
    "adcolony.com",
    "vungle.com",
    "cpmstar.com",
}

PUBLIC_VENUE_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".opentrackr.org",
    ".openbittorrent.com",
    ".coinhive.com",
    ".crypto-loot.com",
    ".adcolony.com",
    ".vungle.com",
)


def evaluate_public_venue_shield(hostname: str) -> Optional[DeviceShieldMatch]:
    """Evaluates whether a domain targets public guest abuse (torrent bootstrap trackers, cryptomining, video-ad bandwidth hogs)."""
    h_lower = hostname.lower().strip()
    if h_lower in PUBLIC_VENUE_EXACT_BLOCKS or any(h_lower.endswith(s) for s in PUBLIC_VENUE_SUFFIX_BLOCKS):
        return DeviceShieldMatch(
            domain=h_lower,
            shield_type="PUBLIC_VENUE_GUEST",
            target_category="HOSPITALITY_NETWORK",
            rule_pattern=f"||{h_lower}^",
            risk_score=0.90,
            description="Public Venue & Guest Policy: blocco tracker invasivi, background cryptomining e video-ad saturanti su reti pubbliche; preserva POS, comande e app delivery."
        )
    return None


def evaluate_device_shield(hostname: str, device_type: Optional[str] = None) -> Optional[DeviceShieldMatch]:
    """
    Unified dispatcher for specialized device shields.
    Prioritizes matches according to device category context when available,
    or falls back to domain-based signatures.
    """
    if not hostname:
        return None

    # Pre-emption: Essential companion app control APIs must never be blocked
    if is_essential_companion_domain(hostname):
        return None

    # 1. Check Nintendo 90DNS
    match = evaluate_nintendo_telemetry(hostname)
    if match:
        return match

    # 2. Check Bambu Lab IP Shield
    match = evaluate_bambu_telemetry(hostname)
    if match:
        return match

    # 3. Check Vacuum Privacy Shield
    match = evaluate_vacuum_telemetry(hostname)
    if match:
        return match

    # 4. Check Gaming Launcher Jitter Telemetry
    match = evaluate_gaming_jitter_telemetry(hostname)
    if match:
        return match

    # 5. Check Smart Appliance Privacy Shield
    match = evaluate_appliance_telemetry(hostname)
    if match:
        return match

    # 6. Check Low-Cost IP Camera P2P Relay Isolation
    match = evaluate_camera_p2p_telemetry(hostname)
    if match:
        return match

    # 7. Check Youth Safeguard Shield
    match = evaluate_youth_safeguard_telemetry(hostname)
    if match:
        return match

    # 8. Check Automotive Telemetry & Insurance Shield
    match = evaluate_automotive_telemetry(hostname)
    if match:
        return match

    # 9. Check Smart Toy Audio & Microphone Shield
    match = evaluate_smart_toy_telemetry(hostname)
    if match:
        return match

    # 10. Check Badbox / Peachpit AOSP Malware Shield
    match = evaluate_badbox_malware(hostname)
    if match:
        return match

    # 11. Check Public Venue & Guest Network Policy Guard
    match = evaluate_public_venue_shield(hostname)
    if match:
        return match

    return None
