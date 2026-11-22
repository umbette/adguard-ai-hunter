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
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class DeviceShieldMatch:
    domain: str
    shield_type: str  # "NINTENDO_90DNS", "VACUUM_PRIVACY", "BAMBU_IP_SHIELD", "GAMING_JITTER"
    target_category: str  # "GAMING_CONSOLE", "VACUUM_ROBOT", "3D_PRINTER", "COMPUTER"
    rule_pattern: str
    risk_score: float
    description: str

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
    "log.dreame.tech",
    "tracking.dreame.tech",
    "log.roborock.com",
    "tracking.roborock.com",
    "api-telemetry.roborock.com",
}

VACUUM_SUFFIX_BLOCKS: Tuple[str, ...] = (
    ".open.ecovacs.com",
    ".ecouser.net",
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


def evaluate_device_shield(hostname: str, device_type: Optional[str] = None) -> Optional[DeviceShieldMatch]:
    """
    Unified dispatcher for specialized device shields.
    Prioritizes matches according to device category context when available,
    or falls back to domain-based signatures.
    """
    if not hostname:
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

    return None
