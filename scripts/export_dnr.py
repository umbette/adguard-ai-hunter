#!/usr/bin/env python3
"""
Sentinel Shield - Chrome Declarative Net Request (DNR) Ruleset Exporter
Converts active IoCs from ThreatStateDB into Manifest V3 declarativeNetRequest JSON rules.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

# Paths
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.proactive_miner import ThreatStateDB, DB_PATH, ROOT_DIR as MINER_ROOT
from scripts.build_filter import load_never_block
from src.dynamic_pricing import DYNAMIC_PRICING_NETWORKS
from src.ip_intel import is_protected_ip

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("export_dnr")

EXTENSION_DIR = ROOT_DIR / "extension"
RULES_DIR = EXTENSION_DIR / "rules"
DATA_DIR = EXTENSION_DIR / "data"
DNR_OUTPUT_FILE = RULES_DIR / "ruleset.json"
PRICING_DNR_OUTPUT_FILE = RULES_DIR / "pricing_trackers.json"
DOMAINS_OUTPUT_FILE = DATA_DIR / "blocked_domains.json"
IPS_OUTPUT_FILE = DATA_DIR / "blocked_ips.json"
MAX_STATIC_RULES = 30000

# Exhaustive list of all valid declarativeNetRequest resource types defined in Chrome Manifest V3 API
ALL_RESOURCE_TYPES = [
    "main_frame",
    "sub_frame",
    "stylesheet",
    "script",
    "image",
    "font",
    "object",
    "xmlhttprequest",
    "ping",
    "csp_report",
    "media",
    "websocket",
    "webtransport",
    "webbundle",
    "other"
]

# Subresource types for third-party tracker & dynamic pricing blocking (preserves direct main_frame navigation)
THIRD_PARTY_SUBRESOURCE_TYPES = [t for t in ALL_RESOURCE_TYPES if t != "main_frame"]

# Curated third-party ad-tech, cookie-sync, behavioral analytics, and social pixel networks
THIRD_PARTY_TRACKER_DOMAINS = [
    # Ad-Tech & Cookie Sync Brokers
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
    "adnxs.com", "rubiconproject.com", "pubmatic.com", "openx.net", "casalemedia.com",
    "taboola.com", "outbrain.com", "scorecardresearch.com", "quantserve.com",
    "bluekai.com", "krxd.net", "rlcdn.com", "tapad.com", "sharethrough.com",
    "33across.com", "smartadserver.com", "adsrvr.org", "bidswitch.net",
    "mathtag.com", "mediamath.com", "indexww.com", "triplelift.com", "teads.tv",
    "mgid.com", "revcontent.com",
    # Behavioral Analytics & Session Profiling
    "mixpanel.com", "amplitude.com", "heapanalytics.com", "crazyegg.com",
    "luckyorange.com", "clarity.ms", "inspectlet.com", "contentsquare.net",
    "chartbeat.com", "parsely.com", "omtrdc.net", "2o7.net",
    # Third-Party Social Tracking Pixels (blocked only in thirdParty context)
    "connect.facebook.net", "pixel.facebook.com", "analytics.tiktok.com",
    "px.ads.linkedin.com", "snap.licdn.com", "analytics.twitter.com",
    "ads-twitter.com", "ct.pinterest.com", "tr.snapchat.com", "bat.bing.com"
]


def compile_dnr_ruleset(
    db_path: Path = DB_PATH,
    output_file: Path = DNR_OUTPUT_FILE,
    domains_output_file: Path = DOMAINS_OUTPUT_FILE,
    min_confidence: int = 85,
    ips_output_file: Optional[Path] = None,
) -> dict:
    """
    Compiles active IoCs into Chrome Manifest V3 declarativeNetRequest static rules.
    - Domains and high-confidence CDN-excluded bare IPs receive single MV3 block rules (0 host permissions).
    - Exports companion JSON arrays for Service Worker `onErrorOccurred` / popup inspection.
    Enforces the <= 30,000 rules quota for static rulesets and filters by confidence >= min_confidence.
    """
    db = ThreatStateDB(db_path=db_path)
    active_domains = db.get_active_domains(min_confidence=min_confidence)
    active_bare_ips = db.get_active_ips(min_confidence=min_confidence, bare_only=True)
    whitelist = load_never_block()

    logger.info(f"Loaded {len(active_domains)} active threat domains and {len(active_bare_ips)} bare C2 IPs from DB (min_confidence >= {min_confidence}).")
    logger.info(f"Loaded {len(whitelist)} protected whitelist entries.")

    rules = []
    blocked_domains = []
    blocked_ips = []
    rule_id = 1

    for domain in active_domains:
        dom_clean = domain.strip().lower()
        if not dom_clean or _is_whitelisted_domain(dom_clean, whitelist):
            continue

        # Single declarativeNetRequest block rule covering main_frame and all subresources.
        # Action type "block" requires ZERO host permissions, keeping extension permissions minimal.
        block_rule = {
            "id": rule_id,
            "priority": 1,
            "action": {
                "type": "block"
            },
            "condition": {
                "urlFilter": f"||{dom_clean}^",
                "resourceTypes": ALL_RESOURCE_TYPES
            }
        }
        rules.append(block_rule)
        blocked_domains.append(dom_clean)
        rule_id += 1

        if len(rules) >= MAX_STATIC_RULES:
            logger.warning(f"Reached Manifest V3 DNR static rule ceiling ({MAX_STATIC_RULES}). Truncating export.")
            break

    for bare_ip in active_bare_ips:
        if len(rules) >= MAX_STATIC_RULES:
            break
        ip_clean = bare_ip.strip().lower()
        if not ip_clean or is_protected_ip(ip_clean):
            continue
        url_host = f"[{ip_clean}]" if ":" in ip_clean else ip_clean
        rules.append({
            "id": rule_id,
            "priority": 1,
            "action": {"type": "block"},
            "condition": {
                "urlFilter": f"||{url_host}^",
                "resourceTypes": ALL_RESOURCE_TYPES,
            },
        })
        blocked_ips.append(ip_clean)
        rule_id += 1

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)

    # Also export compact arrays for ultra-fast, low-memory Service Worker inspection
    if domains_output_file:
        domains_output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(domains_output_file, "w", encoding="utf-8") as f:
            json.dump(blocked_domains, f)

    ips_target = ips_output_file or (
        IPS_OUTPUT_FILE if output_file == DNR_OUTPUT_FILE else output_file.parent / "blocked_ips.json"
    )
    if ips_target:
        ips_target.parent.mkdir(parents=True, exist_ok=True)
        with open(ips_target, "w", encoding="utf-8") as f:
            json.dump(blocked_ips, f)

    logger.info(
        f"Successfully compiled {len(rules)} DNR rules ({len(blocked_domains)} domains, {len(blocked_ips)} bare IPs) into {output_file}"
    )
    return {
        "total_rules": len(rules),
        "domains_covered": len(blocked_domains),
        "ips_covered": len(blocked_ips),
        "output_path": str(output_file),
    }


def _is_whitelisted_domain(domain: str, whitelist: set[str]) -> bool:
    return domain in whitelist or any(domain.endswith(f".{w}") for w in whitelist)


def compile_pricing_tracker_ruleset(output_file: Path = PRICING_DNR_OUTPUT_FILE) -> dict:
    """
    Compiles third-party Anti-Dynamic Pricing (sourced from src.dynamic_pricing)
    and cross-site behavioral/cookie-sync tracker domains into Manifest V3 DNR rules.
    Uses domainType="thirdParty" and excludes main_frame so 0 host_permissions are required
    and direct navigation remains intact.
    """
    whitelist = load_never_block()
    candidate_domains = sorted(set(DYNAMIC_PRICING_NETWORKS.keys()) | set(THIRD_PARTY_TRACKER_DOMAINS))

    rules = []
    rule_id = 1
    for domain in candidate_domains:
        dom_clean = domain.strip().lower()
        if not dom_clean or _is_whitelisted_domain(dom_clean, whitelist):
            continue

        rules.append({
            "id": rule_id,
            "priority": 1,
            "action": {"type": "block"},
            "condition": {
                "urlFilter": f"||{dom_clean}^",
                "domainType": "thirdParty",
                "resourceTypes": THIRD_PARTY_SUBRESOURCE_TYPES,
            },
        })
        rule_id += 1
        if len(rules) >= MAX_STATIC_RULES:
            break

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)

    logger.info(f"Compiled {len(rules)} third-party pricing & tracker DNR rules into {output_file}")
    return {
        "total_rules": len(rules),
        "pricing_domains": len(DYNAMIC_PRICING_NETWORKS),
        "output_path": str(output_file),
    }


if __name__ == "__main__":
    compile_dnr_ruleset()
    compile_pricing_tracker_ruleset()
