#!/usr/bin/env python3
"""
AI Hunter - Chrome Declarative Net Request (DNR) Ruleset Exporter
Converts active IoCs from ThreatStateDB into Manifest V3 declarativeNetRequest JSON rules.
"""

import json
import logging
import sys
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.proactive_miner import ThreatStateDB, DB_PATH, ROOT_DIR as MINER_ROOT
from scripts.build_filter import load_never_block

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("export_dnr")

EXTENSION_DIR = ROOT_DIR / "extension"
RULES_DIR = EXTENSION_DIR / "rules"
DNR_OUTPUT_FILE = RULES_DIR / "ruleset.json"
MAX_STATIC_RULES = 30000


def compile_dnr_ruleset(db_path: Path = DB_PATH, output_file: Path = DNR_OUTPUT_FILE, min_confidence: int = 85) -> dict:
    """
    Compiles active IoCs into Chrome Manifest V3 declarativeNetRequest static rules.
    - main_frame requests: redirected to extension's blocked.html with metadata.
    - subresources: blocked directly at browser network layer.
    Enforces the <= 30,000 rules quota for static rulesets and filters by confidence >= min_confidence.
    """
    db = ThreatStateDB(db_path=db_path)
    active_domains = db.get_active_domains(min_confidence=min_confidence)
    whitelist = load_never_block()

    logger.info(f"Loaded {len(active_domains)} active threat domains from DB (min_confidence >= {min_confidence}).")
    logger.info(f"Loaded {len(whitelist)} protected whitelist entries.")

    rules = []
    rule_id = 1

    for domain in active_domains:
        dom_clean = domain.strip().lower()
        if not dom_clean or dom_clean in whitelist:
            continue
        # Also ensure domain doesn't end with any whitelist domain
        if any(dom_clean.endswith(f".{w}") for w in whitelist):
            continue

        # Rule 1: Redirect main_frame navigation to informative blocked.html
        redirect_rule = {
            "id": rule_id,
            "priority": 1,
            "action": {
                "type": "redirect",
                "redirect": {
                    "extensionPath": f"/pages/blocked.html?domain={dom_clean}"
                }
            },
            "condition": {
                "urlFilter": f"||{dom_clean}^",
                "resourceTypes": ["main_frame"]
            }
        }
        rules.append(redirect_rule)
        rule_id += 1

        # Rule 2: Hard-block all subresource network requests
        block_rule = {
            "id": rule_id,
            "priority": 1,
            "action": {
                "type": "block"
            },
            "condition": {
                "urlFilter": f"||{dom_clean}^",
                "resourceTypes": [
                    "sub_frame",
                    "stylesheet",
                    "script",
                    "image",
                    "xmlhttprequest",
                    "websocket",
                    "other"
                ]
            }
        }
        rules.append(block_rule)
        rule_id += 1

        if len(rules) >= MAX_STATIC_RULES:
            logger.warning(f"Reached Manifest V3 DNR static rule ceiling ({MAX_STATIC_RULES}). Truncating export.")
            break

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)

    logger.info(f"Successfully compiled {len(rules)} DNR rules ({rule_id // 2} domains) into {output_file}")
    return {
        "total_rules": len(rules),
        "domains_covered": rule_id // 2,
        "output_path": str(output_file)
    }


if __name__ == "__main__":
    compile_dnr_ruleset()
