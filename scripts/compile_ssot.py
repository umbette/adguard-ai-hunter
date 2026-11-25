#!/usr/bin/env python3
"""
Sentinel Core Single Source of Truth (SSOT) Compiler & CI Drift Verifier
===================================================================
Compiles canonical brand registries, drainer patterns, and third-party tracker
rules from `spec/` and `src/dynamic_pricing.py` into target-specific bundles
for Python Core (`src/generated/`) and Chrome Extension MV3 (`extension/`),
and verifies 15-shield parity between `device_shield.py` and `dashboard.py`.

Usage:
    python scripts/compile_ssot.py           # Regenerate target artifacts
    python scripts/compile_ssot.py --check   # Verify zero drift (exit 1 on mismatch)
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.export_dnr import compile_pricing_tracker_ruleset
from src.dashboard import ACTIVE_SHIELDS_LIST
from src.device_shield import get_all_shields

SPEC_DIR = ROOT_DIR / "spec"
SPEC_BRANDS = SPEC_DIR / "brands.json"
SPEC_DRAINERS = SPEC_DIR / "drainer_patterns.json"

SRC_GEN_DIR = ROOT_DIR / "src" / "generated"
SRC_BRANDS_OUT = SRC_GEN_DIR / "ssot_brands.json"
SRC_DRAINERS_OUT = SRC_GEN_DIR / "ssot_drainers.json"

EXT_DATA_DIR = ROOT_DIR / "extension" / "data"
EXT_BRANDS_OUT = EXT_DATA_DIR / "brands.json"
EXT_DRAINERS_OUT = EXT_DATA_DIR / "drainer_patterns.json"
EXT_PRICING_OUT = ROOT_DIR / "extension" / "rules" / "pricing_trackers.json"


def _render_json(payload) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _expected_outputs() -> Dict[Path, str]:
    brands_spec = json.loads(SPEC_BRANDS.read_text(encoding="utf-8"))
    drainers_spec = json.loads(SPEC_DRAINERS.read_text(encoding="utf-8"))

    # Extension needs displayName, keywords, officialDomains (all 47 brands sorted deterministically)
    ext_brands = {
        k: {
            "displayName": v["displayName"],
            "keywords": v["keywords"],
            "officialDomains": v["officialDomains"],
        }
        for k, v in sorted(brands_spec.items())
    }

    # Core Python uses canonical spec directly
    core_brands = {k: brands_spec[k] for k in sorted(brands_spec.keys())}

    ext_drainers = [
        {
            "label": d["label"],
            "pattern": d["pattern"],
            "description": d["description"],
        }
        for d in drainers_spec
    ]

    return {
        EXT_BRANDS_OUT: _render_json(ext_brands),
        EXT_DRAINERS_OUT: _render_json(ext_drainers),
        SRC_BRANDS_OUT: _render_json(core_brands),
        SRC_DRAINERS_OUT: _render_json(drainers_spec),
    }


def verify_shields_parity() -> List[str]:
    errors: List[str] = []
    backend_ids = [s["id"] for s in get_all_shields()]
    ui_ids = [s["id"] for s in ACTIVE_SHIELDS_LIST]
    if len(backend_ids) != 15:
        errors.append(f"Expected 15 backend shields in get_all_shields(), found {len(backend_ids)}")
    if len(ui_ids) != 15:
        errors.append(f"Expected 15 UI shields in ACTIVE_SHIELDS_LIST, found {len(ui_ids)}")
    if set(backend_ids) != set(ui_ids):
        errors.append(
            f"Shield ID mismatch backend={sorted(backend_ids)} ui={sorted(ui_ids)}"
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile or verify Sentinel SSOT artifacts.")
    parser.add_argument("--check", action="store_true", help="Fail without writing if any output is out of sync.")
    args = parser.parse_args()

    errors = verify_shields_parity()
    expected = _expected_outputs()

    if args.check:
        for target_path, content in expected.items():
            if not target_path.exists():
                errors.append(f"Missing generated file: {target_path.relative_to(ROOT_DIR)}")
                continue
            current = target_path.read_text(encoding="utf-8")
            if current != content:
                errors.append(f"Out-of-sync SSOT artifact: {target_path.relative_to(ROOT_DIR)}")

        # Check pricing_trackers.json deterministically in temp dir
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp_pricing = Path(tmp) / "pricing_trackers.json"
            compile_pricing_tracker_ruleset(output_file=tmp_pricing)
            if not EXT_PRICING_OUT.exists() or EXT_PRICING_OUT.read_text(encoding="utf-8") != tmp_pricing.read_text(encoding="utf-8"):
                errors.append(f"Out-of-sync DNR ruleset: {EXT_PRICING_OUT.relative_to(ROOT_DIR)}")

        if errors:
            for err in errors:
                print(f"[SSOT DRIFT] {err}", file=sys.stderr)
            return 1
        print("[SSOT OK] All generated brand, drainer, pricing DNR, and 15-shield artifacts are synchronized.")
        return 0

    if errors:
        for err in errors:
            print(f"[SSOT ERROR] {err}", file=sys.stderr)
        return 1

    for target_path, content in expected.items():
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content, encoding="utf-8")
        print(f"[SSOT WRITE] {target_path.relative_to(ROOT_DIR)}")

    res = compile_pricing_tracker_ruleset(output_file=EXT_PRICING_OUT)
    print(f"[SSOT WRITE] {EXT_PRICING_OUT.relative_to(ROOT_DIR)} ({res['total_rules']} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
