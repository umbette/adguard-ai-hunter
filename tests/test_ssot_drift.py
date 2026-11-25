"""Regression tests verifying Single Source of Truth (SSOT) sync and 15-shield parity."""

import json
import subprocess
import sys
from pathlib import Path

from scripts import compile_ssot
from src.crypto_shield import (
    CAREGIVER_PROTECTED_BRANDS,
    DEFAULT_DRAINER_REGEX_PATTERNS,
    DEFAULT_PROTECTED_CRYPTO_BRANDS,
)


ROOT_DIR = Path(__file__).resolve().parent.parent


def test_ssot_check_passes_zero_drift():
    assert compile_ssot.verify_shields_parity() == []
    proc = subprocess.run(
        [sys.executable, "scripts/compile_ssot.py", "--check"],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"SSOT drift detected:\n{proc.stdout}\n{proc.stderr}"


def test_crypto_shield_and_extension_consume_ssot():
    spec_brands = json.loads((ROOT_DIR / "spec" / "brands.json").read_text(encoding="utf-8"))
    spec_drainers = json.loads((ROOT_DIR / "spec" / "drainer_patterns.json").read_text(encoding="utf-8"))
    ext_brands = json.loads((ROOT_DIR / "extension" / "data" / "brands.json").read_text(encoding="utf-8"))
    ext_drainers = json.loads((ROOT_DIR / "extension" / "data" / "drainer_patterns.json").read_text(encoding="utf-8"))

    expected_crypto_keys = {k for k, v in spec_brands.items() if v.get("core_crypto")}
    expected_caregiver_keys = {k for k, v in spec_brands.items() if not v.get("core_crypto")}

    assert set(DEFAULT_PROTECTED_CRYPTO_BRANDS.keys()) == expected_crypto_keys
    assert set(CAREGIVER_PROTECTED_BRANDS.keys()) == expected_caregiver_keys
    assert set(ext_brands.keys()) == set(spec_brands.keys())

    assert len(DEFAULT_DRAINER_REGEX_PATTERNS) == len(spec_drainers)
    assert [d["label"] for d in ext_drainers] == [d["label"] for d in spec_drainers]
