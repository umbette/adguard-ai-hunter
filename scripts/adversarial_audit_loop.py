#!/usr/bin/env python3
"""
Adversarial Self-Auditing & Co-Development Engine (Antigravity <-> Arena.ai)
=============================================================================
Orchestrates an autonomous continuous improvement loop between two AI roles:
1. Builder / Implementer (Antigravity): Writes code, fixes bugs, runs test suites.
2. Hostile Auditor / Critic (Arena.ai persona): Evaluates real added value,
   differentiation, monetizability, and low-level engineering rigor.

Protocol Criteria:
- C1: Real Added Value (strictly measured vs existing free solutions like Chrome Safe Browsing, uBlock, NextDNS)
- C2: True Differentiation (reject unproven marketing hype like 'AI', 'zero-hour', '100% block')
- C3: Monetizability & Willingness-to-Pay (clear user segment, verifiable family/pro utility)
- C4: Engineering Rigor (Manifest V3 quotas, permissions, race conditions, storage lifecycle, test coverage)
"""

import json
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("adversarial_loop")

ROOT_DIR = Path(__file__).resolve().parent.parent


def run_test_suite() -> dict:
    """Executes the repository test suite to establish ground truth."""
    logger.info("Executing pytest suite...")
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", "tests/"],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True
    )
    passed = res.returncode == 0
    return {
        "success": passed,
        "stdout": res.stdout,
        "stderr": res.stderr
    }


def get_git_status() -> dict:
    """Gathers git head commit, diff, and modified files."""
    res_head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT_DIR, capture_output=True, text=True)
    res_status = subprocess.run(["git", "status", "--short"], cwd=ROOT_DIR, capture_output=True, text=True)
    return {
        "head": res_head.stdout.strip(),
        "status": res_status.stdout.strip()
    }


def main():
    logger.info("=== INITIALIZING ADVERSARIAL AUDIT LOOP ===")
    git_info = get_git_status()
    logger.info(f"Active Git Head: {git_info['head']}")

    test_res = run_test_suite()
    if test_res["success"]:
        logger.info("✅ All test suites passed cleanly.")
    else:
        logger.error(f"❌ Test failures detected:\n{test_res['stdout']}\n{test_res['stderr']}")

    logger.info("Ready for autonomous swarm interaction on message board.")


if __name__ == "__main__":
    main()
