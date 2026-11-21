#!/usr/bin/env python3
"""
AI Hunter - AdGuard Community Filter Compiler
Strict zero-trust validator and compiler for crowdsourced threat lists.
"""

import sys
import re
from datetime import datetime, timezone
from pathlib import Path

RFC1123_DOMAIN_REGEX = re.compile(
    r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,63}$"
)
FORBIDDEN_CHARS = set("$^@|/\\*[]()#;,!~%&? \t\r\n\0")

ROOT_DIR = Path(__file__).resolve().parent.parent
SOURCES_DIR = ROOT_DIR / "sources"
FILTERS_DIR = ROOT_DIR / "filters"

DOMAINS_FILE = SOURCES_DIR / "domains.txt"
NEVER_BLOCK_FILE = SOURCES_DIR / "never_block.txt"
OUTPUT_FILE = FILTERS_DIR / "threat_blacklist.txt"


def load_never_block() -> set[str]:
    protected = set()
    if not NEVER_BLOCK_FILE.exists():
        print(f"[WARN] Never-block file not found at {NEVER_BLOCK_FILE}")
        return protected

    with open(NEVER_BLOCK_FILE, "r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip().lower()
            if not clean or clean.startswith("#"):
                continue
            protected.add(clean)
    print(f"Loaded {len(protected)} protected domains from {NEVER_BLOCK_FILE.name}")
    return protected


def is_protected(domain: str, protected: set[str]) -> bool:
    if domain in protected:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in protected:
            return True
    return False


def validate_and_compile():
    protected = load_never_block()
    if not DOMAINS_FILE.exists():
        print(f"[ERROR] Source domains file not found: {DOMAINS_FILE}")
        sys.exit(1)

    valid_domains = set()
    skipped_count = 0
    protected_count = 0

    with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue

            # 1. Reject forbidden characters
            if any(c in FORBIDDEN_CHARS for c in raw):
                print(f"[REJECT Line {line_num}] Contains forbidden filter characters: {raw}")
                skipped_count += 1
                continue

            domain = raw.lower().rstrip(".")

            # 2. RFC1123 Validation
            if not RFC1123_DOMAIN_REGEX.match(domain):
                print(f"[REJECT Line {line_num}] Invalid RFC1123 domain syntax: {raw}")
                skipped_count += 1
                continue

            # 3. Protection check
            if is_protected(domain, protected):
                print(f"[PROTECTED Line {line_num}] Domain is in protected never-block list: {domain}")
                protected_count += 1
                continue

            valid_domains.add(domain)

    sorted_domains = sorted(valid_domains)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    FILTERS_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as out:
        out.write("! ------------------------------------------------------------------------------\n")
        out.write("! Title: AI Hunter - Community Threat & DGA Blacklist\n")
        out.write("! Description: Validated threat intelligence and DGA domains compiled from AI Hunter\n")
        out.write(f"! Last Modified: {now_utc}\n")
        out.write(f"! Number of rules: {len(sorted_domains)}\n")
        out.write("! Syntax: AdGuard / uBlock Origin compatible\n")
        out.write("! License: MIT License\n")
        out.write("! Homepage: https://github.com/umbette/adguard-ai-hunter\n")
        out.write("! ------------------------------------------------------------------------------\n\n")

        for d in sorted_domains:
            out.write(f"||{d}^\n")

    print(f"\nCompilation successful:")
    print(f" - Valid rules compiled: {len(sorted_domains)}")
    print(f" - Rejected invalid lines: {skipped_count}")
    print(f" - Filtered protected domains: {protected_count}")
    print(f" - Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    validate_and_compile()

