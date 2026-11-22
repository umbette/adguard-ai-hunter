#!/usr/bin/env python3
"""
AI Hunter - Proactive Threat Miner & IoC Collector
Gathers active malware, C2, and zero-day threat domains from trusted community feeds
with multi-tier zero-trust validation, Public Suffix List enforcement, and 30-day sliding TTL.
"""

import os
import sys
import re
import socket
import sqlite3
import shutil
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse
import urllib.request

import idna
import tldextract

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("proactive_miner")

# Directory Layout
ROOT_DIR = Path(__file__).resolve().parent.parent
SOURCES_DIR = ROOT_DIR / "sources"
DATA_DIR = ROOT_DIR / "data"
FILTERS_DIR = ROOT_DIR / "filters"

SOURCES_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
FILTERS_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "threat_miner.db"
NEVER_BLOCK_FILE = SOURCES_DIR / "never_block.txt"
PROACTIVE_OUTPUT_FILE = SOURCES_DIR / "proactive_threats.txt"
DOMAINS_FILE = SOURCES_DIR / "domains.txt"

# Security & RFC 1123 Constraints (Supporting standard and IDN Punycode TLDs like xn--...)
RFC1123_DOMAIN_REGEX = re.compile(
    r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+(?:xn\-\-[a-zA-Z0-9\-]{1,59}|[a-zA-Z]{2,63})$"
)
FORBIDDEN_CHARS = set("$^@|/\\*[]()#;,!~%&? \t\r\n\0")

# Multi-Tenant Shared CDNs that CANNOT be sinkholed at DNS level without catastrophic breakage
SHARED_MULTI_TENANT_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "gist.githubusercontent.com",
    "discord.com",
    "discordapp.com",
    "cdn.discordapp.com",
    "drive.google.com",
    "docs.google.com",
    "googleusercontent.com",
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "workers.dev",
    "pages.dev",
    "azureedge.net",
    "cloudfront.net",
    "akamaized.net",
    "fastly.net",
    "fastly-edge.com",
    "telegram.org",
    "api.telegram.org",
    "pastebin.com"
}

INFRASTRUCTURE_SUFFIXES = (
    ".in-addr.arpa", ".ip6.arpa", ".arpa", ".local", ".lan", ".home", ".internal", ".home.arpa"
)


class DomainSanitizer:
    """Zero-Trust input sanitizer ensuring RFC 1123 compliance and neutralizing homograph/injection attacks."""

    def __init__(self):
        # Local tldextract cache with private PSL domains enabled
        cache_dir = DATA_DIR / ".tld_cache"
        self.extractor = tldextract.TLDExtract(cache_dir=str(cache_dir), include_psl_private_domains=True)

    def sanitize(self, raw_input: str) -> str | None:
        if not raw_input or not isinstance(raw_input, str) or len(raw_input) > 2048:
            return None

        # 1. Strip whitespace and control chars
        cleaned = raw_input.strip()
        if not cleaned or cleaned.startswith("#"):
            return None

        # 2. Extract host if a full URL was provided
        if "://" in cleaned:
            try:
                parsed = urlparse(cleaned)
                cleaned = parsed.hostname or cleaned
            except Exception:
                return None

        # 3. Strip any port or trailing dots
        cleaned = cleaned.split(":")[0].strip().lower().rstrip(".")

        # 4. Reject forbidden filter-injection characters
        if any(c in FORBIDDEN_CHARS for c in cleaned):
            return None

        # 5. Reject bare IP addresses (v4 or v6) - DNS adblockers block FQDNs
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cleaned) or ":" in cleaned:
            return None

        # 6. IDN Punycode Conversion (Neutralizes Unicode homograph spoofing)
        try:
            ascii_domain = idna.encode(cleaned).decode("ascii")
        except Exception:
            return None

        # 7. Length check (Max 253 chars overall, max 63 per label)
        if len(ascii_domain) > 253 or len(ascii_domain) < 3:
            return None

        labels = ascii_domain.split(".")
        if any(len(label) > 63 or len(label) == 0 for label in labels):
            return None

        # 8. RFC 1123 Regex Validation
        if not RFC1123_DOMAIN_REGEX.match(ascii_domain):
            return None

        # 9. Public Suffix List Enforcement: Reject bare TLDs or Public Suffixes (e.g. co.uk, com, pages.dev)
        ext = self.extractor(ascii_domain)
        if not ext.domain or not ext.suffix:
            return None
        if ascii_domain == ext.suffix or f"{ext.domain}.{ext.suffix}" == ext.suffix:
            return None

        return ascii_domain


class ShieldWhitelist:
    """Multi-tier protective whitelist preventing false positives on core infrastructure."""

    def __init__(self):
        self.protected_domains = self._load_never_block()

    def _load_never_block(self) -> set[str]:
        protected = set()
        if NEVER_BLOCK_FILE.exists():
            with open(NEVER_BLOCK_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip().lower()
                    if clean and not clean.startswith("#"):
                        protected.add(clean)

        # Merge hardcoded multi-tenant shared CDNs
        protected.update(SHARED_MULTI_TENANT_HOSTS)

        # Import known benign from heuristics if available
        try:
            from src.heuristics import KNOWN_BENIGN_DOMAINS
            protected.update(KNOWN_BENIGN_DOMAINS)
        except Exception:
            pass

        return protected

    def is_protected(self, domain: str) -> bool:
        domain_lower = domain.lower()

        # Check infrastructure suffixes
        if any(domain_lower.endswith(sfx) for sfx in INFRASTRUCTURE_SUFFIXES):
            return True

        if domain_lower in self.protected_domains:
            return True

        # Check all parent domains
        parts = domain_lower.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.protected_domains:
                return True

        return False


class ThreatStateDB:
    """Transactional SQLite database maintaining active IoCs with 30-day sliding TTL."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mined_iocs (
                    domain TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    malware_family TEXT,
                    confidence INTEGER DEFAULT 80,
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    status TEXT DEFAULT 'active'
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON mined_iocs(expires_at);")

    def insert_or_update_iocs(self, candidates: list[dict], max_surge: int = 500) -> tuple[int, int]:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=30)
        now_str = now.isoformat()
        expires_str = expires.isoformat()

        new_count = 0
        updated_count = 0

        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            for cand in candidates:
                dom = cand["domain"]
                source = cand.get("source", "feed")
                family = cand.get("family", "malware")
                conf = cand.get("confidence", 80)

                cur.execute("SELECT domain FROM mined_iocs WHERE domain = ?", (dom,))
                row = cur.fetchone()

                if row:
                    # Update sliding TTL
                    cur.execute("""
                        UPDATE mined_iocs 
                        SET last_seen = ?, expires_at = ?, confidence = MAX(confidence, ?)
                        WHERE domain = ?
                    """, (now_str, expires_str, conf, dom))
                    updated_count += 1
                else:
                    # Surge Circuit Breaker
                    if new_count >= max_surge:
                        logger.warning(f"Surge limit of {max_surge} new domains reached. Halting new additions.")
                        break
                    cur.execute("""
                        INSERT INTO mined_iocs (domain, source, malware_family, confidence, first_seen, last_seen, expires_at, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
                    """, (dom, source, family, conf, now_str, now_str, expires_str))
                    new_count += 1

            conn.commit()

        return new_count, updated_count

    def purge_expired(self) -> int:
        now_str = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM mined_iocs WHERE expires_at < ?", (now_str,))
            purged = cur.rowcount
            conn.commit()
        return purged

    def get_active_domains(self) -> list[str]:
        now_str = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT domain FROM mined_iocs WHERE expires_at >= ? AND status = 'active' ORDER BY domain ASC", (now_str,))
            return [row[0] for row in cur.fetchall()]


class ProactiveMiner:
    """Main orchestrator: fetches feeds, sanitizes, validates against shield, updates DB and triggers filter compile."""

    def __init__(self):
        self.sanitizer = DomainSanitizer()
        self.shield = ShieldWhitelist()
        self.db = ThreatStateDB()

    def fetch_openphish(self) -> list[dict]:
        url = "https://openphish.com/feed.txt"
        logger.info(f"Fetching OpenPhish zero-day feed from {url}...")
        candidates = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AI-Hunter-Proactive-Miner/1.0"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                    sanitized = self.sanitizer.sanitize(line)
                    if sanitized and not self.shield.is_protected(sanitized):
                        candidates.append({
                            "domain": sanitized,
                            "source": "openphish",
                            "family": "phishing",
                            "confidence": 90
                        })
        except Exception as e:
            logger.error(f"Failed to fetch OpenPhish: {e}")
        logger.info(f"OpenPhish produced {len(candidates)} valid candidate domains.")
        return candidates

    def fetch_urlhaus_mirror(self) -> list[dict]:
        url = "https://raw.githubusercontent.com/curbengh/urlhaus-filter/master/urlhaus-filter-domains.txt"
        logger.info(f"Fetching URLhaus malware mirror feed from {url}...")
        candidates = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AI-Hunter-Proactive-Miner/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                    clean = line.strip()
                    if not clean or clean.startswith("#"):
                        continue
                    sanitized = self.sanitizer.sanitize(clean)
                    if sanitized and not self.shield.is_protected(sanitized):
                        candidates.append({
                            "domain": sanitized,
                            "source": "urlhaus",
                            "family": "malware",
                            "confidence": 85
                        })
        except Exception as e:
            logger.error(f"Failed to fetch URLhaus mirror: {e}")
        logger.info(f"URLhaus produced {len(candidates)} valid candidate domains.")
        return candidates

    def run_mining_cycle(self) -> dict:
        logger.info("=== STARTING PROACTIVE THREAT MINING CYCLE ===")

        # 1. Fetch raw candidates
        candidates = []
        candidates.extend(self.fetch_openphish())
        candidates.extend(self.fetch_urlhaus_mirror())

        # 2. De-duplicate candidates in memory
        seen = set()
        deduped = []
        for c in candidates:
            if c["domain"] not in seen:
                seen.add(c["domain"])
                deduped.append(c)

        logger.info(f"Total unique sanitized candidate IoCs: {len(deduped)}")

        # 3. Ingest into SQLite with 30-day sliding TTL and surge protection
        new_cnt, upd_cnt = self.db.insert_or_update_iocs(deduped, max_surge=500)
        purged_cnt = self.db.purge_expired()

        logger.info(f"DB Update: {new_cnt} newly added, {upd_cnt} refreshed TTL, {purged_cnt} expired purged.")

        # 4. Export active domains to sources/proactive_threats.txt atomically
        active_domains = self.db.get_active_domains()
        self._atomic_export_proactive_file(active_domains)

        # 5. Trigger filter compilation
        self._compile_and_verify_canary()

        return {
            "candidates_fetched": len(deduped),
            "new_iocs": new_cnt,
            "refreshed_iocs": upd_cnt,
            "purged_iocs": purged_cnt,
            "total_active_proactive_iocs": len(active_domains)
        }

    def _atomic_export_proactive_file(self, domains: list[str]):
        temp_file = PROACTIVE_OUTPUT_FILE.with_suffix(".tmp")
        with open(temp_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("# Proactive Mined Threat Domains (Auto-generated with 30-day sliding TTL)\n")
            f.write(f"# Last Updated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# Active Count: {len(domains)}\n\n")
            for d in domains:
                f.write(f"{d}\n")

        os.replace(temp_file, PROACTIVE_OUTPUT_FILE)
        logger.info(f"Atomic export to {PROACTIVE_OUTPUT_FILE} successful ({len(domains)} domains).")

    def _compile_and_verify_canary(self):
        """Compiles the AdGuard blocklist and executes a DNS canary check to verify zero-breakage."""
        compiler_script = ROOT_DIR / "scripts" / "build_filter.py"
        if not compiler_script.exists():
            logger.warning(f"Compiler script not found at {compiler_script}")
            return

        import subprocess
        res = subprocess.run([sys.executable, str(compiler_script)], capture_output=True, text=True)
        if res.returncode != 0:
            logger.error(f"Filter compilation failed:\n{res.stderr}")
            return

        logger.info(f"Filter compiler finished successfully:\n{res.stdout.strip()}")

        # Canary DNS Health Check: ensure core resolution is NOT broken
        canaries = ["cloudflare.com", "google.com"]
        for canary in canaries:
            try:
                socket.gethostbyname(canary)
                logger.info(f"✅ Canary DNS probe succeeded for {canary}")
            except Exception as e:
                logger.critical(f"❌ CANARY RESOLUTION FAILED for {canary}: {e}")
                # Rollback safety if needed
                backup_file = FILTERS_DIR / "threat_blacklist.txt.bak"
                active_file = FILTERS_DIR / "threat_blacklist.txt"
                if backup_file.exists():
                    shutil.copy2(backup_file, active_file)
                    logger.warning("Rolled back threat_blacklist.txt to last known good backup.")


if __name__ == "__main__":
    miner = ProactiveMiner()
    stats = miner.run_mining_cycle()
    print("\n" + "=" * 60)
    print(" 🛡️ PROACTIVE THREAT MINING SUMMARY")
    print("=" * 60)
    for k, v in stats.items():
        print(f" • {k}: {v}")
    print("=" * 60)
