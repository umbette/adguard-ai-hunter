"""
Sentinel Core Malicious IP Intelligence & DNS Answer Correlation
==========================================================
Zero-trust parser, strict multi-tenant CDN/DNS exclusion list, and fast
lookup index for high-confidence dedicated C2 IPs and Hijacked CIDR ranges.

Designed to prevent CDN collateral damage (never blocks Cloudflare, Fastly,
AWS CloudFront, public resolvers, or RFC1918/CGNAT ranges) while detecting:
  1. New/DGA domains resolving in AdGuard querylog `answer` RRs to known C2 IPs
  2. Bare-IP phishing/malware URLs inside the MV3 browser extension
"""

from dataclasses import dataclass
import ipaddress
import logging
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

logger = logging.getLogger("sentinel.ip_intel")

IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddr = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

MIN_IPV4_CIDR_PREFIX = 16
MIN_IPV6_CIDR_PREFIX = 48
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

# Multi-tenant CDNs, shared cloud edge ranges, and public DNS resolvers that MUST NEVER be blocked by IP.
CDN_AND_DNS_EXCLUSIONS: Tuple[IPNet, ...] = (
    # Cloudflare IPv4
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("104.16.0.0/12"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("131.0.72.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    # Cloudflare IPv6
    ipaddress.ip_network("2400:cb00::/32"),
    ipaddress.ip_network("2606:4700::/32"),
    ipaddress.ip_network("2803:f800::/32"),
    ipaddress.ip_network("2405:b500::/32"),
    ipaddress.ip_network("2405:8100::/32"),
    ipaddress.ip_network("2a06:98c0::/29"),
    ipaddress.ip_network("2c0f:f248::/32"),
    # Fastly Anycast & GitHub Pages
    ipaddress.ip_network("151.101.0.0/16"),
    ipaddress.ip_network("199.232.0.0/16"),
    ipaddress.ip_network("185.199.108.0/22"),
    # Public DNS Anycast Resolvers (Cloudflare, Google, Quad9, OpenDNS)
    ipaddress.ip_network("1.1.1.1/32"),
    ipaddress.ip_network("1.0.0.1/32"),
    ipaddress.ip_network("8.8.8.8/32"),
    ipaddress.ip_network("8.8.4.4/32"),
    ipaddress.ip_network("9.9.9.9/32"),
    ipaddress.ip_network("149.112.112.112/32"),
    ipaddress.ip_network("208.67.222.222/32"),
    ipaddress.ip_network("208.67.220.220/32"),
    ipaddress.ip_network("2606:4700:4700::1111/128"),
    ipaddress.ip_network("2606:4700:4700::1001/128"),
    ipaddress.ip_network("2001:4860:4860::8888/128"),
    ipaddress.ip_network("2001:4860:4860::8844/128"),
)


@dataclass(frozen=True)
class ThreatIPMatch:
    ip: str
    matched_ioc: str
    source: str
    family: str
    confidence: int


def is_protected_network_or_cdn(target: Union[IPAddr, IPNet]) -> bool:
    """Returns True if the IP or CIDR is non-global, CGNAT, or overlaps a multi-tenant CDN/DNS range."""
    if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        if (
            target.is_private
            or target.is_loopback
            or target.is_link_local
            or target.is_multicast
            or target.is_reserved
            or target.is_unspecified
            or not target.is_global
        ):
            return True
        if target.version == 4 and target in CGNAT_NETWORK:
            return True
        for cdn in CDN_AND_DNS_EXCLUSIONS:
            if target.version == cdn.version and target in cdn:
                return True
        return False

    # CIDR / Network check
    if target.version == 4 and target.prefixlen < MIN_IPV4_CIDR_PREFIX:
        return True
    if target.version == 6 and target.prefixlen < MIN_IPV6_CIDR_PREFIX:
        return True
    if (
        target.is_private
        or target.is_loopback
        or target.is_link_local
        or target.is_multicast
        or target.is_reserved
        or target.is_unspecified
        or not target.is_global
    ):
        return True
    if target.version == 4 and target.overlaps(CGNAT_NETWORK):
        return True
    for cdn in CDN_AND_DNS_EXCLUSIONS:
        if target.version == cdn.version and target.overlaps(cdn):
            return True
    return False


def is_protected_ip(raw_ip_or_cidr: str) -> bool:
    """Convenience string wrapper returning True if an IP/CIDR is protected or invalid."""
    text = (raw_ip_or_cidr or "").strip()
    if not text:
        return True
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            return is_protected_network_or_cdn(net)
        addr = ipaddress.ip_address(text)
        return is_protected_network_or_cdn(addr)
    except ValueError:
        return True


def _extract_candidate_host(raw: str) -> str:
    """Strips inline feed comments, URL wrappers, brackets, and ports cleanly."""
    cleaned = (raw or "").strip()
    if not cleaned:
        return ""

    # Strip inline comments (Spamhaus DROP '; SBL...' or '# ...')
    for sep in (";", "#"):
        if sep in cleaned:
            cleaned = cleaned.split(sep, 1)[0].strip()
    if not cleaned:
        return ""

    # Extract host from URLs (e.g. http://198.51.100.42:8080/gate.php)
    if "://" in cleaned:
        try:
            parsed = urlparse(cleaned)
            cleaned = (parsed.hostname or "").strip()
        except Exception:
            return ""
    else:
        # Handle bracketed IPv6 [2001:db8::1]:443 or plain IPv4:port
        if cleaned.startswith("["):
            if "]" in cleaned:
                cleaned = cleaned[1:cleaned.index("]")]
            else:
                return ""
        elif cleaned.count(":") == 1 and "/" not in cleaned:
            # IPv4:port
            cleaned = cleaned.split(":", 1)[0].strip()

    return cleaned.strip()


def sanitize_malicious_ip_or_cidr(raw_input: str, allow_cidr: bool = True) -> Optional[str]:
    """
    Validates a raw IP/URL/CIDR string from a threat feed and returns canonical
    IP or CIDR string, or None if invalid, private, CGNAT, overly broad, or CDN/DNS.
    """
    if not raw_input or not isinstance(raw_input, str) or len(raw_input) > 2048:
        return None

    candidate = _extract_candidate_host(raw_input)
    if not candidate:
        return None

    try:
        if "/" in candidate:
            if not allow_cidr:
                return None
            net = ipaddress.ip_network(candidate, strict=False)
            if is_protected_network_or_cdn(net):
                return None
            return str(net)
        addr = ipaddress.ip_address(candidate)
        if is_protected_network_or_cdn(addr):
            return None
        return str(addr)
    except ValueError:
        return None


def extract_answer_ips(entry: Dict[str, Any]) -> List[str]:
    """
    Extracts global A/AAAA resolved IP addresses from an AdGuard Home querylog entry.
    Supports both AdGuard's `answer` ([{type, value, ttl}]) and `answers` formats.
    """
    if not isinstance(entry, dict):
        return []

    raw_answers = entry.get("answer")
    if raw_answers is None:
        raw_answers = entry.get("answers")
    if not isinstance(raw_answers, list):
        return []

    seen: Set[str] = set()
    ips: List[str] = []

    for rr in raw_answers:
        val: Optional[str] = None
        if isinstance(rr, dict):
            rr_type = str(rr.get("type", "")).upper().strip()
            if rr_type and rr_type not in ("A", "AAAA"):
                continue
            raw_val = rr.get("value") or rr.get("Value")
            if isinstance(raw_val, str):
                val = raw_val.strip()
        elif isinstance(rr, str):
            val = rr.strip()

        if not val:
            continue

        try:
            addr = ipaddress.ip_address(val)
        except ValueError:
            continue

        if not is_protected_network_or_cdn(addr):
            canonical = str(addr)
            if canonical not in seen:
                seen.add(canonical)
                ips.append(canonical)

    return ips


class ThreatIPIndex:
    """In-memory index + SQLite/file loader for high-confidence malicious IPs & C2 CIDRs."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        auto_load: bool = True,
        fallback_ips_file: Optional[Path] = None,
    ):
        root_dir = Path(__file__).resolve().parent.parent
        self.db_path = Path(db_path) if db_path else root_dir / "data" / "threat_miner.db"
        # Default production runtime falls back to git-tracked sources/proactive_ips.txt in fresh containers
        self.fallback_ips_file = (
            Path(fallback_ips_file)
            if fallback_ips_file is not None
            else (root_dir / "sources" / "proactive_ips.txt" if db_path is None else None)
        )
        self._exact_ips: Dict[str, ThreatIPMatch] = {}
        self._cidr_entries: List[Tuple[IPNet, ThreatIPMatch]] = []
        if auto_load:
            self.reload()

    def reload(self) -> int:
        self._exact_ips.clear()
        self._cidr_entries.clear()
        loaded = 0

        if self.db_path.is_file():
            try:
                with sqlite3.connect(self.db_path, timeout=2.0) as conn:
                    has_table = conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='mined_ips'"
                    ).fetchone()
                    if has_table:
                        rows = conn.execute(
                            """
                            SELECT DISTINCT m.ip_or_cidr, COALESCE(m.malware_family, 'c2'), m.confidence,
                                   COALESCE(GROUP_CONCAT(DISTINCT src.source), 'threat_intel')
                            FROM mined_ips m
                            INNER JOIN ip_sources src ON m.ip_or_cidr = src.ip_or_cidr
                            WHERE m.status = 'active' AND m.confidence >= 85
                            GROUP BY m.ip_or_cidr
                            """
                        ).fetchall()
                        for ip_or_cidr, family, conf, source in rows:
                            if self.add_entry(
                                ip_or_cidr=str(ip_or_cidr),
                                source=str(source),
                                family=str(family),
                                confidence=int(conf),
                            ):
                                loaded += 1
            except Exception as exc:
                logger.debug(f"ThreatIPIndex reload skipped ({self.db_path}): {exc}")

        if loaded == 0 and self.fallback_ips_file and self.fallback_ips_file.is_file():
            try:
                for line in self.fallback_ips_file.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if self.add_entry(
                        ip_or_cidr=stripped,
                        source="proactive_ips",
                        family="c2_or_drop",
                        confidence=90,
                    ):
                        loaded += 1
            except Exception as exc:
                logger.debug(f"ThreatIPIndex fallback file load skipped ({self.fallback_ips_file}): {exc}")

        return loaded

    def add_entry(
        self,
        ip_or_cidr: str,
        source: str = "threat_intel",
        family: str = "c2",
        confidence: int = 90,
    ) -> bool:
        canonical = sanitize_malicious_ip_or_cidr(ip_or_cidr, allow_cidr=True)
        if not canonical:
            return False
        match = ThreatIPMatch(
            ip=canonical,
            matched_ioc=canonical,
            source=source,
            family=family,
            confidence=confidence,
        )
        if "/" in canonical:
            self._cidr_entries.append((ipaddress.ip_network(canonical, strict=False), match))
        else:
            prev = self._exact_ips.get(canonical)
            if prev is None or confidence > prev.confidence:
                self._exact_ips[canonical] = match
        return True

    @property
    def total_entries(self) -> int:
        return len(self._exact_ips) + len(self._cidr_entries)

    def match_ip(self, raw_ip: str) -> Optional[ThreatIPMatch]:
        try:
            addr = ipaddress.ip_address((raw_ip or "").strip())
        except ValueError:
            return None

        if is_protected_network_or_cdn(addr):
            return None

        canonical = str(addr)
        exact = self._exact_ips.get(canonical)
        if exact is not None:
            return exact

        for net, entry in self._cidr_entries:
            if addr.version == net.version and addr in net:
                return ThreatIPMatch(
                    ip=canonical,
                    matched_ioc=entry.matched_ioc,
                    source=entry.source,
                    family=entry.family,
                    confidence=entry.confidence,
                )
        return None
