"""Tests for High-Confidence Malicious IP Intelligence, CDN Exclusion, DNS Correlation & DNR Export."""

from datetime import datetime, timedelta, timezone
import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from scripts.export_dnr import compile_dnr_ruleset
from scripts.proactive_miner import FeedFetchResult, ProactiveMiner, ThreatStateDB
from src.config import Settings
from src.heuristics import HeuristicsEngine
from src.ingestion import IngestionWorker
from src.ip_intel import (
    ThreatIPIndex,
    extract_answer_ips,
    is_protected_ip,
    sanitize_malicious_ip_or_cidr,
)
from src.storage import StorageEngine


def test_ip_sanitizer_excludes_cdn_resolvers_private_and_broad_cidrs():
    # Valid global malicious IPs, URLs with port, Spamhaus CIDR comments
    assert sanitize_malicious_ip_or_cidr("45.155.205.42") == "45.155.205.42"
    assert sanitize_malicious_ip_or_cidr("http://45.155.205.42:8080/dropper.exe") == "45.155.205.42"
    assert sanitize_malicious_ip_or_cidr("https://[2a03:b0c0:3:d0::bad:5]:443/panel") == "2a03:b0c0:3:d0::bad:5"
    assert sanitize_malicious_ip_or_cidr("91.92.240.0/24 ; SBL999999") == "91.92.240.0/24"
    assert sanitize_malicious_ip_or_cidr("185.220.101.4:9001 # c2 node") == "185.220.101.4"

    # Must NEVER match private/loopback/CGNAT/link-local/documentation TEST-NET
    for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.5.4", "100.64.10.1", "169.254.1.1", "::1", "198.51.100.42", "203.0.113.0/24"):
        assert sanitize_malicious_ip_or_cidr(bad) is None
        assert is_protected_ip(bad) is True

    # Must NEVER block Cloudflare, Fastly, GitHub Pages, or Public DNS Resolvers
    for cdn_or_dns in ("104.16.132.229", "172.67.10.20", "1.1.1.1", "8.8.8.8", "9.9.9.9", "151.101.1.69", "185.199.108.153"):
        assert sanitize_malicious_ip_or_cidr(cdn_or_dns) is None
        assert is_protected_ip(cdn_or_dns) is True

    # Must reject overly broad CIDRs or CIDRs overlapping Cloudflare/CDN
    assert sanitize_malicious_ip_or_cidr("104.0.0.0/8") is None
    assert sanitize_malicious_ip_or_cidr("91.0.0.0/8") is None
    assert sanitize_malicious_ip_or_cidr("104.16.0.0/24") is None


def test_extract_answer_ips_from_adguard_querylog():
    entry = {
        "answer": [
            {"type": "CNAME", "value": "alias.example.net"},
            {"type": "A", "value": "45.155.205.99"},
            {"type": "A", "value": "192.168.1.50"},   # LAN IP ignored
            {"type": "A", "value": "104.16.10.5"},    # Cloudflare CDN ignored
            {"type": "AAAA", "value": "2a03:b0c0:3:d0::bad:2"},
        ]
    }
    assert extract_answer_ips(entry) == ["45.155.205.99", "2a03:b0c0:3:d0::bad:2"]


def test_proactive_miner_ip_db_ttl_and_export_dnr(tmp_path, monkeypatch):
    db_path = tmp_path / "threats.db"
    ip_out = tmp_path / "proactive_ips.txt"
    rules_out = tmp_path / "ruleset.json"
    doms_out = tmp_path / "blocked_domains.json"
    ips_out = tmp_path / "blocked_ips.json"

    db = ThreatStateDB(db_path=db_path)
    miner = ProactiveMiner()
    miner.db = db
    monkeypatch.setattr("scripts.proactive_miner.PROACTIVE_IP_OUTPUT_FILE", ip_out)

    monkeypatch.setattr(
        miner,
        "fetch_feodo_c2",
        lambda: FeedFetchResult(
            "feodo_c2",
            [
                {"ip_or_cidr": "45.155.205.77", "source": "feodo_c2", "family": "botnet_c2", "confidence": 95},
                {"ip_or_cidr": "104.16.12.12", "source": "feodo_c2", "family": "botnet_c2", "confidence": 95},
            ],
            success=True,
        ),
    )
    monkeypatch.setattr(
        miner,
        "fetch_spamhaus_drop",
        lambda: FeedFetchResult(
            "spamhaus_drop",
            [{"ip_or_cidr": "91.92.240.0/24", "source": "spamhaus_drop", "family": "hijacked_netblock", "confidence": 92}],
            success=True,
        ),
    )
    monkeypatch.setattr(
        miner,
        "fetch_openphish_ips",
        lambda: FeedFetchResult("openphish_ip", [], success=False, error="timeout"),
    )

    stats = miner.run_ip_mining_cycle()
    assert stats["new_ips"] == 2  # Cloudflare 104.16.12.12 was rejected!
    assert "45.155.205.77" in ip_out.read_text(encoding="utf-8")
    assert "91.92.240.0/24" in ip_out.read_text(encoding="utf-8")
    assert "104.16.12.12" not in ip_out.read_text(encoding="utf-8")

    # Verify ThreatIPIndex loads both bare IPs and CIDRs cleanly
    idx = ThreatIPIndex(db_path=db_path)
    assert idx.match_ip("45.155.205.77").source == "feodo_c2"
    cidr_hit = idx.match_ip("91.92.240.55")
    assert cidr_hit is not None and cidr_hit.matched_ioc == "91.92.240.0/24"
    assert idx.match_ip("1.1.1.1") is None

    # Verify export_dnr includes only bare IPs (no CIDR subnets) into ruleset & blocked_ips.json
    res = compile_dnr_ruleset(
        db_path=db_path,
        output_file=rules_out,
        domains_output_file=doms_out,
        ips_output_file=ips_out,
        min_confidence=85,
    )
    assert res["ips_covered"] == 1
    assert json.loads(ips_out.read_text(encoding="utf-8")) == ["45.155.205.77"]
    rules = json.loads(rules_out.read_text(encoding="utf-8"))
    assert len(rules) == 1
    assert rules[0]["condition"]["urlFilter"] == "||45.155.205.77^"

    # Verify 14-day TTL expiration purge clears old IP source rows
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE ip_sources SET expires_at = ? WHERE source = 'feodo_c2'", (past,))
        conn.commit()
    purged = db.purge_expired_ips(eligible_sources=["feodo_c2"])
    assert purged == 1
    assert db.get_active_ips(bare_only=True) == []


@pytest.mark.asyncio
async def test_ingestion_dns_answer_correlates_malicious_c2_ip(tmp_path):
    settings = Settings()
    settings.storage.db_path = str(tmp_path / "sentinel.db")
    settings.admission.enabled = False
    storage = StorageEngine(settings.storage.db_path)
    heuristics = HeuristicsEngine(settings)
    gemini = MagicMock()

    dispatcher = MagicMock()
    dispatcher.get_session = AsyncMock(return_value=MagicMock())
    dispatcher.send_mobile_alert = AsyncMock(return_value=True)
    dispatcher.send_new_device_alert = AsyncMock(return_value=True)
    dispatcher.inject_adguard_rule = AsyncMock(return_value=True)
    dispatcher.device_resolver = MagicMock()
    dispatcher.device_resolver.resolve = AsyncMock(
        return_value=SimpleNamespace(name="Budget TV Box", device_type="IOT_GENERIC", icon="📦")
    )

    ip_index = ThreatIPIndex(auto_load=False)
    ip_index.add_entry("45.155.205.88", source="feodo_c2", family="botnet_c2", confidence=95)
    ip_index.add_entry("91.92.240.0/24", source="spamhaus_drop", family="hijacked_netblock", confidence=92)

    worker = IngestionWorker(settings, storage, heuristics, gemini, dispatcher, ip_intel=ip_index)

    entries = [
        # 1. Innocent query resolving to Cloudflare CDN -> NO IP correlation alert
        {
            "time": "2026-11-24T22:50:01Z",
            "reason": "NotFilteredNotFound",
            "client": "192.168.1.40",
            "question": {"name": "news.example.com"},
            "answer": [{"type": "A", "value": "104.16.10.20"}],
        },
        # 2. Brand-new non-blacklisted domain resolving to Spamhaus DROP netblock -> Alert!
        {
            "time": "2026-11-24T22:50:02Z",
            "reason": "NotFilteredNotFound",
            "client": "192.168.1.40",
            "question": {"name": "fresh-c2-stage.example"},
            "answer": [{"type": "A", "value": "91.92.240.19"}],
        },
    ]

    await worker._process_entries(entries)

    dispatcher.send_mobile_alert.assert_awaited_once()
    call_kw = dispatcher.send_mobile_alert.call_args.kwargs
    assert call_kw["domain"] == "fresh-c2-stage.example"
    assert call_kw["classification"] == "MALICIOUS_IP_RESOLUTION"
    assert "91.92.240.19" in call_kw["summary"]
    assert call_kw["suggested_rule"] == "||fresh-c2-stage.example^$client=192.168.1.40"


def test_threat_ip_index_fallback_file_works_without_db(tmp_path):
    """Ensures fresh containers/HA add-ons without threat_miner.db still boot with sources/proactive_ips.txt."""
    missing_db = tmp_path / "missing.db"
    fallback_txt = tmp_path / "proactive_ips.txt"
    fallback_txt.write_text("# comment\n45.155.205.12\n104.16.10.10\n", encoding="utf-8")

    idx = ThreatIPIndex(db_path=missing_db, fallback_ips_file=fallback_txt)
    assert idx.total_entries == 1
    assert idx.match_ip("45.155.205.12").source == "proactive_ips"
    assert idx.match_ip("104.16.10.10") is None
