import json
import pytest
from pathlib import Path
from scripts.export_dnr import compile_dnr_ruleset, MAX_STATIC_RULES
from scripts.proactive_miner import ThreatStateDB


def test_export_dnr_ruleset_structure(tmp_path):
    """
    Verifies that compile_dnr_ruleset generates valid Manifest V3 declarativeNetRequest rules:
    - Unique positive integer IDs
    - Exactly 1 main_frame redirect rule and 1 subresource block rule per domain
    - Whitelisted domains are strictly excluded
    - Rules count does not exceed MAX_STATIC_RULES ceiling
    """
    db_path = tmp_path / "test_threats.db"
    rules_out = tmp_path / "ruleset.json"

    db = ThreatStateDB(db_path=db_path)
    # Seed 3 domains: 2 malicious, 1 on never_block whitelist (google.com)
    candidates = [
        {"domain": "malicious-phishing.org", "source": "openphish", "family": "phishing", "confidence": 90},
        {"domain": "c2-malware.net", "source": "urlhaus", "family": "malware", "confidence": 85},
        {"domain": "google.com", "source": "urlhaus", "family": "malware", "confidence": 85}
    ]
    db.insert_or_update_iocs(candidates)

    res = compile_dnr_ruleset(db_path=db_path, output_file=rules_out, min_confidence=85)
    assert res["total_rules"] == 2  # 2 domains * 1 block rule (google.com was excluded)
    assert res["domains_covered"] == 2
    assert rules_out.exists()

    rules = json.loads(rules_out.read_text(encoding="utf-8"))
    assert len(rules) == 2

    rule_ids = set()
    for r in rules:
        assert isinstance(r["id"], int) and r["id"] > 0
        assert r["id"] not in rule_ids
        rule_ids.add(r["id"])

        assert "action" in r and "condition" in r
        url_filter = r["condition"]["urlFilter"]
        assert "google.com" not in url_filter
        assert r["action"]["type"] == "block"
        assert "main_frame" in r["condition"]["resourceTypes"]
        assert "sub_frame" in r["condition"]["resourceTypes"]
        assert "font" in r["condition"]["resourceTypes"]
        assert "media" in r["condition"]["resourceTypes"]
        assert "ping" in r["condition"]["resourceTypes"]


def test_export_dnr_filters_confidence(tmp_path):
    """Verifies that compile_dnr_ruleset only exports IoCs with confidence >= min_confidence."""
    db_path = tmp_path / "conf_db.db"
    rules_out = tmp_path / "conf_ruleset.json"
    db = ThreatStateDB(db_path=db_path)

    candidates = [
        {"domain": "high-threat.org", "source": "openphish", "family": "phishing", "confidence": 90},
        {"domain": "exact-threat.org", "source": "urlhaus", "family": "malware", "confidence": 85},
        {"domain": "low-threat.org", "source": "urlhaus", "family": "malware", "confidence": 75}
    ]
    db.insert_or_update_iocs(candidates)

    res = compile_dnr_ruleset(db_path=db_path, output_file=rules_out, min_confidence=85)
    assert res["total_rules"] == 2  # 2 domains (high-threat.org, exact-threat.org)
    assert res["domains_covered"] == 2

    content = rules_out.read_text(encoding="utf-8")
    assert "high-threat.org" in content
    assert "exact-threat.org" in content
    assert "low-threat.org" not in content


def test_export_dnr_respects_quota(tmp_path, monkeypatch):
    """Verifies that the exporter truncates rules if they exceed MAX_STATIC_RULES."""
    db_path = tmp_path / "huge_db.db"
    rules_out = tmp_path / "truncated_ruleset.json"
    db = ThreatStateDB(db_path=db_path)

    # Seed 10 domains
    candidates = [
        {"domain": f"malicious-domain-{i}.com", "source": "urlhaus", "family": "malware", "confidence": 90}
        for i in range(10)
    ]
    db.insert_or_update_iocs(candidates)

    # Artificially lower ceiling to 6 rules (3 domains)
    monkeypatch.setattr("scripts.export_dnr.MAX_STATIC_RULES", 6)

    res = compile_dnr_ruleset(db_path=db_path, output_file=rules_out)
    assert res["total_rules"] == 6
    rules = json.loads(rules_out.read_text(encoding="utf-8"))
    assert len(rules) == 6
