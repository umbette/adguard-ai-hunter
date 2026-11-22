import sys
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.build_filter import validate_and_compile, OUTPUT_FILE


def test_filter_compilation_and_guardrails():
    validate_and_compile()
    
    assert OUTPUT_FILE.exists()
    content = OUTPUT_FILE.read_text(encoding="utf-8")
    
    assert "||google.com^" not in content
    assert "||apple.com^" not in content
    assert "||co.uk^" not in content
    assert "||com^" not in content
    assert "||pages.dev^" not in content
    assert "||workers.dev^" not in content
    assert "||github.io^" not in content
    assert "$dnsrewrite" not in content
    assert "$important" not in content
    assert "@@" not in content
    assert "! Number of rules:" in content


def test_adverse_psl_fixtures_rejection(tmp_path):
    """
    Directly stresses build_filter with adversarial inputs:
    - Bare public suffixes (co.uk, com, gov.uk)
    - Bare private multi-tenant suffixes (pages.dev, workers.dev, github.io)
    - Malformed and injection attempts
    - Protected infrastructure domains
    - Valid specific tenant hostnames
    """
    test_src = tmp_path / "test_domains.txt"
    test_never_block = tmp_path / "never_block.txt"
    test_out = tmp_path / "output_filter.txt"

    never_block_content = "google.com\nmicrosoft.com\n"
    test_never_block.write_text(never_block_content, encoding="utf-8")

    adverse_inputs = [
        # 1. Bare public suffixes & TLDs (MUST REJECT)
        "co.uk",
        "com",
        "org",
        "gov.uk",
        # 2. Bare private multi-tenant suffixes (MUST REJECT)
        "pages.dev",
        "workers.dev",
        "github.io",
        "duckdns.org",
        "vercel.app",
        # 3. Injection and invalid formatting (MUST REJECT)
        "bad..domain.com",
        "evil.com/payload",
        "inject.com$dnsrewrite",
        "malicious.com$important",
        # 4. Protected infrastructure (MUST FILTER)
        "google.com",
        "login.microsoft.com",
        # 5. Valid specific tenant and domain entries (MUST ACCEPT)
        "phishing-threat.pages.dev",
        "c2-controller.workers.dev",
        "malware-payload.github.io",
        "stealer-c2.com",
    ]
    test_src.write_text("\n".join(adverse_inputs), encoding="utf-8")

    res = validate_and_compile(
        source_files=[test_src],
        never_block_path=test_never_block,
        output_path=test_out
    )

    # 4 valid tenant/domain rules, 2 protected infrastructure domains, 13 rejected bare/malformed entries
    assert res["valid"] == 4
    assert res["protected"] == 2
    assert res["skipped"] == 13

    compiled = test_out.read_text(encoding="utf-8")

    # Verify bare suffixes and TLDs are strictly rejected
    for bare_suffix in ["||co.uk^", "||com^", "||org^", "||gov.uk^", "||pages.dev^", "||workers.dev^", "||github.io^", "||duckdns.org^", "||vercel.app^"]:
        assert bare_suffix not in compiled, f"Vulnerability: bare suffix {bare_suffix} was compiled into filter!"

    # Verify protected domains are excluded
    assert "||google.com^" not in compiled
    assert "||login.microsoft.com^" not in compiled

    # Verify legitimate specific tenant threats are compiled accurately
    assert "||phishing-threat.pages.dev^\n" in compiled
    assert "||c2-controller.workers.dev^\n" in compiled
    assert "||malware-payload.github.io^\n" in compiled
    assert "||stealer-c2.com^\n" in compiled


def test_end_to_end_idn_punycode_pipeline(tmp_path):
    """
    End-to-end verification that Internationalized Domain Names (IDNs)
    are sanitized into valid Punycode, accepted by the compiler, and bare Punycode TLDs are rejected.
    """
    from scripts.proactive_miner import DomainSanitizer

    sanitizer = DomainSanitizer()

    # 1. Test Unicode conversion in sanitizer
    idn_domain = "phishing-bank.中国"
    sanitized_idn = sanitizer.sanitize(idn_domain)
    assert sanitized_idn == "phishing-bank.xn--fiqs8s"

    # 2. Test malformed punycode rejection in sanitizer
    assert sanitizer.sanitize("evil.xn--invalid!!!") is None
    assert sanitizer.sanitize("evil.xn--") is None

    # 3. Test compilation pipeline
    test_src = tmp_path / "idn_domains.txt"
    test_out = tmp_path / "idn_output.txt"
    test_src.write_text(
        f"{sanitized_idn}\n"
        "phish.xn--vermgensberatung-pwb\n"
        "xn--fiqs8s\n",  # Bare Punycode TLD (must reject)
        encoding="utf-8"
    )

    res = validate_and_compile(
        source_files=[test_src],
        output_path=test_out
    )

    assert res["valid"] == 2
    assert res["skipped"] == 1  # xn--fiqs8s bare suffix rejected

    content = test_out.read_text(encoding="utf-8")
    assert "||phishing-bank.xn--fiqs8s^\n" in content
    assert "||phish.xn--vermgensberatung-pwb^\n" in content
    assert "||xn--fiqs8s^" not in content


def test_stream_feed_lines_limits():
    """Verifies that stream_feed_lines drops bloated line buffers and raises FeedStreamLimitError on bound violations."""
    import io
    import pytest
    from scripts.proactive_miner import stream_feed_lines, FeedStreamLimitError

    # 1. Multi-chunk non-newline oversized line (> 65,536 chars across chunk boundaries)
    # The tail of the oversized line (evil-tail.example.com) must be discarded along with the prefix!
    multi_chunk_oversized = b"x" * 70000 + b"evil-tail.example.com\nlegitimate-domain.com\n"
    mock_resp_multichunk = io.BytesIO(multi_chunk_oversized)
    lines_multichunk = list(stream_feed_lines(mock_resp_multichunk, max_bytes=1000000))
    assert lines_multichunk == ["legitimate-domain.com"]

    # 2. Exceeding max_bytes raises FeedStreamLimitError (fail-closed)
    mock_resp_bytes = io.BytesIO(b"line1.com\nline2.com\nline3.com\n")
    with pytest.raises(FeedStreamLimitError, match="byte limit"):
        list(stream_feed_lines(mock_resp_bytes, max_bytes=15))

    # 3. Exceeding max_lines raises FeedStreamLimitError (fail-closed)
    mock_resp_lines = io.BytesIO(b"a.com\nb.com\nc.com\nd.com\n")
    with pytest.raises(FeedStreamLimitError, match="line limit"):
        list(stream_feed_lines(mock_resp_lines, max_lines=2))


def test_offline_psl_snapshot_reproducibility(tmp_path, monkeypatch):
    """Verifies that full validate_and_compile succeeds completely offline without network access using snapshot fallback."""
    import socket
    import urllib.request
    import tldextract

    # Block all network sockets to strictly simulate air-gapped / offline environment
    def guard_network(*args, **kwargs):
        raise OSError("Network is unreachable (simulated offline build)")

    monkeypatch.setattr(socket, "socket", guard_network)
    monkeypatch.setattr(urllib.request, "urlopen", guard_network)

    # Isolate cache in an empty temporary directory with fallback enabled
    empty_cache = tmp_path / "empty_psl_cache"
    empty_cache.mkdir()

    ext = tldextract.TLDExtract(
        cache_dir=str(empty_cache),
        include_psl_private_domains=True,
        fallback_to_snapshot=True
    )

    # Must accurately identify private suffixes without network access
    res_bare = ext("pages.dev")
    assert not res_bare.domain and res_bare.suffix == "pages.dev"

    res_tenant = ext("my-service.pages.dev")
    assert res_tenant.domain == "my-service" and res_tenant.suffix == "pages.dev"

    # End-to-end compiler test under offline conditions
    test_src = tmp_path / "offline_domains.txt"
    test_out = tmp_path / "offline_output.txt"
    test_src.write_text("evil.pages.dev\npages.dev\nco.uk\nthreat-actor.org\n", encoding="utf-8")

    res = validate_and_compile(
        source_files=[test_src],
        output_path=test_out
    )

    assert res["valid"] == 2  # evil.pages.dev and threat-actor.org
    assert res["skipped"] == 2  # pages.dev and co.uk bare suffixes
    content = test_out.read_text(encoding="utf-8")
    assert "||evil.pages.dev^\n" in content
    assert "||threat-actor.org^\n" in content
    assert "||pages.dev^" not in content
    assert "||co.uk^" not in content


def test_partial_feed_failure_preserves_offline_feed_iocs(tmp_path):
    """
    Verifies that when one feed fails and another succeeds, expired IoCs belonging
    to the unreachable feed are NOT prematurely purged from the database.
    """
    from datetime import datetime, timezone, timedelta
    from scripts.proactive_miner import ThreatStateDB
    import sqlite3

    db_path = tmp_path / "threat_state.db"
    db = ThreatStateDB(db_path=db_path)

    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    now_str = datetime.now(timezone.utc).isoformat()

    # Seed 2 expired IoCs from different sources
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            INSERT INTO mined_iocs (domain, source, malware_family, confidence, first_seen, last_seen, expires_at, status)
            VALUES (?, ?, 'phishing', 90, ?, ?, ?, 'active')
        """, ("expired-openphish.com", "openphish", now_str, now_str, past))
        conn.execute("""
            INSERT INTO mined_iocs (domain, source, malware_family, confidence, first_seen, last_seen, expires_at, status)
            VALUES (?, ?, 'malware', 85, ?, ?, ?, 'active')
        """, ("expired-urlhaus.com", "urlhaus", now_str, now_str, past))

    # Scenario: OpenPhish failed, only URLhaus succeeded
    purged = db.purge_expired(eligible_sources=["urlhaus"])
    assert purged == 1

    # OpenPhish expired IoC must be preserved; URLhaus expired IoC must be purged
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT domain FROM mined_iocs")
        remaining = [row[0] for row in cur.fetchall()]
        assert "expired-openphish.com" in remaining
        assert "expired-urlhaus.com" not in remaining

