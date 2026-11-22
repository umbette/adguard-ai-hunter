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
    """Verifies that stream_feed_lines respects byte bounds and line length limits."""
    import io
    from scripts.proactive_miner import stream_feed_lines

    # Simulated feed with one valid line, one oversized line (3000 chars), and another valid line
    data = (
        b"valid-one.com\n"
        + b"a" * 3000 + b".com\n"
        + b"valid-two.com\n"
    )
    mock_resp = io.BytesIO(data)
    lines = list(stream_feed_lines(mock_resp, max_bytes=10000))
    assert lines == ["valid-one.com", "valid-two.com"]

    # Test byte limit cutoff
    mock_resp_large = io.BytesIO(b"line1.com\nline2.com\nline3.com\n")
    lines_cutoff = list(stream_feed_lines(mock_resp_large, max_bytes=12))
    assert len(lines_cutoff) <= 2

