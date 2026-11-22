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
    assert "$dnsrewrite" not in content
    assert "$important" not in content
    assert "@@" not in content
    assert "! Number of rules:" in content


if __name__ == "__main__":
    test_filter_compilation_and_guardrails()
    print("Zero-trust guardrails & filter build verified successfully!")

