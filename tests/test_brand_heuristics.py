import json
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
EXTENSION_DIR = ROOT_DIR / "extension"


def damerau_levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    d = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        d[i][0] = i
    for j in range(n + 1):
        d[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,       # deletion
                d[i][j - 1] + 1,       # insertion
                d[i - 1][j - 1] + cost # substitution
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost) # transposition
    return d[m][n]


def get_etld_plus_one(hostname: str, suffixes: list[str]) -> str:
    if not hostname:
        return ""
    parts = hostname.lower().split(".")
    if len(parts) <= 1:
        return hostname.lower()

    for i in range(min(len(parts) - 1, 3), 1, -1):
        candidate = ".".join(parts[-i:])
        if candidate in suffixes:
            return ".".join(parts[-(i + 1):])

    return ".".join(parts[-2:])


def keyword_matches(domain_core: str, kw: str) -> bool:
    if domain_core == kw:
        return True
    regex = re.compile(rf"(^|[-_0-9]){re.escape(kw)}([-_0-9]|$)", re.IGNORECASE)
    return bool(regex.search(domain_core))


def evaluate_domain(hostname: str, brands: dict, suffixes: list[str]) -> bool:
    etld1 = get_etld_plus_one(hostname, suffixes)
    domain_core = etld1.split(".")[0]

    for key, brand in brands.items():
        if any(etld1 == d or etld1.endswith("." + d) for d in brand["officialDomains"]):
            continue

        for kw in brand["keywords"]:
            if keyword_matches(domain_core, kw):
                return True
            if len(kw) >= 4 and damerau_levenshtein(domain_core, kw) <= 1:
                return True

    return False


def test_brand_heuristics_against_false_positives():
    brands_file = EXTENSION_DIR / "data" / "brands.json"
    suffixes_file = EXTENSION_DIR / "data" / "public_suffixes.json"

    assert brands_file.exists()
    assert suffixes_file.exists()

    brands = json.loads(brands_file.read_text(encoding="utf-8"))
    suffixes = json.loads(suffixes_file.read_text(encoding="utf-8"))

    # 1. Benign domains must NEVER be flagged as spoofing (False Positive Prevention)
    assert not evaluate_domain("amazonaws.com", brands, suffixes)
    assert not evaluate_domain("s3.amazonaws.com", brands, suffixes)
    assert not evaluate_domain("impostore.it", brands, suffixes)
    assert not evaluate_domain("risposte.it", brands, suffixes)
    assert not evaluate_domain("postecert.it", brands, suffixes)
    assert not evaluate_domain("amazon.it", brands, suffixes)
    assert not evaluate_domain("poste.it", brands, suffixes)
    assert not evaluate_domain("bper.it", brands, suffixes)
    assert not evaluate_domain("spid.gov.it", brands, suffixes)

    # 2. Known spoofing / phishing attempts MUST be flagged
    assert evaluate_domain("poste-servizio.com", brands, suffixes)
    assert evaluate_domain("verifica-postepay.net", brands, suffixes)
    assert evaluate_domain("amazon-login-verify.com", brands, suffixes)
    assert evaluate_domain("paypa1.com", brands, suffixes)
    assert evaluate_domain("intesasampaolo.com", brands, suffixes)
    assert evaluate_domain("brt-tracking-pacco.org", brands, suffixes)

    # 3. Multi-part public suffix extraction
    assert get_etld_plus_one("login.service.gov.it", suffixes) == "service.gov.it"
    assert get_etld_plus_one("my-app.pages.dev", suffixes) == "my-app.pages.dev"
    assert get_etld_plus_one("portal.co.uk", suffixes) == "portal.co.uk"
