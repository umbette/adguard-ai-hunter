import json
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
EXTENSION_DIR = ROOT_DIR / "extension"

BENIGN_DOMAINS = {
    "next.com", "next.co.uk", "iper.it", "beer.com", "skip.com", "spin.com",
    "la-poste.fr", "laposte.net", "poste.ch", "deutschepost.de", "gls-bank.de",
    "spedisci-subito.it", "ips.com", "news.com", "tips.com", "open.com",
    "uber.com", "maps.com", "trip.com", "free.com", "home.com", "care.com"
}

PHISHING_INTENT_TOKENS = [
    "login", "accedi", "auth", "verify", "verifica", "secure", "sicurezza",
    "assistenza", "servizio", "servizi", "conto", "online", "portal", "update",
    "banking", "privati", "clienti", "support", "help", "pay"
]


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


def get_etld_plus_one(hostname: str, suffixes: set[str] | list[str]) -> str:
    if not hostname:
        return ""
    parts = hostname.lower().split(".")
    if len(parts) <= 1:
        return hostname.lower()

    suffixes_set = set(suffixes) if isinstance(suffixes, list) else suffixes

    for i in range(min(len(parts) - 1, 4), 1, -1):
        candidate = ".".join(parts[-i:])
        if candidate in suffixes_set:
            return ".".join(parts[-(i + 1):])

    return ".".join(parts[-2:])


def keyword_matches(domain_core: str, kw: str) -> bool:
    if domain_core == kw:
        return True
    regex = re.compile(rf"(^|[-_0-9]){re.escape(kw)}([-_0-9]|$)", re.IGNORECASE)
    if regex.search(domain_core):
        return True
    for token in PHISHING_INTENT_TOKENS:
        if domain_core == f"{kw}{token}" or domain_core == f"{token}{kw}":
            return True
    return False


def evaluate_domain(hostname: str, brands: dict, suffixes: list[str]) -> bool:
    raw_lower = hostname.lower()
    raw_etld1 = get_etld_plus_one(raw_lower, suffixes)

    # 1. Strict official domain check on RAW hostname
    for key, brand in brands.items():
        if any(raw_etld1 == d or raw_etld1.endswith("." + d) for d in brand["officialDomains"]):
            return False

    # 2. Benign known domains immunity
    if raw_etld1 in BENIGN_DOMAINS or raw_lower in BENIGN_DOMAINS:
        return False

    domain_core = raw_etld1.split(".")[0]
    subparts = (
        raw_lower[:-len(raw_etld1)].rstrip(".").split(".")
        if raw_lower.endswith(raw_etld1) and len(raw_lower) > len(raw_etld1)
        else []
    )

    for key, brand in brands.items():
        # Subdomain Phishing vector
        for sub in subparts:
            if not sub:
                continue
            for kw in brand["keywords"]:
                if keyword_matches(sub, kw):
                    return True

        # Core Domain Inspection
        for kw in brand["keywords"]:
            if keyword_matches(domain_core, kw):
                return True
            # Levenshtein distance: strictly length >= 5 to prevent false positives on next, beer, ips
            if len(kw) >= 5 and len(domain_core) >= 5 and abs(len(domain_core) - len(kw)) <= 1:
                if damerau_levenshtein(domain_core, kw) <= 1:
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
    assert not evaluate_domain("next.com", brands, suffixes)
    assert not evaluate_domain("beer.com", brands, suffixes)
    assert not evaluate_domain("ips.com", brands, suffixes)
    assert not evaluate_domain("news.com", brands, suffixes)
    assert not evaluate_domain("uber.com", brands, suffixes)
    assert not evaluate_domain("open.com", brands, suffixes)
    assert not evaluate_domain("amazonaws.com", brands, suffixes)
    assert not evaluate_domain("s3.amazonaws.com", brands, suffixes)
    assert not evaluate_domain("impostore.it", brands, suffixes)
    assert not evaluate_domain("risposte.it", brands, suffixes)
    assert not evaluate_domain("postecert.it", brands, suffixes)
    assert not evaluate_domain("amazon.it", brands, suffixes)
    assert not evaluate_domain("poste.it", brands, suffixes)
    assert not evaluate_domain("bper.it", brands, suffixes)
    assert not evaluate_domain("spid.gov.it", brands, suffixes)
    assert not evaluate_domain("metamask.io", brands, suffixes)
    assert not evaluate_domain("revolut.com", brands, suffixes)
    assert not evaluate_domain("binance.com", brands, suffixes)
    assert not evaluate_domain("microsoft.com", brands, suffixes)
    assert not evaluate_domain("google.com", brands, suffixes)
    assert not evaluate_domain("apple.com", brands, suffixes)

    # 2. Known spoofing / phishing attempts MUST be flagged
    assert evaluate_domain("poste-servizio.com", brands, suffixes)
    assert evaluate_domain("verifica-postepay.net", brands, suffixes)
    assert evaluate_domain("amazon-login-verify.com", brands, suffixes)
    assert evaluate_domain("paypa1.com", brands, suffixes)
    assert evaluate_domain("intesasampaolo.com", brands, suffixes)
    assert evaluate_domain("brt-tracking-pacco.org", brands, suffixes)
    assert evaluate_domain("metamask-login.com", brands, suffixes)
    assert evaluate_domain("revolut-security.net", brands, suffixes)

    # 3. Subdomain and compound phish attacks
    assert evaluate_domain("poste.attacker-server.com", brands, suffixes)
    assert evaluate_domain("postepay.free-hosting.net", brands, suffixes)
    assert evaluate_domain("postelogin.com", brands, suffixes)
    assert evaluate_domain("serviziposte.com", brands, suffixes)
    assert evaluate_domain("finecobanking.com", brands, suffixes)

    # 4. Multi-part public suffix extraction across global ccTLDs and platforms
    assert get_etld_plus_one("login.service.gov.it", suffixes) == "service.gov.it"
    assert get_etld_plus_one("my-app.pages.dev", suffixes) == "my-app.pages.dev"
    assert get_etld_plus_one("portal.co.uk", suffixes) == "portal.co.uk"
    assert get_etld_plus_one("auth.bank.co.in", suffixes) == "bank.co.in"
    assert get_etld_plus_one("empresa.com.br", suffixes) == "empresa.com.br"
    assert get_etld_plus_one("shop.com.cn", suffixes) == "shop.com.cn"
    assert get_etld_plus_one("secure.org.il", suffixes) == "secure.org.il"
    assert get_etld_plus_one("news.co.za", suffixes) == "news.co.za"
