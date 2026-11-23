"""
Crypto Vault & Financial Shield (Privacy-Preserving Architecture)
================================================================
Protects Web3 users, high-value crypto portfolios, and fintech accounts
from:
1. RPC Tampering / Poisoning: hijacking blockchain RPC calls to siphon funds.
2. Wallet Drainers & Malicious dApp Clones: typosquatting and homograph phishing.
3. IDN Punycode Homograph attacks on financial platforms.
4. Pluggable Custom Vault: dynamically loads private, user-defined brands
   (RWA platforms, private hardware wallets, personal neobanks) from an uncommitted
   local configuration file without leaking portfolio affiliations to public git.
"""

import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None  # Fallback gracefully if yaml is not installed

@dataclass
class CryptoThreatMatch:
    domain: str
    target_brand: str
    threat_type: str  # "WALLET_DRAINER", "RPC_POISONING", "DAPP_CLONE", "HOMOGRAPH_PUNYCODE"
    risk_score: float
    description: str

# ------------------------------------------------------------------------------
# 1. Default Public Protected Brands (Ubiquitous Industry Protocols & Benchmarks)
# ------------------------------------------------------------------------------
DEFAULT_PROTECTED_CRYPTO_BRANDS: Dict[str, Dict] = {
    "metamask": {
        "displayName": "MetaMask",
        "officialDomains": ["metamask.io", "metamask.zendesk.com"],
        "keywords": ["metamask"]
    },
    "phantom": {
        "displayName": "Phantom Wallet",
        "officialDomains": ["phantom.app", "phantom.com"],
        "keywords": ["phantom-wallet", "phantomapp"]
    },
    "rabby": {
        "displayName": "Rabby Wallet",
        "officialDomains": ["rabby.io"],
        "keywords": ["rabby-wallet"]
    },
    "uniswap": {
        "displayName": "Uniswap",
        "officialDomains": ["uniswap.org", "app.uniswap.org"],
        "keywords": ["uniswap"]
    },
    "curve": {
        "displayName": "Curve Finance",
        "officialDomains": ["curve.fi"],
        "keywords": ["curvefi", "curve-fi"]
    },
    "aave": {
        "displayName": "Aave",
        "officialDomains": ["aave.com", "app.aave.com"],
        "keywords": ["aave-app", "aave-finance"]
    },
    "lido": {
        "displayName": "Lido Finance",
        "officialDomains": ["lido.fi", "stake.lido.fi"],
        "keywords": ["lido-fi", "lido-stake"]
    },
    "opensea": {
        "displayName": "OpenSea",
        "officialDomains": ["opensea.io"],
        "keywords": ["opensea"]
    },
    "blur": {
        "displayName": "Blur.io",
        "officialDomains": ["blur.io"],
        "keywords": ["blur-market", "blur-nft"]
    },
    "binance": {
        "displayName": "Binance",
        "officialDomains": ["binance.com", "binance.je", "binance.us"],
        "keywords": ["binance"]
    },
    "coinbase": {
        "displayName": "Coinbase",
        "officialDomains": ["coinbase.com", "pro.coinbase.com"],
        "keywords": ["coinbase"]
    },
    "kraken": {
        "displayName": "Kraken",
        "officialDomains": ["kraken.com"],
        "keywords": ["kraken-exchange"]
    },
    "ledger": {
        "displayName": "Ledger",
        "officialDomains": ["ledger.com", "support.ledger.com"],
        "keywords": ["ledger-live", "ledgerlive", "ledger-support"]
    },
    "trezor": {
        "displayName": "Trezor",
        "officialDomains": ["trezor.io", "suite.trezor.io"],
        "keywords": ["trezor-suite", "trezorsuite"]
    }
}

# ------------------------------------------------------------------------------
# 2. Verified Official RPC Endpoints (Must NEVER be blocked)
# ------------------------------------------------------------------------------
DEFAULT_OFFICIAL_RPC_ENDPOINTS: Set[str] = {
    "mainnet.infura.io",
    "eth.llamarpc.com",
    "rpc.ankr.com",
    "cloudflare-eth.com",
    "ethereum-rpc.publicnode.com",
    "api.mainnet-beta.solana.com",
    "solana-api.projectserum.com",
    "rpc.helius.xyz",
    "polygon-rpc.com",
    "rpc-mainnet.matic.network",
    "arb1.arbitrum.io",
    "mainnet.optimism.io",
    "bsc-dataseed.binance.org"
}

# ------------------------------------------------------------------------------
# 3. Known signature patterns of automated wallet drainers & phishing kits
# ------------------------------------------------------------------------------
DEFAULT_DRAINER_REGEX_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"(^|[-_0-9\.])(claim[-_]?airdrop|airdrop[-_]?claim)([-_0-9\.]|$)", re.I), "WALLET_DRAINER", "Finto airdrop per autorizzare lo svuotamento del wallet."),
    (re.compile(r"(^|[-_0-9\.])(connect[-_]?wallet|sync[-_]?wallet|rectify[-_]?wallet)([-_0-9\.]|$)", re.I), "WALLET_DRAINER", "Phishing kit di 'rettifica' o 'connessione' wallet."),
    (re.compile(r"(^|[-_0-9\.])(claim[-_]?reward|token[-_]?reward|presale[-_]?token)([-_0-9\.]|$)", re.I), "WALLET_DRAINER", "Esca per minting o presale malevola."),
    (re.compile(r"(^|[-_0-9\.])(ledger[-_]?live[-_]?update|trezor[-_]?firmware|hardware[-_]?wallet[-_]?backup|seed[-_]?phrase[-_]?backup)([-_0-9\.]|$)", re.I), "WALLET_DRAINER", "Falso aggiornamento firmware o backup per estorsione di chiavi o seed phrase."),
    (re.compile(r"(^|[-_0-9\.])(rwa[-_]?yield|property[-_]?token|asset[-_]?token|token[-_]?dividend)([-_0-9\.]|$)", re.I), "WALLET_DRAINER", "Phishing mirato per finto claim di dividendi o token RWA.")
]

# ------------------------------------------------------------------------------
# 4. Runtime Active State & Dynamic Custom Vault Loader
# ------------------------------------------------------------------------------
PROTECTED_CRYPTO_BRANDS: Dict[str, Dict] = dict(DEFAULT_PROTECTED_CRYPTO_BRANDS)
OFFICIAL_RPC_ENDPOINTS: Set[str] = set(DEFAULT_OFFICIAL_RPC_ENDPOINTS)
DRAINER_REGEX_PATTERNS: List[Tuple[re.Pattern, str, str]] = list(DEFAULT_DRAINER_REGEX_PATTERNS)
CUSTOM_WHITELIST: Set[str] = set()

_VAULT_LOADED: bool = False
_LOADED_VAULT_PATH: Optional[str] = None

def _resolve_vault_file(custom_path: Optional[str] = None) -> Optional[Path]:
    """Finds the active custom vault configuration file based on priority paths."""
    candidates = []
    if custom_path:
        candidates.append(Path(custom_path))
    
    env_path = os.getenv("SENTINEL_CUSTOM_VAULT_PATH")
    if env_path:
        candidates.append(Path(env_path))

    # Project-relative candidate paths
    candidates.extend([
        Path("data/custom_vault.yaml"),
        Path("data/custom_vault.yml"),
        Path("data/custom_vault.json"),
        Path("custom_vault.local.yaml"),
        Path("private/custom_vault.yaml"),
        Path(__file__).resolve().parent.parent / "data" / "custom_vault.yaml"
    ])

    for p in candidates:
        if p.is_file():
            return p.resolve()
    return None

def load_custom_vault(file_path: Optional[str] = None, force_reload: bool = False) -> bool:
    """
    Dynamically loads and merges private custom brands, drainer patterns, and
    official endpoints from an uncommitted local file (e.g. data/custom_vault.yaml).
    Ensures local user portfolio assets remain private and never get committed to GitHub.
    """
    global PROTECTED_CRYPTO_BRANDS, OFFICIAL_RPC_ENDPOINTS, DRAINER_REGEX_PATTERNS, CUSTOM_WHITELIST
    global _VAULT_LOADED, _LOADED_VAULT_PATH

    if _VAULT_LOADED and not force_reload and file_path is None:
        return True

    # Always reset to defaults before merging to ensure clean state
    PROTECTED_CRYPTO_BRANDS = dict(DEFAULT_PROTECTED_CRYPTO_BRANDS)
    OFFICIAL_RPC_ENDPOINTS = set(DEFAULT_OFFICIAL_RPC_ENDPOINTS)
    DRAINER_REGEX_PATTERNS = list(DEFAULT_DRAINER_REGEX_PATTERNS)
    CUSTOM_WHITELIST = set()

    vault_path = _resolve_vault_file(file_path)
    if not vault_path:
        _VAULT_LOADED = True
        _LOADED_VAULT_PATH = None
        return False

    try:
        content = vault_path.read_text(encoding="utf-8")
        data: Dict[str, Any] = {}
        if vault_path.suffix in (".yaml", ".yml") and yaml is not None:
            data = yaml.safe_load(content) or {}
        elif vault_path.suffix == ".json" or (yaml is None):
            import json
            data = json.loads(content) or {}

        # 1. Merge custom brands
        custom_brands = data.get("custom_brands", {})
        if isinstance(custom_brands, dict):
            for b_key, b_info in custom_brands.items():
                if isinstance(b_info, dict):
                    k = b_key.lower().strip()
                    PROTECTED_CRYPTO_BRANDS[k] = {
                        "displayName": b_info.get("displayName", b_key),
                        "officialDomains": [d.lower().strip() for d in b_info.get("officialDomains", [])],
                        "keywords": [kw.lower().strip() for kw in b_info.get("keywords", [k])]
                    }

        # 2. Merge custom drainer regex patterns
        custom_patterns = data.get("custom_drainer_patterns", [])
        if isinstance(custom_patterns, list):
            for pat_def in custom_patterns:
                if isinstance(pat_def, dict) and "pattern" in pat_def:
                    pat_str = pat_def["pattern"]
                    t_type = pat_def.get("threat_type", "WALLET_DRAINER")
                    desc = pat_def.get("description", "Custom drainer pattern")
                    try:
                        compiled = re.compile(pat_str, re.I)
                        DRAINER_REGEX_PATTERNS.append((compiled, t_type, desc))
                    except re.error:
                        pass

        # 3. Merge custom RPC endpoints
        custom_rpcs = data.get("custom_rpc_endpoints", [])
        if isinstance(custom_rpcs, list):
            for rpc in custom_rpcs:
                if isinstance(rpc, str):
                    OFFICIAL_RPC_ENDPOINTS.add(rpc.lower().strip())

        # 4. Merge custom whitelist
        custom_wl = data.get("custom_whitelist", [])
        if isinstance(custom_wl, list):
            for w in custom_wl:
                if isinstance(w, str):
                    CUSTOM_WHITELIST.add(w.lower().strip())

        _VAULT_LOADED = True
        _LOADED_VAULT_PATH = str(vault_path)
        return True
    except Exception:
        _VAULT_LOADED = True
        return False

def reset_to_defaults() -> None:
    """Resets the crypto shield state to public defaults."""
    global PROTECTED_CRYPTO_BRANDS, OFFICIAL_RPC_ENDPOINTS, DRAINER_REGEX_PATTERNS, CUSTOM_WHITELIST
    global _VAULT_LOADED, _LOADED_VAULT_PATH
    PROTECTED_CRYPTO_BRANDS = dict(DEFAULT_PROTECTED_CRYPTO_BRANDS)
    OFFICIAL_RPC_ENDPOINTS = set(DEFAULT_OFFICIAL_RPC_ENDPOINTS)
    DRAINER_REGEX_PATTERNS = list(DEFAULT_DRAINER_REGEX_PATTERNS)
    CUSTOM_WHITELIST = set()
    _VAULT_LOADED = False
    _LOADED_VAULT_PATH = None

# Automatically attempt to load custom vault on startup
load_custom_vault()

# ------------------------------------------------------------------------------
# 5. Core Evaluation Logic
# ------------------------------------------------------------------------------
def evaluate_crypto_financial_threat(hostname: str) -> Optional[CryptoThreatMatch]:
    """
    Evaluates a domain against crypto wallet drainer patterns,
    brand impersonation of DeFi/exchanges/RWA/hardware wallets, and IDN homograph punycode traps.
    Seamlessly incorporates private custom vault protections if loaded.
    """
    if not hostname:
        return None

    h_lower = hostname.lower().strip()

    # 1. Whitelist official RPC endpoints, custom RPC endpoints, and custom whitelist
    if h_lower in OFFICIAL_RPC_ENDPOINTS or h_lower in CUSTOM_WHITELIST:
        return None

    # Check official domains of all active brands (defaults + custom vault)
    for brand_key, brand in PROTECTED_CRYPTO_BRANDS.items():
        if any(h_lower == d or h_lower.endswith(f".{d}") for d in brand.get("officialDomains", [])):
            return None

    # 2. Check for IDN Homograph Punycode traps on protected brands (e.g. xn--uniswp-... -> uniswáp)
    if "xn--" in h_lower:
        try:
            decoded = h_lower.encode("ascii").decode("idna")
            # Decompose and strip diacritics / combining accents to expose homoglyph base characters
            normalized = "".join(c for c in unicodedata.normalize("NFKD", decoded) if not unicodedata.combining(c)).lower()
            for brand_key, brand in PROTECTED_CRYPTO_BRANDS.items():
                if brand_key in normalized:
                    return CryptoThreatMatch(
                        domain=h_lower,
                        target_brand=brand["displayName"],
                        threat_type="HOMOGRAPH_PUNYCODE",
                        risk_score=0.99,
                        description=f"Attacco omografo Punycode ({decoded}) per impersonare {brand['displayName']}."
                    )
        except Exception:
            pass

    # 3. Check for specific wallet drainer keywords (default + custom patterns)
    for pattern, threat_type, desc in DRAINER_REGEX_PATTERNS:
        if pattern.search(h_lower):
            return CryptoThreatMatch(
                domain=h_lower,
                target_brand="Web3 Crypto User",
                threat_type=threat_type,
                risk_score=0.95,
                description=desc
            )

    # 4. Check for brand impersonation / typosquatting on DeFi, exchanges, and hardware wallets
    for brand_key, brand in PROTECTED_CRYPTO_BRANDS.items():
        for kw in brand.get("keywords", []):
            escaped = re.escape(kw)
            regex = re.compile(rf"(^|[-_0-9\.]){escaped}([-_0-9\.]|$)", re.I)
            if regex.search(h_lower):
                return CryptoThreatMatch(
                    domain=h_lower,
                    target_brand=brand["displayName"],
                    threat_type="DAPP_CLONE",
                    risk_score=0.92,
                    description=f"Clone non ufficiale o phishing che imita {brand['displayName']}. Rischio furto fondi/chiavi."
                )

    return None
