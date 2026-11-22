"""
Crypto Vault & Financial Shield
===============================
Protects high-net-worth users, mobile banking customers, and Web3 crypto wallet owners
(MetaMask, Phantom, Ledger, Revolut) from:
1. RPC Tampering / Poisoning: hijacking blockchain RPC calls to siphon funds.
2. Wallet Drainers & Malicious dApp Clones: typosquatting and homograph phishing on DeFi protocols.
3. IDN Punycode Homograph attacks on financial platforms.
"""

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class CryptoThreatMatch:
    domain: str
    target_brand: str
    threat_type: str  # "WALLET_DRAINER", "RPC_POISONING", "DAPP_CLONE", "HOMOGRAPH_PUNYCODE"
    risk_score: float
    description: str

# Protected High-Value Financial & Crypto Brands
PROTECTED_CRYPTO_BRANDS: Dict[str, Dict] = {
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
    },
    "revolut": {
        "displayName": "Revolut",
        "officialDomains": ["revolut.com", "business.revolut.com"],
        "keywords": ["revolut"]
    }
}

# Verified Official RPC Node Endpoints (Must NEVER be blocked)
OFFICIAL_RPC_ENDPOINTS: Set[str] = {
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

# Known signature patterns of automated wallet drainers & phishing kits
DRAINER_REGEX_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"(^|[-_0-9])(claim[-_]?airdrop|airdrop[-_]?claim)([-_0-9]|$)", re.I), "WALLET_DRAINER", "Finto airdrop per autorizzare lo svuotamento del wallet."),
    (re.compile(r"(^|[-_0-9])(connect[-_]?wallet|sync[-_]?wallet|rectify[-_]?wallet)([-_0-9]|$)", re.I), "WALLET_DRAINER", "Phishing kit di 'rettifica' o 'connessione' wallet."),
    (re.compile(r"(^|[-_0-9])(claim[-_]?reward|token[-_]?reward|presale[-_]?token)([-_0-9]|$)", re.I), "WALLET_DRAINER", "Esca per minting o presale malevola."),
    (re.compile(r"(^|[-_0-9])(ledger[-_]?live[-_]?update|trezor[-_]?firmware)([-_0-9]|$)", re.I), "WALLET_DRAINER", "Falso aggiornamento firmware per estorsione della seed phrase (24 parole).")
]

def evaluate_crypto_financial_threat(hostname: str) -> Optional[CryptoThreatMatch]:
    """
    Evaluates a domain against crypto wallet drainer patterns,
    brand impersonation of DeFi/exchanges, and IDN homograph punycode traps.
    """
    if not hostname:
        return None

    h_lower = hostname.lower().strip()

    # 1. Whitelist official RPC endpoints & known official dApps
    if h_lower in OFFICIAL_RPC_ENDPOINTS:
        return None

    for brand_key, brand in PROTECTED_CRYPTO_BRANDS.items():
        if any(h_lower == d or h_lower.endswith(f".{d}") for d in brand["officialDomains"]):
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

    # 3. Check for specific wallet drainer keywords
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
        for kw in brand["keywords"]:
            escaped = re.escape(kw)
            regex = re.compile(rf"(^|[-_0-9]){escaped}([-_0-9]|$)", re.I)
            if regex.search(h_lower):
                return CryptoThreatMatch(
                    domain=h_lower,
                    target_brand=brand["displayName"],
                    threat_type="DAPP_CLONE",
                    risk_score=0.92,
                    description=f"Clone non ufficiale o phishing che imita {brand['displayName']}. Rischio furto fondi/chiavi."
                )

    return None
