import pytest
from src.crypto_shield import evaluate_crypto_financial_threat

def test_crypto_shield_drainers_and_phishing():
    # 1. Wallet drainer patterns
    d1 = evaluate_crypto_financial_threat("claim-airdrop-solana.xyz")
    assert d1 is not None
    assert d1.threat_type == "WALLET_DRAINER"

    d2 = evaluate_crypto_financial_threat("connect-wallet-portal.online")
    assert d2 is not None
    assert d2.threat_type == "WALLET_DRAINER"

    d3 = evaluate_crypto_financial_threat("ledger-live-update-v2.com")
    assert d3 is not None
    assert d3.threat_type == "WALLET_DRAINER"

    # 2. High-value dApp / exchange typosquatting & clones
    c1 = evaluate_crypto_financial_threat("app-uniswap-token.com")
    assert c1 is not None
    assert c1.target_brand == "Uniswap"
    assert c1.threat_type == "DAPP_CLONE"

    c2 = evaluate_crypto_financial_threat("login-metamask-web.org")
    assert c2 is not None
    assert c2.target_brand == "MetaMask"
    assert c2.threat_type == "DAPP_CLONE"

    c3 = evaluate_crypto_financial_threat("revolut-security-auth.net")
    assert c3 is not None
    assert c3.target_brand == "Revolut"

    # 3. Punycode IDN homograph attack (e.g. xn--uniswp-tta.org -> uniswáp.org)
    p1 = evaluate_crypto_financial_threat("xn--uniswp-tta.org")
    assert p1 is not None
    assert p1.target_brand == "Uniswap"
    assert p1.threat_type == "HOMOGRAPH_PUNYCODE"

def test_crypto_shield_official_rpc_and_dapps_allowed():
    # Official RPC nodes must NEVER be blocked
    assert evaluate_crypto_financial_threat("mainnet.infura.io") is None
    assert evaluate_crypto_financial_threat("eth.llamarpc.com") is None
    assert evaluate_crypto_financial_threat("rpc.ankr.com") is None
    assert evaluate_crypto_financial_threat("cloudflare-eth.com") is None
    assert evaluate_crypto_financial_threat("polygon-rpc.com") is None

    # Official dApps and exchanges must be allowed
    assert evaluate_crypto_financial_threat("app.uniswap.org") is None
    assert evaluate_crypto_financial_threat("metamask.io") is None
    assert evaluate_crypto_financial_threat("binance.com") is None
    assert evaluate_crypto_financial_threat("revolut.com") is None
    assert evaluate_crypto_financial_threat("ledger.com") is None
