import os
import tempfile
import pytest
from src.crypto_shield import (
    evaluate_crypto_financial_threat,
    load_custom_vault,
    reset_to_defaults,
    PROTECTED_CRYPTO_BRANDS,
    OFFICIAL_RPC_ENDPOINTS,
    DEFAULT_PROTECTED_CRYPTO_BRANDS
)

def test_default_crypto_shield_drainers_and_phishing():
    reset_to_defaults()
    # 1. Standard wallet drainer patterns
    d1 = evaluate_crypto_financial_threat("claim-airdrop-solana.xyz")
    assert d1 is not None
    assert d1.threat_type == "WALLET_DRAINER"

    d2 = evaluate_crypto_financial_threat("connect-wallet-portal.online")
    assert d2 is not None
    assert d2.threat_type == "WALLET_DRAINER"

    d3 = evaluate_crypto_financial_threat("ledger-live-update-v2.com")
    assert d3 is not None
    assert d3.threat_type == "WALLET_DRAINER"

    # Generalized RWA / Tokenized dividend pattern
    d4 = evaluate_crypto_financial_threat("rwa-yield-claim-portal.net")
    assert d4 is not None
    assert d4.threat_type == "WALLET_DRAINER"

    # 2. Public high-value dApp & exchange typosquatting / clones
    c1 = evaluate_crypto_financial_threat("app-uniswap-token.com")
    assert c1 is not None
    assert c1.target_brand == "Uniswap"
    assert c1.threat_type == "DAPP_CLONE"

    c2 = evaluate_crypto_financial_threat("login-metamask-web.org")
    assert c2 is not None
    assert c2.target_brand == "MetaMask"
    assert c2.threat_type == "DAPP_CLONE"

    # 3. Punycode IDN homograph attack (e.g. xn--uniswp-tta.org -> uniswáp.org & Cyrillic lookalikes)
    p1 = evaluate_crypto_financial_threat("xn--uniswp-tta.org")
    assert p1 is not None
    assert p1.target_brand == "Uniswap"
    assert p1.threat_type == "HOMOGRAPH_PUNYCODE"

    cyrillic_uniswap = "unisw\u0430p.org".encode("idna").decode("ascii")  # Cyrillic 'а'
    p2 = evaluate_crypto_financial_threat(cyrillic_uniswap)
    assert p2 is not None
    assert p2.target_brand == "Uniswap"
    assert p2.threat_type == "HOMOGRAPH_PUNYCODE"

def test_default_official_rpc_and_dapps_allowed():
    reset_to_defaults()
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
    assert evaluate_crypto_financial_threat("ledger.com") is None

def test_custom_vault_dynamic_loading():
    # Test that a custom vault configuration dynamically extends the shield without code edits
    custom_yaml = """
custom_brands:
  mock_protocol:
    displayName: "Mock Protocol"
    officialDomains:
      - "mock-protocol.org"
      - "app.mock-protocol.org"
    keywords:
      - "mock-protocol"
      - "mockprotocol"

custom_drainer_patterns:
  - pattern: "(^|[-_0-9\\\\.])(mock[-_]?drainer)([-_0-9\\\\.]|$)"
    threat_type: "WALLET_DRAINER"
    description: "Mock targeted drainer trap."

custom_rpc_endpoints:
  - "rpc.mock-protocol.org"

custom_whitelist:
  - "staging.mock-protocol.net"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(custom_yaml)
        temp_path = f.name

    try:
        success = load_custom_vault(temp_path, force_reload=True)
        assert success is True

        # Check official domain and subdomains are allowed
        assert evaluate_crypto_financial_threat("mock-protocol.org") is None
        assert evaluate_crypto_financial_threat("app.mock-protocol.org") is None

        # Check custom RPC and whitelist are allowed
        assert evaluate_crypto_financial_threat("rpc.mock-protocol.org") is None
        assert evaluate_crypto_financial_threat("staging.mock-protocol.net") is None

        # Check clone of custom brand is intercepted
        clone_threat = evaluate_crypto_financial_threat("mock-protocol-claim-token.xyz")
        assert clone_threat is not None
        assert clone_threat.target_brand == "Mock Protocol"
        assert clone_threat.threat_type == "DAPP_CLONE"

        # Check custom drainer pattern is caught
        drainer_threat = evaluate_crypto_financial_threat("safe-mock-drainer.cc")
        assert drainer_threat is not None
        assert drainer_threat.threat_type == "WALLET_DRAINER"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        reset_to_defaults()

def test_local_private_vault_loaded_if_present():
    # If the user has data/custom_vault.yaml present locally, it should be loaded
    local_vault = os.path.join(os.path.dirname(__file__), "..", "data", "custom_vault.yaml")
    if os.path.isfile(local_vault):
        loaded = load_custom_vault(local_vault, force_reload=True)
        assert loaded is True
        # Verify that loaded brands are active and protected
        assert len(PROTECTED_CRYPTO_BRANDS) > len(DEFAULT_PROTECTED_CRYPTO_BRANDS)
