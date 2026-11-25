"""
End-to-End Practical Browser Test Suite for Sentinel Shield Manifest V3 Extension
Runs against real Chrome for Testing engine using DevTools Protocol (CDP) & Selenium.
Validates:
1. MV3 Service Worker lifecycle & zero-deadlock startup
2. DeclarativeNetRequest static ruleset activation (500 threat rules)
3. 100% Local Brand Impersonation heuristic (Punycode, Subdomains, Compound keywords)
4. Anti-False Positive immunity (next.com, iper.it, beer.com, la-poste.fr, spin.com)
5. Session Bypass monotonic allow rules & UI rendering (blocked.html, popup.html)
"""

import asyncio
import json
import os
import subprocess
import tempfile
import time
import urllib.request
import pytest
import websockets
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

CHROME_BIN = "/home/umbette/.local/share/chrome-linux64/chrome"
EXTENSION_DIR = Path(__file__).resolve().parent.parent / "extension"


@pytest.fixture(scope="module")
def chrome_env():
    """
    Spawns a clean Chrome for Testing instance with Sentinel Shield MV3 extension.
    Yields (driver, ext_id, ws_url, port).
    """
    assert Path(CHROME_BIN).exists(), f"Chrome for Testing binary missing at {CHROME_BIN}"
    assert EXTENSION_DIR.exists(), f"Extension dir missing at {EXTENSION_DIR}"

    user_data = tempfile.mkdtemp(prefix="sentinel_cft_test_")
    port = 9977

    cmd = [
        CHROME_BIN,
        "--headless=new",
        f"--user-data-dir={user_data}",
        f"--load-extension={EXTENSION_DIR}",
        f"--remote-debugging-port={port}",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "about:blank"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.8)

    # Poll targets from CDP HTTP endpoint
    targets = []
    for _ in range(10):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json") as resp:
                targets = json.loads(resp.read().decode())
                if any("background/service_worker.js" in t.get("url", "") for t in targets):
                    break
        except Exception:
            time.sleep(0.3)

    sw_targets = [t for t in targets if "background/service_worker.js" in t.get("url", "")]
    assert len(sw_targets) > 0, f"Sentinel Shield MV3 Service Worker was not discovered. Targets: {targets}"

    sw_target = sw_targets[0]
    ext_id = sw_target["url"].split("://")[1].split("/")[0]
    ws_url = sw_target["webSocketDebuggerUrl"]

    # Attach Selenium WebDriver for UI tests
    options = Options()
    options.binary_location = CHROME_BIN
    options.add_experimental_option("debuggerAddress", f"127.0.0.1:{port}")
    driver = webdriver.Chrome(options=options)

    yield driver, ext_id, ws_url, port

    try:
        driver.quit()
    except Exception:
        pass
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()


async def sw_eval(ws_url: str, expression: str):
    """Evaluates JavaScript inside the real Chrome Service Worker V8 isolate."""
    async with websockets.connect(ws_url) as ws:
        req_id = int(time.time() * 1000) % 100000
        req = {
            "id": req_id,
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "awaitPromise": True,
                "returnByValue": True
            }
        }
        await ws.send(json.dumps(req))
        while True:
            raw = await ws.recv()
            data = json.loads(raw)
            if data.get("id") == req_id:
                if "exceptionDetails" in data.get("result", {}):
                    exc = data["result"]["exceptionDetails"]
                    raise RuntimeError(f"SW Eval Exception: {exc.get('text')} - {exc.get('exception', {}).get('description')}")
                return data["result"]["result"].get("value")


def test_service_worker_loaded_and_initialized(chrome_env):
    """Verifies that Chrome loads Sentinel Shield and Service Worker successfully initializes state."""
    _, ext_id, ws_url, _ = chrome_env
    assert len(ext_id) == 32

    # Check DNR API availability
    res_dnr_type = asyncio.run(sw_eval(ws_url, "typeof chrome.declarativeNetRequest"))
    assert res_dnr_type == "object"

    # Verify enabled rulesets (Phishing/IoC + Anti-Dynamic Pricing & Tracker shield)
    rulesets = asyncio.run(sw_eval(ws_url, "new Promise(r => chrome.declarativeNetRequest.getEnabledRulesets(r))"))
    assert "sentinel_ruleset" in rulesets
    assert "pricing_tracker_ruleset" in rulesets

    # Verify Zero-Permission default manifest + opt-in Cookie Guard declarations
    manifest = asyncio.run(sw_eval(ws_url, "chrome.runtime.getManifest()"))
    assert manifest["name"] == "Sentinel Shield"
    assert manifest["host_permissions"] == []
    assert "cookies" in manifest["optional_permissions"]
    assert "<all_urls>" in manifest["optional_host_permissions"]

    # Verify atomic loaded data
    data_counts = asyncio.run(sw_eval(ws_url, "ensureDataLoaded().then(() => ({ brands: Object.keys(BRANDS).length, psl: PUBLIC_SUFFIXES.size, blocked: BLOCKED_DOMAINS.size }))"))
    assert data_counts["brands"] >= 30, f"Expected >= 30 brands, got {data_counts['brands']}"
    assert data_counts["psl"] == 8707, f"Expected 8707 PSL entries, got {data_counts['psl']}"
    assert data_counts["blocked"] >= 400, f"Expected >= 400 blocked domains, got {data_counts['blocked']}"


def test_brand_impersonation_heuristics_in_browser(chrome_env):
    """Verifies that the brand impersonation engine detects real attack vectors in the browser."""
    _, _, ws_url, _ = chrome_env

    # 1. Standard lookalike and boundary spoofing
    res1 = asyncio.run(sw_eval(ws_url, 'checkBrandImpersonation("poste-servizio.com")'))
    assert res1["spoofed"] is True
    assert "Poste" in res1["brandName"]

    res2 = asyncio.run(sw_eval(ws_url, 'checkBrandImpersonation("paypa1.com")'))
    assert res2["spoofed"] is True
    assert "PayPal" in res2["brandName"]

    # 2. Subdomain phishing vector
    res3 = asyncio.run(sw_eval(ws_url, 'checkBrandImpersonation("poste.attacker-server.com")'))
    assert res3["spoofed"] is True
    assert res3["vector"] == "subdomain"

    # 3. Compound words without hyphens
    res4 = asyncio.run(sw_eval(ws_url, 'checkBrandImpersonation("postelogin.com")'))
    assert res4["spoofed"] is True

    res5 = asyncio.run(sw_eval(ws_url, 'checkBrandImpersonation("serviziposte.com")'))
    assert res5["spoofed"] is True

    # 4. IDN / Punycode homograph attack & NFKD diacritics
    res6 = asyncio.run(sw_eval(ws_url, 'checkBrandImpersonation("xn--pypal-4ve.com")'))
    assert res6["spoofed"] is True

    res7 = asyncio.run(sw_eval(ws_url, 'checkBrandImpersonation("pàypal-sicuro.com")'))
    assert res7["spoofed"] is True

    # 5. Web3 Wallet Drainer signatures
    res8 = asyncio.run(sw_eval(ws_url, 'checkBrandImpersonation("claim-airdrop-eth.xyz")'))
    assert res8["spoofed"] is True
    assert res8["vector"] == "drainer"


def test_false_positive_immunity_in_browser(chrome_env):
    """Verifies that the Skeptical Architect fixes guarantee zero false alarms on legitimate brands."""
    _, _, ws_url, _ = chrome_env

    benign_test_cases = [
        "next.com",          # British retailer (FTSE 100) must NOT flag as Nexi
        "iper.it",           # Italian supermarket must NOT flag as BPER
        "beer.com",          # Common word must NOT flag as BPER
        "skip.com",          # Common word must NOT flag as SPID
        "spin.com",          # Common word must NOT flag as SPID
        "ips.com",           # Common acronym must NOT flag as INPS
        "la-poste.fr",       # Sovereign French post must NOT flag as Poste Italiane
        "poste.it",          # Authentic official domain
        "bper.it",           # Authentic official domain
        "google.com",        # Authentic official domain
        "microsoft.com",     # Authentic official domain
        "s3.amazonaws.com"   # Cloud infrastructure
    ]

    for d in benign_test_cases:
        res = asyncio.run(sw_eval(ws_url, f'checkBrandImpersonation("{d}")'))
        assert res["spoofed"] is False, f"False Positive detected on benign domain: {d}"


def test_session_bypass_allow_rules_in_browser(chrome_env):
    """Verifies that bypassDomain adds monotonic priority 2 allow rules in Chrome declarativeNetRequest."""
    _, _, ws_url, _ = chrome_env

    # Add bypass for a test domain
    res1 = asyncio.run(sw_eval(ws_url, """
    new Promise(resolve => {
        chrome.runtime.onMessage.dispatch(
            { action: "bypassDomain", domain: "0-24bpautomentes.hu", tabId: 101 },
            { id: chrome.runtime.id },
            resolve
        );
    })
    """))
    assert res1["success"] is True
    assert res1["ruleId"] >= 100001

    # Verify rule is registered in browser engine
    rules = asyncio.run(sw_eval(ws_url, "new Promise(r => chrome.declarativeNetRequest.getSessionRules(r))"))
    allow_rule = next((r for r in rules if r["id"] == res1["ruleId"]), None)
    assert allow_rule is not None
    assert allow_rule["priority"] == 2
    assert allow_rule["action"]["type"] == "allow"
    assert allow_rule["condition"]["urlFilter"] == "||0-24bpautomentes.hu^"
    assert allow_rule["condition"]["tabIds"] == [101]


def test_blocked_page_ui_rendering(chrome_env):
    """Verifies that pages/blocked.html renders cleanly without modal dialogs or errors."""
    driver, ext_id, _, _ = chrome_env
    test_domain = "threat-phishing.test"
    blocked_url = f"chrome-extension://{ext_id}/pages/blocked.html?domain={test_domain}"

    driver.get(blocked_url)
    WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "domainDisplay")))

    domain_text = driver.find_element(By.ID, "domainDisplay").text
    assert domain_text == test_domain

    btn_back = driver.find_element(By.ID, "btnBack")
    btn_proceed = driver.find_element(By.ID, "btnProceed")
    assert btn_back.is_displayed()
    assert btn_proceed.is_displayed()


def test_popup_ui_rendering(chrome_env):
    """Verifies that popup.html renders properly and suppresses bypass button on safe domains."""
    driver, ext_id, _, _ = chrome_env
    popup_url = f"chrome-extension://{ext_id}/popup/popup.html"

    driver.get(popup_url)
    WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "statusTitle")))

    title = driver.find_element(By.ID, "statusTitle").text
    desc = driver.find_element(By.ID, "statusDesc").text
    btn_bypass = driver.find_element(By.ID, "btnBypassDnr")

    assert "Nessun Avviso" in title
    assert len(desc) > 0
    # On a safe domain (or about:blank), the bypass button must remain hidden (Anti-YAGNI fix)
    assert not btn_bypass.is_displayed()

    # Verify Sentinel Shield brand identity & privacy/cookie shield toggles in popup
    assert "Sentinel Shield" in driver.find_element(By.TAG_NAME, "h2").text
    toggle_pricing = driver.find_element(By.ID, "togglePricingShield")
    toggle_cookie = driver.find_element(By.ID, "toggleCookieGuard")
    assert toggle_pricing.is_selected()
    assert not toggle_cookie.is_selected()
    assert driver.find_element(By.ID, "pricingTag").text == "ATTIVO"
    assert driver.find_element(By.ID, "cookieTag").text == "OPT-IN"


def test_pricing_shield_and_site_exception_dnr_in_browser(chrome_env):
    """Verifies Chrome accepts pricing_tracker_ruleset toggles and dynamic per-site allow rules."""
    _, _, ws_url, _ = chrome_env

    # 1. Toggle Anti-Dynamic Pricing ruleset OFF then back ON in real Chrome
    off_res = asyncio.run(sw_eval(ws_url, """
    new Promise(resolve => {
        chrome.runtime.onMessage.dispatch(
            { action: "setPricingShield", enabled: false },
            { id: chrome.runtime.id },
            resolve
        );
    })
    """))
    assert off_res["success"] is True
    assert off_res["pricingShieldEnabled"] is False

    enabled_off = asyncio.run(sw_eval(ws_url, "new Promise(r => chrome.declarativeNetRequest.getEnabledRulesets(r))"))
    assert "sentinel_ruleset" in enabled_off
    assert "pricing_tracker_ruleset" not in enabled_off

    on_res = asyncio.run(sw_eval(ws_url, """
    new Promise(resolve => {
        chrome.runtime.onMessage.dispatch(
            { action: "setPricingShield", enabled: true },
            { id: chrome.runtime.id },
            resolve
        );
    })
    """))
    assert on_res["success"] is True
    assert on_res["pricingShieldEnabled"] is True

    enabled_on = asyncio.run(sw_eval(ws_url, "new Promise(r => chrome.declarativeNetRequest.getEnabledRulesets(r))"))
    assert "pricing_tracker_ruleset" in enabled_on

    # 2. Register and clear per-site privacy allow rule in real Chrome dynamic DNR
    ex_on = asyncio.run(sw_eval(ws_url, """
    new Promise(resolve => {
        chrome.runtime.onMessage.dispatch(
            { action: "toggleSitePrivacyException", domain: "shop.example.it" },
            { id: chrome.runtime.id },
            resolve
        );
    })
    """))
    assert ex_on["success"] is True
    assert ex_on["sitePrivacyExempt"] is True
    assert ex_on["etld1"] == "example.it"

    dyn_rules = asyncio.run(sw_eval(ws_url, "chrome.declarativeNetRequest.getDynamicRules()"))
    assert any(r["priority"] == 3 and r["condition"]["initiatorDomains"] == ["example.it"] for r in dyn_rules)

    ex_off = asyncio.run(sw_eval(ws_url, """
    new Promise(resolve => {
        chrome.runtime.onMessage.dispatch(
            { action: "toggleSitePrivacyException", domain: "shop.example.it" },
            { id: chrome.runtime.id },
            resolve
        );
    })
    """))
    assert ex_off["success"] is True
    assert ex_off["sitePrivacyExempt"] is False
