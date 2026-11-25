import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "..");
const EXTENSION_DIR = path.join(ROOT_DIR, "extension");

// Helper to construct a realistic Chrome MV3 sandbox environment
function createChromeMock() {
  const sessionRules = [];
  const dynamicRules = [];
  const enabledRulesets = new Set(["sentinel_ruleset", "pricing_tracker_ruleset"]);
  const grantedPermissions = { cookies: false, origins: [] };
  const cookieStore = [
    { name: "_ga", value: "123", domain: ".example-shop.com", path: "/", secure: true, storeId: "0" },
    { name: "criteo_uid", value: "xyz", domain: "www.example-shop.com", path: "/", secure: false, storeId: "0" },
    { name: "other_site", value: "abc", domain: "other.org", path: "/", secure: true, storeId: "0" }
  ];
  const sessionStorage = {};
  const localStorage = {};
  const tabs = [{ id: 42, url: "https://0-24bpautomentes.hu/login" }];
  const listeners = {
    onInstalled: [],
    onStartup: [],
    onErrorOccurred: [],
    onBeforeNavigate: [],
    onMessage: [],
    onRemoved: []
  };

  const updatedTabs = [];

  const chromeMock = {
    runtime: {
      id: "sentinel-shield-mock-id",
      getURL: (relPath) => `file://${path.join(EXTENSION_DIR, relPath)}`,
      onInstalled: { addListener: (fn) => listeners.onInstalled.push(fn) },
      onStartup: { addListener: (fn) => listeners.onStartup.push(fn) },
      onMessage: { addListener: (fn) => listeners.onMessage.push(fn) },
      lastError: null
    },
    permissions: {
      contains: async ({ permissions = [], origins = [] }) => {
        const hasPerm = permissions.every(p => p === "cookies" && grantedPermissions.cookies);
        const hasOrig = origins.every(o => grantedPermissions.origins.includes(o));
        return hasPerm && hasOrig;
      }
    },
    cookies: {
      getAll: async ({ domain }) => {
        if (!domain) return [...cookieStore];
        return cookieStore.filter(c => {
          const clean = c.domain.replace(/^\./, "");
          return clean === domain || clean.endsWith("." + domain);
        });
      },
      remove: async ({ url, name }) => {
        const parsed = new URL(url);
        const idx = cookieStore.findIndex(c => c.name === name && c.domain.replace(/^\./, "") === parsed.hostname);
        if (idx >= 0) {
          const [removed] = cookieStore.splice(idx, 1);
          return removed;
        }
        return null;
      }
    },
    declarativeNetRequest: {
      getSessionRules: (cb) => {
        const rulesCopy = [...sessionRules];
        if (cb) cb(rulesCopy);
        return Promise.resolve(rulesCopy);
      },
      updateSessionRules: ({ addRules, removeRuleIds }, cb) => {
        if (removeRuleIds) {
          for (const id of removeRuleIds) {
            const idx = sessionRules.findIndex(r => r.id === id);
            if (idx >= 0) sessionRules.splice(idx, 1);
          }
        }
        if (addRules) {
          for (const r of addRules) {
            sessionRules.push(r);
          }
        }
        if (cb) cb();
      },
      getDynamicRules: async () => [...dynamicRules],
      updateDynamicRules: async ({ addRules = [], removeRuleIds = [] }) => {
        for (const id of removeRuleIds) {
          const idx = dynamicRules.findIndex(r => r.id === id);
          if (idx >= 0) dynamicRules.splice(idx, 1);
        }
        for (const r of addRules) {
          dynamicRules.push(r);
        }
      },
      getEnabledRulesets: async () => [...enabledRulesets],
      updateEnabledRulesets: async ({ enableRulesetIds = [], disableRulesetIds = [] }) => {
        for (const id of disableRulesetIds) enabledRulesets.delete(id);
        for (const id of enableRulesetIds) enabledRulesets.add(id);
      }
    },
    storage: {
      session: {
        get: (keys, cb) => {
          const res = {};
          for (const k of keys) {
            if (sessionStorage[k] !== undefined) res[k] = sessionStorage[k];
          }
          if (cb) cb(res);
          return Promise.resolve(res);
        },
        set: (obj, cb) => {
          Object.assign(sessionStorage, obj);
          if (cb) cb();
          return Promise.resolve();
        },
        remove: (key, cb) => {
          delete sessionStorage[key];
          if (cb) cb();
          return Promise.resolve();
        }
      },
      local: {
        get: (keys, cb) => {
          const res = {};
          for (const k of keys) {
            if (localStorage[k] !== undefined) res[k] = localStorage[k];
          }
          if (cb) cb(res);
          return Promise.resolve(res);
        },
        set: (obj, cb) => {
          Object.assign(localStorage, obj);
          if (cb) cb();
          return Promise.resolve();
        }
      }
    },
    action: {
      setBadgeText: () => {},
      setBadgeBackgroundColor: () => {}
    },
    tabs: {
      query: async (queryInfo) => {
        return tabs;
      },
      update: (tabId, updateProps, cb) => {
        updatedTabs.push({ tabId, updateProps });
        if (cb) cb();
      },
      reload: (tabId, cb) => {
        if (cb) cb();
      },
      onRemoved: { addListener: (fn) => listeners.onRemoved.push(fn) }
    },
    webNavigation: {
      onErrorOccurred: { addListener: (fn) => listeners.onErrorOccurred.push(fn) },
      onBeforeNavigate: { addListener: (fn) => listeners.onBeforeNavigate.push(fn) }
    }
  };

  // Node fetch polyfill that loads file:// URLs from the extension directory
  const fetchMock = async (urlStr) => {
    const filePath = urlStr.replace("file://", "");
    const content = await fs.readFile(filePath, "utf-8");
    return {
      ok: true,
      json: async () => JSON.parse(content)
    };
  };

  return {
    chromeMock,
    fetchMock,
    sessionRules,
    dynamicRules,
    enabledRulesets,
    grantedPermissions,
    cookieStore,
    sessionStorage,
    localStorage,
    listeners,
    updatedTabs
  };
}

// Loads and evaluates service_worker.js inside a VM context
async function loadServiceWorker() {
  const env = createChromeMock();
  const swCode = await fs.readFile(path.join(EXTENSION_DIR, "background", "service_worker.js"), "utf-8");

  const context = vm.createContext({
    chrome: env.chromeMock,
    fetch: env.fetchMock,
    console: console,
    Set: Set,
    Map: Map,
    URL: URL,
    Math: Math,
    RegExp: RegExp,
    Object: Object,
    JSON: JSON,
    encodeURIComponent: encodeURIComponent,
    Promise: Promise,
    String: String
  });

  vm.runInContext(swCode, context);

  // Trigger atomic data loading
  await vm.runInContext("ensureDataLoaded()", context);

  return { env, context };
}

test("Service Worker: Atomic initialization loads brands, PSL and DNR rules", async () => {
  const { context } = await loadServiceWorker();

  const brandsCount = vm.runInContext("Object.keys(BRANDS).length", context);
  const pslSize = vm.runInContext("PUBLIC_SUFFIXES.size", context);
  const blockedSize = vm.runInContext("BLOCKED_DOMAINS.size", context);

  assert.ok(brandsCount >= 30, `Expected at least 30 brands, got ${brandsCount}`);
  assert.equal(pslSize, 8707, `Expected exactly 8707 normalized PSL suffixes, got ${pslSize}`);
  assert.ok(blockedSize >= 400, `Expected at least 400 DNR blocked domains, got ${blockedSize}`);
});

test("Service Worker: getETLDPlusOne handles multi-part ccTLDs and cloud platforms", async () => {
  const { context } = await loadServiceWorker();

  const testCases = [
    { input: "login.service.gov.it", expected: "service.gov.it" },
    { input: "my-app.pages.dev", expected: "my-app.pages.dev" },
    { input: "portal.co.uk", expected: "portal.co.uk" },
    { input: "auth.bank.co.in", expected: "bank.co.in" },
    { input: "empresa.com.br", expected: "empresa.com.br" },
    { input: "shop.com.cn", expected: "shop.com.cn" },
    { input: "secure.org.il", expected: "secure.org.il" },
    { input: "news.co.za", expected: "news.co.za" },
    { input: "sub.domain.com", expected: "domain.com" },
    { input: "simple.org", expected: "simple.org" }
  ];

  for (const tc of testCases) {
    const result = vm.runInContext(`getETLDPlusOne("${tc.input}")`, context);
    assert.equal(result, tc.expected, `Failed for ${tc.input}: expected ${tc.expected}, got ${result}`);
  }
});

test("Service Worker: Brand impersonation heuristic accurately detects spoofing and avoids false positives", async () => {
  const { context } = await loadServiceWorker();

  // 1. Phishing / spoofing domains with boundary separation MUST be flagged
  const spoofedDomains = [
    "poste-servizio.com",
    "verifica-postepay.net",
    "amazon-login-verify.com",
    "paypa1.com",
    "intesasampaolo.com",
    "brt-tracking-pacco.org"
  ];
  for (const d of spoofedDomains) {
    const res = vm.runInContext(`checkBrandImpersonation("${d}")`, context);
    assert.equal(res.spoofed, true, `Expected ${d} to be flagged as spoofed`);
    assert.ok(res.brandName, `Missing brandName for ${d}`);
  }

  // 2. Benign official or dictionary words must NEVER be flagged (Defect #1 Fix: next.com, beer.com, ips.com)
  const benignDomains = [
    "next.com",
    "beer.com",
    "ips.com",
    "news.com",
    "uber.com",
    "open.com",
    "amazonaws.com",
    "s3.amazonaws.com",
    "impostore.it",
    "risposte.it",
    "postecert.it",
    "amazon.it",
    "poste.it",
    "bper.it",
    "spid.gov.it",
    "microsoft.com",
    "apple.com",
    "google.com"
  ];
  for (const d of benignDomains) {
    const res = vm.runInContext(`checkBrandImpersonation("${d}")`, context);
    assert.equal(res.spoofed, false, `Expected ${d} NOT to be flagged as spoofed`);
  }
});

test("Service Worker: Subdomain Phishing Defense detects rogue subdomains on unofficial domains", async () => {
  const { context } = await loadServiceWorker();

  // Subdomains on third-party domains MUST be flagged (Defect #2 Fix)
  const subdomainAttacks = [
    "poste.attacker-server.com",
    "postepay.free-hosting.net",
    "paypal.account-verification-service.org",
    "fineco.security-update.xyz",
    "login.microsoft.attacker.com",
    "appleid.portal-verify.com"
  ];

  for (const d of subdomainAttacks) {
    const res = vm.runInContext(`checkBrandImpersonation("${d}")`, context);
    assert.equal(res.spoofed, true, `Expected subdomain phish ${d} to be flagged`);
    assert.equal(res.vector, "subdomain");
  }

  // Subdomains on official domains MUST NOT be flagged
  const officialSubdomains = [
    "login.poste.it",
    "bancoposta.poste.it",
    "identity.microsoft.com",
    "accounts.google.com",
    "secure.bnl.it"
  ];
  for (const d of officialSubdomains) {
    const res = vm.runInContext(`checkBrandImpersonation("${d}")`, context);
    assert.equal(res.spoofed, false, `Expected official subdomain ${d} NOT to be flagged`);
  }
});

test("Service Worker: Compound words without hyphens detected with suspicious action affixes", async () => {
  const { context } = await loadServiceWorker();

  // Compound domain names without hyphen (Defect #3 Fix)
  const compoundAttacks = [
    "postelogin.com",
    "posteverifica.com",
    "serviziposte.com",
    "intesaprivati.com",
    "unicreditonline.com",
    "finecobanking.com",
    "netflixlogin.com"
  ];

  for (const d of compoundAttacks) {
    const res = vm.runInContext(`checkBrandImpersonation("${d}")`, context);
    assert.equal(res.spoofed, true, `Expected compound phish ${d} to be flagged`);
  }
});

test("Service Worker: IDN Homograph Punycode decoder catches lookalike domain attacks", async () => {
  const { context } = await loadServiceWorker();

  // Punycode attacks (Defect #4 Fix)
  // xn--pste-05a.it decodes to pöste.it -> normalizes to poste.it
  // xn--pypal-4ve.com decodes to pаypal.com (with Cyrillic а) -> normalizes to paypal.com
  const punycodeAttacks = [
    "xn--pste-05a.it",
    "xn--pypal-4ve.com"
  ];

  for (const d of punycodeAttacks) {
    const res = vm.runInContext(`checkBrandImpersonation("${d}")`, context);
    assert.equal(res.spoofed, true, `Expected punycode attack ${d} to be flagged`);
  }
});

test("Service Worker: onErrorOccurred disambiguates DNR blocks and prevents infinite loops", async () => {
  const { env, context } = await loadServiceWorker();
  const errorListener = env.listeners.onErrorOccurred[0];
  assert.ok(errorListener, "Missing onErrorOccurred listener");

  // Case A: Blocked by uBlock Origin (not in Sentinel Shield's BLOCKED_DOMAINS)
  await errorListener({
    frameId: 0,
    error: "net::ERR_BLOCKED_BY_CLIENT",
    url: "https://ad.doubleclick.net/ad.js",
    tabId: 101
  });
  assert.equal(env.updatedTabs.length, 0, "Sentinel Shield must NOT hijack blocks produced by uBlock Origin");

  // Case B: Blocked by Sentinel Shield (present in BLOCKED_DOMAINS)
  await errorListener({
    frameId: 0,
    error: "net::ERR_BLOCKED_BY_CLIENT",
    url: "http://0-24bpautomentes.hu/path",
    tabId: 102
  });
  assert.equal(env.updatedTabs.length, 1, "Sentinel Shield must redirect its own blocked domains to blocked.html");
  assert.equal(env.updatedTabs[0].tabId, 102);
  assert.ok(env.updatedTabs[0].updateProps.url.includes("pages/blocked.html?domain=0-24bpautomentes.hu"));

  // Case C: Domain already bypassed in session rules (Defect #5 Fix - Infinite Loop Prevention)
  env.sessionRules.push({
    id: 100001,
    priority: 2,
    action: { type: "allow" },
    condition: { urlFilter: "||0-24bpautomentes.hu^" }
  });
  env.updatedTabs.length = 0; // reset
  await errorListener({
    frameId: 0,
    error: "net::ERR_BLOCKED_BY_CLIENT",
    url: "http://0-24bpautomentes.hu/path",
    tabId: 102
  });
  assert.equal(env.updatedTabs.length, 0, "Must NOT redirect if domain was already bypassed in session rules");
});

test("Service Worker: bypassDomain registers monotonic collision-free session allow rule", async () => {
  const { env, context } = await loadServiceWorker();
  const messageListener = env.listeners.onMessage[0];
  assert.ok(messageListener, "Missing onMessage listener");

  // 1. First bypass request
  let reply1 = null;
  messageListener({ action: "bypassDomain", domain: "0-24bpautomentes.hu" }, {}, (r) => { reply1 = r; });
  await new Promise(resolve => setTimeout(resolve, 20));

  assert.equal(reply1?.success, true);
  assert.equal(reply1?.ruleId, 100001);
  assert.equal(env.sessionRules.length, 1);
  assert.equal(env.sessionRules[0].id, 100001);
  assert.equal(env.sessionRules[0].priority, 2);
  assert.equal(env.sessionRules[0].action.type, "allow");
  assert.equal(env.sessionRules[0].condition.urlFilter, "||0-24bpautomentes.hu^");

  // 2. Duplicate bypass for same domain (idempotent)
  let reply2 = null;
  messageListener({ action: "bypassDomain", domain: "0-24bpautomentes.hu" }, {}, (r) => { reply2 = r; });
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(reply2?.success, true);
  assert.equal(reply2?.alreadyAllowed, true);
  assert.equal(env.sessionRules.length, 1);

  // 3. Second bypass for a different domain (monotonic ID without collision)
  let reply3 = null;
  messageListener({ action: "bypassDomain", domain: "another-blocked-domain.com" }, {}, (r) => { reply3 = r; });
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(reply3?.success, true);
  assert.equal(reply3?.ruleId, 100002);
  assert.equal(env.sessionRules.length, 2);
  assert.equal(env.sessionRules[1].id, 100002);

  // 4. Tab-scoped bypass via sender.tab.id + automatic DNR cleanup on chrome.tabs.onRemoved
  let reply4 = null;
  messageListener({ action: "bypassDomain", domain: "scoped-tab.example" }, { tab: { id: 77 } }, (r) => { reply4 = r; });
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(reply4?.success, true);
  assert.equal(reply4?.tabScoped, true);
  assert.equal(JSON.stringify(env.sessionRules.find(r => r.id === reply4.ruleId)?.condition.tabIds), "[77]");

  const onRemovedListener = env.listeners.onRemoved[0];
  assert.ok(onRemovedListener, "Missing onRemoved listener");
  await onRemovedListener(77);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(env.sessionRules.some(r => r.id === reply4.ruleId), false);
});

test("Popup: extracts activeHostname from standard tab and from blocked.html warning URL", async () => {
  function extractHostname(tabUrl) {
    if (!tabUrl) return "";
    try {
      const parsedUrl = new URL(tabUrl);
      if (parsedUrl.protocol === "chrome-extension:" && parsedUrl.searchParams.has("domain")) {
        return parsedUrl.searchParams.get("domain");
      }
      return parsedUrl.hostname;
    } catch (e) {
      return "";
    }
  }

  // 1. Standard web browsing tab
  assert.equal(extractHostname("https://example.com/test"), "example.com");

  // 2. Warning blocked page tab
  assert.equal(
    extractHostname("chrome-extension://fignfifoniblkonapihmkfakmlgkbkcf/pages/blocked.html?domain=phish-test.bank.com"),
    "phish-test.bank.com"
  );

  // 3. System chrome URL
  assert.equal(extractHostname("chrome://extensions"), "extensions");
});

test("Service Worker: Crypto drainer patterns, expanded Web3 brands and NFKD diacritics", async () => {
  const { context } = await loadServiceWorker();

  const drainerDomains = [
    "claim-airdrop-eth.xyz",
    "connect-wallet-sync.org",
    "rwa-yield-claim.io",
    "seed-phrase-backup.net"
  ];
  for (const d of drainerDomains) {
    const res = vm.runInContext(`checkBrandImpersonation("${d}")`, context);
    assert.equal(res.spoofed, true, `Expected drainer ${d} to be flagged`);
    assert.equal(res.vector, "drainer");
  }

  // Ledger firmware/update spoof still gets caught (with officialDomains hint)
  const ledgerSpoof = vm.runInContext(`checkBrandImpersonation("ledger-live-update.io")`, context);
  assert.equal(ledgerSpoof.spoofed, true);
  assert.equal(ledgerSpoof.brandName, "Ledger");

  // NFKD diacritic & expanded Web3 brand checks
  const spoofed = ["pàypal-sicuro.com", "uniswap-airdrop.net", "phantom-wallet-verify.org"];
  for (const d of spoofed) {
    const res = vm.runInContext(`checkBrandImpersonation("${d}")`, context);
    assert.equal(res.spoofed, true, `Expected ${d} to be flagged`);
  }

  const officialWeb3 = ["uniswap.org", "app.uniswap.org", "phantom.app", "rabby.io", "aave.com", "lido.fi", "opensea.io", "coinbase.com", "kraken.com"];
  for (const d of officialWeb3) {
    const res = vm.runInContext(`checkBrandImpersonation("${d}")`, context);
    assert.equal(res.spoofed, false, `Expected official domain ${d} NOT to be flagged`);
  }
});

test("Service Worker: Anti-Dynamic Pricing toggle, Opt-In Cookie Guard DNR rules, and site cookie cleanup", async () => {
  const { env } = await loadServiceWorker();
  const messageListener = env.listeners.onMessage[0];
  const sendMsg = (msg) => new Promise(resolve => messageListener(msg, {}, resolve));

  // 1. Toggle Anti-Dynamic Pricing ruleset OFF then ON
  const pOff = await sendMsg({ action: "setPricingShield", enabled: false });
  assert.equal(pOff.success, true);
  assert.equal(env.enabledRulesets.has("pricing_tracker_ruleset"), false);
  assert.equal(env.enabledRulesets.has("sentinel_ruleset"), true);

  const pOn = await sendMsg({ action: "setPricingShield", enabled: true });
  assert.equal(pOn.success, true);
  assert.equal(env.enabledRulesets.has("pricing_tracker_ruleset"), true);

  // 2. Cookie Guard cannot be enabled without optional host & cookies permissions
  const denied = await sendMsg({ action: "setCookieGuard", enabled: true });
  assert.equal(denied.success, false);
  assert.equal(env.dynamicRules.length, 0);

  // 3. Grant permissions and enable Cookie & Tracking Param Guard
  env.grantedPermissions.cookies = true;
  env.grantedPermissions.origins = ["<all_urls>"];
  const enabled = await sendMsg({ action: "setCookieGuard", enabled: true });
  assert.equal(enabled.success, true);
  assert.equal(enabled.cookieGuardEnabled, true);

  const cookieRule = env.dynamicRules.find(r => r.id === 200001);
  const paramRule = env.dynamicRules.find(r => r.id === 200002);
  assert.ok(cookieRule, "Expected 3rd-party Cookie modifyHeaders dynamic rule");
  assert.equal(cookieRule.action.type, "modifyHeaders");
  assert.equal(cookieRule.condition.domainType, "thirdParty");
  assert.ok(cookieRule.condition.excludedRequestDomains.includes("stripe.com"));
  assert.ok(paramRule, "Expected tracking query param redirect dynamic rule");
  assert.ok(paramRule.action.redirect.transform.queryTransform.removeParams.includes("fbclid"));

  // 4. Per-site privacy exception adds priority 3 allow rule and excludes site from Cookie Guard
  const ex = await sendMsg({ action: "toggleSitePrivacyException", domain: "shop.example-shop.com" });
  assert.equal(ex.success, true);
  assert.equal(ex.sitePrivacyExempt, true);
  assert.equal(ex.etld1, "example-shop.com");
  const allowRule = env.dynamicRules.find(r => r.id >= 300000);
  assert.ok(allowRule, "Expected per-site allow rule");
  assert.equal(allowRule.priority, 3);
  assert.deepEqual([...allowRule.condition.initiatorDomains], ["example-shop.com"]);

  const updatedCookieRule = env.dynamicRules.find(r => r.id === 200001);
  assert.deepEqual([...updatedCookieRule.condition.excludedInitiatorDomains], ["example-shop.com"]);

  // 5. Site cookie count & 1-click cleanup scoped to eTLD+1
  const countBefore = await sendMsg({ action: "getSiteCookiesCount", domain: "www.example-shop.com" });
  assert.equal(countBefore.count, 2);
  const cleaned = await sendMsg({ action: "cleanSiteCookies", domain: "www.example-shop.com" });
  assert.equal(cleaned.success, true);
  assert.equal(cleaned.removed, 2);
  assert.equal(env.cookieStore.length, 1, "Cookies belonging to other.org must remain intact");

  // 6. Disabling Cookie Guard removes rules 200001 and 200002 cleanly
  const disabled = await sendMsg({ action: "setCookieGuard", enabled: false });
  assert.equal(disabled.success, true);
  assert.equal(env.dynamicRules.some(r => r.id === 200001 || r.id === 200002), false);
});

test("Service Worker: bare-IP C2 list triggers blocked.html redirect and popup warning without blocking benign hosts", async () => {
  const { env, swCode, loadIntoContext } = await (async () => {
    const base = createChromeMock();
    const origFetch = base.fetchMock;
    base.fetchMock = async (urlStr) => {
      if (urlStr.endsWith("data/blocked_ips.json")) {
        return {
          ok: true,
          json: async () => ["198.51.100.77", "2001:db8:bad::1"]
        };
      }
      return origFetch(urlStr);
    };
    const code = await fs.readFile(path.join(EXTENSION_DIR, "background/service_worker.js"), "utf-8");
    const sandbox = {
      chrome: base.chromeMock,
      fetch: base.fetchMock,
      URL,
      URLSearchParams,
      Set,
      Map,
      RegExp,
      console: { log: () => {}, warn: () => {}, error: () => {} }
    };
    const context = vm.createContext(sandbox);
    vm.runInContext(code, context);
    return { env: base, swCode: code, loadIntoContext: context };
  })();

  await env.listeners.onErrorOccurred[0]({
    frameId: 0,
    tabId: 71,
    error: "net::ERR_BLOCKED_BY_CLIENT",
    url: "http://198.51.100.77/gate.php"
  });
  assert.equal(env.updatedTabs.length, 1);
  assert.ok(env.updatedTabs[0].updateProps.url.includes("blocked.html?domain=198.51.100.77"));

  // Check bracketed IPv6 support via getTabWarning
  const tabWarning = await new Promise((resolve) => {
    env.listeners.onMessage[0]({ action: "getTabWarning", tabId: 71, domain: "[2001:db8:bad::1]" }, {}, resolve);
  });
  assert.equal(tabWarning.isBlocked, true);

  const safeCheck = await new Promise((resolve) => {
    env.listeners.onMessage[0]({ action: "getTabWarning", tabId: 72, domain: "1.1.1.1" }, {}, resolve);
  });
  assert.equal(safeCheck.isBlocked, false);
});
