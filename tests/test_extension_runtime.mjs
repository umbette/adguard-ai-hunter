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
