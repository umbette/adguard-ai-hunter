/**
 * Sentinel Shield - Manifest V3 Background Service Worker
 * 100% Local Heuristic Inspection, Brand Impersonation Guard,
 * Anti-Dynamic Pricing DNR & Opt-In Cookie/Tracking Param Shield
 */

let BRANDS = {};
let PUBLIC_SUFFIXES = new Set();
let BLOCKED_DOMAINS = new Set();
let BLOCKED_IPS = new Set();
let loadDataPromise = null;
let memorySessionRuleId = 100000;

const PRICING_RULESET_ID = "pricing_tracker_ruleset";
const COOKIE_HEADER_RULE_ID = 200001;
const TRACKING_PARAM_RULE_ID = 200002;
const SITE_ALLOW_RULE_BASE_ID = 300000;

const THIRD_PARTY_SUBRESOURCE_TYPES = [
  "sub_frame", "stylesheet", "script", "image", "font", "object",
  "xmlhttprequest", "ping", "csp_report", "media", "websocket",
  "webtransport", "webbundle", "other"
];

// Essential payment, 2FA, captcha and SSO endpoints excluded from 3rd-party cookie stripping
const ESSENTIAL_AUTH_PAYMENT_DOMAINS = [
  "stripe.com", "paypal.com", "nexi.it", "satispay.com", "sumup.com",
  "adyen.com", "braintreegateway.com", "accounts.google.com",
  "appleid.apple.com", "login.microsoftonline.com", "login.live.com",
  "auth0.com", "okta.com", "challenges.cloudflare.com", "hcaptcha.com",
  "recaptcha.net", "walletconnect.com", "walletconnect.org"
];

// Cross-site tracking query parameters stripped when Cookie & Param Guard is active
const TRACKING_QUERY_PARAMS = [
  "fbclid", "gclid", "dclid", "gbraid", "wbraid", "msclkid", "yclid",
  "mc_cid", "mc_eid", "igshid", "_hsenc", "_hsmi",
  "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
  "vero_id", "oly_enc_id", "oly_anon_id", "__s"
];

// Synchronized with SSOT spec/drainer_patterns.json (loaded dynamically in ensureDataLoaded)
let DRAINER_PATTERNS = [
  {
    pattern: /(^|[-_0-9.])(claim[-_]?airdrop|airdrop[-_]?claim)([-_0-9.]|$)/i,
    label: "claim-airdrop",
    description: "Finto airdrop Web3 progettato per autorizzare lo svuotamento del wallet."
  },
  {
    pattern: /(^|[-_0-9.])(connect[-_]?wallet|sync[-_]?wallet|rectify[-_]?wallet)([-_0-9.]|$)/i,
    label: "connect-wallet",
    description: "Phishing kit di falsa connessione o sincronizzazione wallet."
  },
  {
    pattern: /(^|[-_0-9.])(claim[-_]?reward|token[-_]?reward|presale[-_]?token)([-_0-9.]|$)/i,
    label: "claim-reward",
    description: "Esca per minting o presale malevola."
  },
  {
    pattern: /(^|[-_0-9.])(ledger[-_]?live[-_]?update|trezor[-_]?firmware|hardware[-_]?wallet[-_]?backup|seed[-_]?phrase[-_]?backup)([-_0-9.]|$)/i,
    label: "wallet-backup",
    description: "Falso aggiornamento firmware o backup per estorsione di seed phrase."
  },
  {
    pattern: /(^|[-_0-9.])(rwa[-_]?yield|property[-_]?token|asset[-_]?token|token[-_]?dividend)([-_0-9.]|$)/i,
    label: "rwa-yield",
    description: "Phishing mirato per finto claim di dividendi o token RWA."
  }
];

// Verified benign domains that share dictionary words or international brands/services
const BENIGN_DOMAINS = new Set([
  "next.com", "next.co.uk", "iper.it", "beer.com", "skip.com", "spin.com",
  "la-poste.fr", "laposte.net", "poste.ch", "deutschepost.de", "gls-bank.de",
  "spedisci-subito.it", "ips.com", "news.com", "tips.com", "open.com",
  "uber.com", "maps.com", "trip.com", "free.com", "home.com", "care.com",
  "best.com", "fast.com", "post.com", "mail.com", "bank.com", "shop.com",
  "live.com", "play.com", "word.com", "work.com", "food.com", "auto.com"
]);

// Cyrillic / Greek confusable homoglyphs mapped to ASCII equivalents
const HOMOGLYPH_MAP = {
  "\u0430": "a", // Cyrillic small letter a
  "\u0441": "c", // Cyrillic small letter es
  "\u0435": "e", // Cyrillic small letter ie
  "\u043E": "o", // Cyrillic small letter o
  "\u0440": "p", // Cyrillic small letter er
  "\u0445": "x", // Cyrillic small letter ha
  "\u0443": "y", // Cyrillic small letter u
  "\u0456": "i", // Cyrillic small letter byelorussian-ukrainian i
  "\u0455": "s", // Cyrillic small letter dze
  "\u0458": "j", // Cyrillic small letter je
  "\u03BF": "o", // Greek small letter omicron
  "\u03C1": "p", // Greek small letter rho
  "ö": "o", "ӧ": "o", "é": "e", "è": "e", "à": "a", "á": "a",
  "í": "i", "ì": "i", "ó": "o", "ò": "o", "ú": "u", "ù": "u",
  "1": "l", "0": "o"
};

// Common phishing intent tokens that accompany brand spoofing in compound domains
const PHISHING_INTENT_TOKENS = [
  "login", "accedi", "auth", "verify", "verifica", "secure", "sicurezza",
  "assistenza", "servizio", "servizi", "conto", "online", "portal", "update",
  "banking", "privati", "clienti", "support", "help", "pay"
];

// RFC 3492 Punycode label decoder
function decodePunycodeLabel(label) {
  if (!label || !label.toLowerCase().startsWith("xn--")) return label;
  try {
    const input = label.slice(4).toLowerCase();
    const output = [];
    const basic = input.lastIndexOf("-");
    let b = 0;
    if (basic > 0) {
      for (let i = 0; i < basic; i++) {
        output.push(input.charCodeAt(i));
      }
      b = basic + 1;
    }
    let n = 128, i = 0, bias = 72;
    let pos = b;
    while (pos < input.length) {
      const oldi = i;
      let w = 1, k = 36;
      while (true) {
        if (pos >= input.length) break;
        const c = input.charCodeAt(pos++);
        const digit = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : 36;
        i += digit * w;
        const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
        if (digit < t) break;
        w *= 36 - t;
        k += 36;
      }
      const outLen = output.length + 1;
      bias = adaptPunycode(i - oldi, outLen, oldi === 0);
      n += Math.floor(i / outLen);
      i %= outLen;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  } catch (e) {
    return label;
  }
}

function adaptPunycode(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / 700) : Math.floor(delta / 2);
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((36 - 1) * 26) / 2) {
    delta = Math.floor(delta / (36 - 1));
    k += 36;
  }
  return Math.floor(k + (36 * delta) / (delta + 38));
}

// Strip Latin combining diacritics via NFKD normalization
function stripDiacritics(str) {
  if (!str) return "";
  return typeof str.normalize === "function"
    ? str.normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    : str;
}

// Fold homoglyphs to ASCII for resilient comparison
function foldHomoglyphs(str) {
  if (!str) return "";
  let out = "";
  for (const ch of str) {
    out += HOMOGLYPH_MAP[ch] || ch;
  }
  return out;
}

// Normalize domain label (punycode decode + NFKD diacritics strip + homoglyph folding)
function normalizeDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.toLowerCase().split(".");
  const normalizedParts = parts.map(p => foldHomoglyphs(stripDiacritics(decodePunycodeLabel(p))));
  return normalizedParts.join(".");
}

// Atomically load local brand database, public suffix list, and compact DNR blocked domains
function ensureDataLoaded() {
  if (!loadDataPromise) {
    loadDataPromise = (async () => {
      try {
        const brandsUrl = chrome.runtime.getURL("data/brands.json");
        const brandsResp = await fetch(brandsUrl);
        BRANDS = await brandsResp.json();

        const suffixesUrl = chrome.runtime.getURL("data/public_suffixes.json");
        const suffixesResp = await fetch(suffixesUrl);
        const suffixesArr = await suffixesResp.json();
        PUBLIC_SUFFIXES = new Set(suffixesArr);

        try {
          const drainersUrl = chrome.runtime.getURL("data/drainer_patterns.json");
          const drainersResp = await fetch(drainersUrl);
          const drainersArr = await drainersResp.json();
          if (Array.isArray(drainersArr) && drainersArr.length > 0) {
            DRAINER_PATTERNS = drainersArr.map(d => ({
              pattern: new RegExp(d.pattern, "i"),
              label: d.label,
              description: d.description
            }));
          }
        } catch (e) {
          // Retain fallback inline DRAINER_PATTERNS if bundled file is absent
        }

        // Load compact blocked domains array for sub-millisecond, low-memory inspection
        try {
          const blockedUrl = chrome.runtime.getURL("data/blocked_domains.json");
          const blockedResp = await fetch(blockedUrl);
          const blockedArr = await blockedResp.json();
          BLOCKED_DOMAINS = new Set(blockedArr.map(d => d.toLowerCase()));
        } catch (e) {
          // Fallback to ruleset.json if blocked_domains.json is absent
          const rulesUrl = chrome.runtime.getURL("rules/ruleset.json");
          const rulesResp = await fetch(rulesUrl);
          const rules = await rulesResp.json();
          BLOCKED_DOMAINS = new Set();
          for (const r of rules) {
            if (r.condition && r.condition.urlFilter) {
              let filter = r.condition.urlFilter;
              if (filter.startsWith("||")) filter = filter.slice(2);
              if (filter.endsWith("^")) filter = filter.slice(0, -1);
              BLOCKED_DOMAINS.add(filter.toLowerCase());
            }
          }
        }

        // Load compact blocked malicious C2 IPs array (optional / bare-IP DNR matches)
        try {
          const blockedIpsUrl = chrome.runtime.getURL("data/blocked_ips.json");
          const blockedIpsResp = await fetch(blockedIpsUrl);
          const blockedIpsArr = await blockedIpsResp.json();
          BLOCKED_IPS = new Set(
            Array.isArray(blockedIpsArr) ? blockedIpsArr.map(ip => String(ip).replace(/^\[|\]$/g, "").toLowerCase()) : []
          );
        } catch (e) {
          BLOCKED_IPS = new Set();
        }

        console.log(
          `[Sentinel Shield] Loaded verified brand database (${Object.keys(BRANDS).length} brands), PSL (${PUBLIC_SUFFIXES.size} suffixes), ${BLOCKED_DOMAINS.size} DNR blocked domains, and ${BLOCKED_IPS.size} C2 IPs.`
        );
      } catch (err) {
        loadDataPromise = null; // Reset to allow retry on transient failure
        console.error("[Sentinel Shield] Failed to load data files:", err);
      }
    })();
  }
  return loadDataPromise;
}

// Public suffix extractor for eTLD+1 using data/public_suffixes.json
function getETLDPlusOne(hostname) {
  if (!hostname) return "";
  const parts = hostname.toLowerCase().split(".");
  if (parts.length <= 1) return hostname.toLowerCase();

  // Match against multi-part public suffixes (e.g. pages.dev, gov.it, co.uk, com.br, co.in)
  for (let i = Math.min(parts.length - 1, 4); i >= 2; i--) {
    const candidateSuffix = parts.slice(-i).join(".");
    if (PUBLIC_SUFFIXES.has(candidateSuffix)) {
      return parts.slice(-(i + 1)).join(".");
    }
  }

  return parts.slice(-2).join(".");
}

// Damerau-Levenshtein distance for near-miss typo detection
function damerauLevenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const d = [];

  for (let i = 0; i <= m; i++) d[i] = [i];
  for (let j = 0; j <= n; j++) d[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1,       // deletion
        d[i][j - 1] + 1,       // insertion
        d[i - 1][j - 1] + cost // substitution
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost); // transposition
      }
    }
  }
  return d[m][n];
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Boundary or compound-aware keyword matching
function keywordMatches(domainCore, kw) {
  if (domainCore === kw) return true;
  const escaped = escapeRegex(kw);
  const boundaryRegex = new RegExp(`(^|[-_0-9])${escaped}([-_0-9]|$)`, "i");
  if (boundaryRegex.test(domainCore)) return true;

  // Compound check: e.g. "postelogin", "serviziposte", "paypalverify", "bancopostaservizio"
  for (const token of PHISHING_INTENT_TOKENS) {
    if (domainCore === `${kw}${token}` || domainCore === `${token}${kw}`) {
      return true;
    }
  }
  return false;
}

// Comprehensive brand impersonation & crypto drainer inspection with subdomain and homoglyph defense
function checkBrandImpersonation(rawHostname) {
  if (!rawHostname) return { spoofed: false };

  const rawLower = rawHostname.toLowerCase();
  const rawEtld1 = getETLDPlusOne(rawLower);

  // 1. Strict official domain check on RAW hostname (must strictly match before any homoglyph folding)
  for (const [key, brand] of Object.entries(BRANDS)) {
    if (brand.officialDomains.some(d => rawEtld1 === d || rawEtld1.endsWith("." + d))) {
      return { spoofed: false };
    }
  }

  // 2. Benign known domains immunity
  if (BENIGN_DOMAINS.has(rawEtld1) || BENIGN_DOMAINS.has(rawLower)) {
    return { spoofed: false };
  }

  // 3. Normalize domain (Punycode decode + NFKD diacritic strip + Homoglyph folding)
  const normalizedHostname = normalizeDomain(rawHostname);
  const etld1 = getETLDPlusOne(normalizedHostname);
  const domainCore = etld1.split(".")[0];

  if (BENIGN_DOMAINS.has(etld1) || BENIGN_DOMAINS.has(normalizedHostname)) {
    return { spoofed: false };
  }

  // Split subdomain parts before the eTLD+1
  const subparts = normalizedHostname.endsWith(etld1)
    ? normalizedHostname.slice(0, -etld1.length).replace(/\.$/, "").split(".")
    : [];

  for (const [key, brand] of Object.entries(BRANDS)) {
    // Subdomain Phishing vector: e.g. "poste.attacker-server.com" or "postepay.free-hosting.net"
    for (const sub of subparts) {
      if (!sub) continue;
      for (const kw of brand.keywords) {
        if (keywordMatches(sub, kw)) {
          return {
            spoofed: true,
            brandName: brand.displayName,
            officialDomains: brand.officialDomains,
            matchedKeyword: kw,
            hostname: rawHostname,
            vector: "subdomain"
          };
        }
      }
    }

    // Core Domain Inspection
    for (const kw of brand.keywords) {
      if (keywordMatches(domainCore, kw)) {
        return {
          spoofed: true,
          brandName: brand.displayName,
          officialDomains: brand.officialDomains,
          matchedKeyword: kw,
          hostname: rawHostname,
          vector: "domain"
        };
      }

      // Typo/Levenshtein similarity check: strictly enabled only for keywords of length >= 5
      // to avoid false positives on 4-letter English words (next.com, beer.com, ips.com)
      if (kw.length >= 5 && domainCore.length >= 5 && Math.abs(domainCore.length - kw.length) <= 1) {
        if (damerauLevenshtein(domainCore, kw) <= 1) {
          return {
            spoofed: true,
            brandName: brand.displayName,
            officialDomains: brand.officialDomains,
            matchedKeyword: kw,
            hostname: rawHostname,
            vector: "typo"
          };
        }
      }
    }
  }

  // 4. Crypto / Web3 Wallet Drainer Signatures
  for (const drainer of DRAINER_PATTERNS) {
    if (drainer.pattern.test(normalizedHostname)) {
      return {
        spoofed: true,
        brandName: "Wallet / Web3 Security",
        officialDomains: [],
        matchedKeyword: drainer.label,
        hostname: rawHostname,
        vector: "drainer",
        description: drainer.description
      };
    }
  }

  return { spoofed: false };
}

// Check whether optional Cookie & Tracking Param permissions are granted
async function hasCookiePermissions() {
  if (!chrome.permissions || typeof chrome.permissions.contains !== "function") {
    return false;
  }
  try {
    return await chrome.permissions.contains({
      permissions: ["cookies"],
      origins: ["<all_urls>"]
    });
  } catch (e) {
    return false;
  }
}

// Synchronize static tracker ruleset, per-site exceptions, and opt-in Cookie/Param Guard dynamic DNR rules
async function syncPrivacyShields() {
  try {
    const stored = await chrome.storage.local.get([
      "pricingShieldEnabled",
      "cookieGuardEnabled",
      "sitePrivacyExceptions"
    ]);
    const pricingEnabled = stored.pricingShieldEnabled !== false; // Enabled by default (0 host permissions)
    const cookieRequested = stored.cookieGuardEnabled === true;
    const siteExceptions = Array.isArray(stored.sitePrivacyExceptions)
      ? stored.sitePrivacyExceptions.filter(d => typeof d === "string" && d.length > 0)
      : [];

    // 1. Toggle Zero-Permission Anti-Dynamic Pricing & 3rd-Party Tracker static ruleset
    if (chrome.declarativeNetRequest && typeof chrome.declarativeNetRequest.updateEnabledRulesets === "function") {
      await chrome.declarativeNetRequest.updateEnabledRulesets({
        enableRulesetIds: pricingEnabled ? ["sentinel_ruleset", PRICING_RULESET_ID] : ["sentinel_ruleset"],
        disableRulesetIds: pricingEnabled ? [] : [PRICING_RULESET_ID]
      });
    }

    // 2. Sync dynamic rules for Opt-In Cookie/Param Guard and Per-Site Exceptions
    if (chrome.declarativeNetRequest && typeof chrome.declarativeNetRequest.updateDynamicRules === "function") {
      const existingDynamic = typeof chrome.declarativeNetRequest.getDynamicRules === "function"
        ? await chrome.declarativeNetRequest.getDynamicRules()
        : [];
      const removeRuleIds = (existingDynamic || [])
        .map(r => r.id)
        .filter(id => id === COOKIE_HEADER_RULE_ID || id === TRACKING_PARAM_RULE_ID || id >= SITE_ALLOW_RULE_BASE_ID);

      const addRules = [];

      // Per-site third-party allow rules (priority 3 overrides static rulesets for user-whitelisted sites)
      siteExceptions.forEach((siteDomain, idx) => {
        addRules.push({
          id: SITE_ALLOW_RULE_BASE_ID + idx,
          priority: 3,
          action: { type: "allow" },
          condition: {
            initiatorDomains: [siteDomain],
            domainType: "thirdParty",
            resourceTypes: THIRD_PARTY_SUBRESOURCE_TYPES
          }
        });
      });

      const cookiePermitted = cookieRequested && await hasCookiePermissions();
      if (cookiePermitted) {
        const cookieCondition = {
          domainType: "thirdParty",
          resourceTypes: [
            "sub_frame", "script", "image", "xmlhttprequest",
            "ping", "media", "font", "stylesheet", "other"
          ],
          excludedRequestDomains: ESSENTIAL_AUTH_PAYMENT_DOMAINS
        };
        if (siteExceptions.length > 0) {
          cookieCondition.excludedInitiatorDomains = siteExceptions;
        }

        addRules.push({
          id: COOKIE_HEADER_RULE_ID,
          priority: 1,
          action: {
            type: "modifyHeaders",
            requestHeaders: [{ header: "cookie", operation: "remove" }],
            responseHeaders: [{ header: "set-cookie", operation: "remove" }]
          },
          condition: cookieCondition
        });

        const paramCondition = {
          urlFilter: "*",
          resourceTypes: ["main_frame"]
        };
        if (siteExceptions.length > 0) {
          paramCondition.excludedInitiatorDomains = siteExceptions;
          paramCondition.excludedRequestDomains = siteExceptions;
        }

        addRules.push({
          id: TRACKING_PARAM_RULE_ID,
          priority: 1,
          action: {
            type: "redirect",
            redirect: {
              transform: {
                queryTransform: {
                  removeParams: TRACKING_QUERY_PARAMS
                }
              }
            }
          },
          condition: paramCondition
        });
      }

      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds,
        addRules
      });
    }
  } catch (err) {
    console.error("[Sentinel Shield] Failed to sync privacy shields:", err);
  }
}

// Lifecycle events
chrome.runtime.onInstalled.addListener(() => {
  ensureDataLoaded();
  syncPrivacyShields();
});

chrome.runtime.onStartup.addListener(() => {
  ensureDataLoaded();
  syncPrivacyShields();
});

function normalizeBareHost(hostname) {
  return (hostname || "").toLowerCase().trim().replace(/^\[|\]$/g, "");
}

function isHostBlocked(hostname, etld1) {
  const bare = normalizeBareHost(hostname);
  return BLOCKED_DOMAINS.has(bare) || BLOCKED_DOMAINS.has(etld1) || BLOCKED_IPS.has(bare);
}

// Catch DNR network blocks on main_frame and seamlessly display local blocked.html without requiring host permissions.
// Disambiguates against other content blockers and prevents infinite redirect loops when a session allow rule exists.
chrome.webNavigation.onErrorOccurred.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only top-level window
  if (details.error === "net::ERR_BLOCKED_BY_CLIENT" && details.url && details.url.startsWith("http")) {
    try {
      await ensureDataLoaded();
      const hostname = normalizeBareHost(new URL(details.url).hostname);
      const etld1 = getETLDPlusOne(hostname);

      if (isHostBlocked(hostname, etld1)) {
        const existingSessionRules = await new Promise(resolve => {
          chrome.declarativeNetRequest.getSessionRules(resolve);
        });

        const isAlreadyAllowed = (existingSessionRules || []).some(
          r => r.action && r.action.type === "allow" &&
               (!r.condition?.tabIds || r.condition.tabIds.includes(details.tabId)) &&
               r.condition && (
                 r.condition.urlFilter === `||${hostname}^` ||
                 r.condition.urlFilter === `||${etld1}^`
               )
        );

        if (isAlreadyAllowed) {
          return;
        }

        const blockedPageUrl = chrome.runtime.getURL(`pages/blocked.html?domain=${encodeURIComponent(hostname)}`);
        chrome.tabs.update(details.tabId, { url: blockedPageUrl });
      }
    } catch (e) {
      // Ignore URL parsing errors
    }
  }
});

// Evaluate navigations
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only inspect top-level window navigation
  if (!details.url || !details.url.startsWith("http")) return;

  try {
    const url = new URL(details.url);
    const hostname = url.hostname;

    const storage = await chrome.storage.local.get(["exceptions"]);
    const exceptions = storage.exceptions || [];
    const warningKey = `tab_${details.tabId}`;

    if (exceptions.includes(hostname)) {
      await chrome.storage.session.remove(warningKey);
      chrome.action.setBadgeText({ text: "", tabId: details.tabId });
      return;
    }

    await ensureDataLoaded();

    const result = checkBrandImpersonation(hostname);
    if (result.spoofed) {
      await chrome.storage.session.set({ [warningKey]: result });
      chrome.action.setBadgeText({ text: "!", tabId: details.tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#f59e0b", tabId: details.tabId });
      console.warn(`[Sentinel Shield] Threat alert for tab ${details.tabId}:`, result);
    } else {
      await chrome.storage.session.remove(warningKey);
      chrome.action.setBadgeText({ text: "", tabId: details.tabId });
    }
  } catch (err) {
    // Ignore invalid URLs
  }
});

// Clean up tab tracking and tab-scoped DNR session bypass rules on tab close
chrome.tabs.onRemoved.addListener(async (tabId) => {
  const warningKey = `tab_${tabId}`;
  const bypassKey = `tabBypass_${tabId}`;
  try {
    const stored = await chrome.storage.session.get([bypassKey]);
    const ruleIds = Array.isArray(stored[bypassKey]) ? stored[bypassKey] : [];
    await chrome.storage.session.remove([warningKey, bypassKey]);
    if (ruleIds.length > 0 && chrome.declarativeNetRequest?.updateSessionRules) {
      chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ruleIds });
    }
  } catch (e) {
    chrome.storage.session.remove(warningKey);
  }
});

// Message handling for popup UI, privacy toggles, cookie cleanup, and bypass requests
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getTabWarning") {
    const warningKey = `tab_${request.tabId}`;
    (async () => {
      await ensureDataLoaded();
      const [sessRes, localRes, cookiePermitted] = await Promise.all([
        chrome.storage.session.get([warningKey]),
        chrome.storage.local.get(["pricingShieldEnabled", "cookieGuardEnabled", "sitePrivacyExceptions"]),
        hasCookiePermissions()
      ]);

      const warning = sessRes[warningKey] || null;
      const domain = normalizeBareHost(request.domain);
      const etld1 = getETLDPlusOne(domain);
      const isBlocked = isHostBlocked(domain, etld1);
      const siteExceptions = Array.isArray(localRes.sitePrivacyExceptions) ? localRes.sitePrivacyExceptions : [];

      sendResponse({
        warning,
        isBlocked,
        etld1,
        pricingShieldEnabled: localRes.pricingShieldEnabled !== false,
        cookieGuardEnabled: localRes.cookieGuardEnabled === true && cookiePermitted,
        hasCookiePermission: cookiePermitted,
        sitePrivacyExempt: Boolean(etld1 && siteExceptions.includes(etld1))
      });
    })();
    return true;
  }

  if (request.action === "addException") {
    const domain = request.domain;
    chrome.storage.local.get(["exceptions"], (res) => {
      const list = res.exceptions || [];
      if (!list.includes(domain)) {
        list.push(domain);
        chrome.storage.local.set({ exceptions: list }, () => {
          if (request.tabId) {
            const warningKey = `tab_${request.tabId}`;
            chrome.storage.session.remove(warningKey);
            chrome.action.setBadgeText({ text: "", tabId: request.tabId });
          }
          sendResponse({ success: true });
        });
      } else {
        sendResponse({ success: true });
      }
    });
    return true;
  }

  if (request.action === "setPricingShield") {
    const enabled = Boolean(request.enabled);
    chrome.storage.local.set({ pricingShieldEnabled: enabled }, async () => {
      await syncPrivacyShields();
      sendResponse({ success: true, pricingShieldEnabled: enabled });
    });
    return true;
  }

  if (request.action === "setCookieGuard") {
    const enabled = Boolean(request.enabled);
    (async () => {
      if (enabled) {
        const permitted = await hasCookiePermissions();
        if (!permitted) {
          sendResponse({ success: false, error: "Cookie & host permissions not granted" });
          return;
        }
      }
      await chrome.storage.local.set({ cookieGuardEnabled: enabled });
      await syncPrivacyShields();
      sendResponse({ success: true, cookieGuardEnabled: enabled });
    })();
    return true;
  }

  if (request.action === "toggleSitePrivacyException") {
    (async () => {
      await ensureDataLoaded();
      const rawDomain = (request.domain || "").toLowerCase().trim();
      const etld1 = getETLDPlusOne(rawDomain);
      if (!etld1) {
        sendResponse({ success: false, error: "Invalid domain" });
        return;
      }
      const stored = await chrome.storage.local.get(["sitePrivacyExceptions"]);
      const list = Array.isArray(stored.sitePrivacyExceptions) ? [...stored.sitePrivacyExceptions] : [];
      const idx = list.indexOf(etld1);
      let exempt = false;
      if (idx >= 0) {
        list.splice(idx, 1);
        exempt = false;
      } else {
        list.push(etld1);
        exempt = true;
      }
      await chrome.storage.local.set({ sitePrivacyExceptions: list });
      await syncPrivacyShields();
      sendResponse({ success: true, sitePrivacyExempt: exempt, etld1 });
    })();
    return true;
  }

  if (request.action === "getSiteCookiesCount") {
    (async () => {
      await ensureDataLoaded();
      const permitted = await hasCookiePermissions();
      if (!permitted || !chrome.cookies) {
        sendResponse({ permitted: false, count: 0, etld1: "" });
        return;
      }
      const rawDomain = (request.domain || "").toLowerCase().trim();
      const etld1 = getETLDPlusOne(rawDomain);
      if (!etld1) {
        sendResponse({ permitted: true, count: 0, etld1: "" });
        return;
      }
      const cookies = await chrome.cookies.getAll({ domain: etld1 });
      sendResponse({ permitted: true, count: cookies.length, etld1 });
    })();
    return true;
  }

  if (request.action === "cleanSiteCookies") {
    (async () => {
      await ensureDataLoaded();
      const permitted = await hasCookiePermissions();
      if (!permitted || !chrome.cookies) {
        sendResponse({ success: false, removed: 0, error: "Permission required" });
        return;
      }
      const rawDomain = (request.domain || "").toLowerCase().trim();
      const etld1 = getETLDPlusOne(rawDomain);
      if (!etld1) {
        sendResponse({ success: false, removed: 0, error: "Invalid domain" });
        return;
      }
      const cookies = await chrome.cookies.getAll({ domain: etld1 });
      let removed = 0;
      for (const c of cookies) {
        const cleanHost = (c.domain || etld1).replace(/^\./, "");
        const protocol = c.secure ? "https" : "http";
        const cookieUrl = `${protocol}://${cleanHost}${c.path || "/"}`;
        try {
          const details = { url: cookieUrl, name: c.name };
          if (c.storeId) details.storeId = c.storeId;
          const res = await chrome.cookies.remove(details);
          if (res) removed += 1;
        } catch (e) {
          // Ignore individual cookie removal edge cases (e.g. partitionKey differences)
        }
      }
      sendResponse({ success: true, removed, etld1 });
    })();
    return true;
  }

  // Session-scoped bypass for DNR blocked sites (overrides static block rules via priority 2 allow rule)
  if (request.action === "bypassDomain") {
    const domain = (request.domain || "").toLowerCase().trim();
    if (!domain) {
      sendResponse({ success: false, error: "Empty domain" });
      return true;
    }

    const resolvedTabId = Number.isInteger(request.tabId)
      ? request.tabId
      : (sender && sender.tab && Number.isInteger(sender.tab.id) ? sender.tab.id : null);

    chrome.declarativeNetRequest.getSessionRules(async (existingRules) => {
      const alreadyAllowed = (existingRules || []).some(
        r => r.condition &&
             r.condition.urlFilter === `||${domain}^` &&
             r.action && r.action.type === "allow" &&
             (resolvedTabId === null ? !r.condition.tabIds : (!r.condition.tabIds || r.condition.tabIds.includes(resolvedTabId)))
      );
      if (alreadyAllowed) {
        sendResponse({ success: true, alreadyAllowed: true });
        return;
      }

      const storage = await chrome.storage.session.get(["lastSessionRuleId"]);
      const existingMax = (existingRules || []).reduce((max, r) => Math.max(max, r.id || 0), 100000);
      memorySessionRuleId = Math.max(memorySessionRuleId, existingMax, storage.lastSessionRuleId || 100000) + 1;
      const nextId = memorySessionRuleId;
      await chrome.storage.session.set({ lastSessionRuleId: nextId });

      const condition = {
        urlFilter: `||${domain}^`
      };
      if (resolvedTabId !== null) {
        condition.tabIds = [resolvedTabId];
      }

      const allowRule = {
        id: nextId,
        priority: 2,
        action: { type: "allow" },
        condition: condition
      };

      chrome.declarativeNetRequest.updateSessionRules({
        addRules: [allowRule]
      }, async () => {
        if (chrome.runtime.lastError) {
          console.error("[Sentinel Shield] Failed to add session bypass rule:", chrome.runtime.lastError);
          sendResponse({ success: false, error: chrome.runtime.lastError.message });
        } else {
          if (resolvedTabId !== null) {
            const bypassKey = `tabBypass_${resolvedTabId}`;
            const cur = await chrome.storage.session.get([bypassKey]);
            const prevIds = Array.isArray(cur[bypassKey]) ? cur[bypassKey] : [];
            if (!prevIds.includes(nextId)) prevIds.push(nextId);
            await chrome.storage.session.set({ [bypassKey]: prevIds });
          }
          console.log(`[Sentinel Shield] Added session bypass allow rule (id ${nextId}) for ${domain}`);
          sendResponse({ success: true, ruleId: nextId, tabScoped: resolvedTabId !== null });
        }
      });
    });
    return true;
  }
});
