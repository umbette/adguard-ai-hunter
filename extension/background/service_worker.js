/**
 * Sentinel Shield - Manifest V3 Background Service Worker
 * 100% Local Heuristic Inspection & Brand Impersonation Guard
 */

let BRANDS = {};
let PUBLIC_SUFFIXES = new Set();
let BLOCKED_DOMAINS = new Set();
let loadDataPromise = null;

// Atomically load local brand database, public suffix list, and DNR ruleset on startup
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

        // Load static DNR rules to enable precise disambiguation against other content blockers
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

        console.log(
          `[Sentinel Shield] Loaded verified brand database (${Object.keys(BRANDS).length} brands), PSL (${PUBLIC_SUFFIXES.size} multi-part suffixes), and ${BLOCKED_DOMAINS.size} DNR blocked domains.`
        );
      } catch (err) {
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

// Damerau-Levenshtein distance for short strings
function damerauLevenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const d = [];

  for (let i = 0; i <= m; i++) {
    d[i] = [i];
  }
  for (let j = 0; j <= n; j++) {
    d[0][j] = j;
  }

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

// Escape regex special characters to prevent invalid regex or unexpected matching
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Boundary-aware keyword matching: requires exact match or separation by hyphens, underscores or digits.
// Prevents false positives on legitimate words containing a brand substring (e.g. "impostore", "risposte", "amazonaws").
function keywordMatches(domainCore, kw) {
  if (domainCore === kw) return true;
  const escaped = escapeRegex(kw);
  const regex = new RegExp(`(^|[-_0-9])${escaped}([-_0-9]|$)`, "i");
  return regex.test(domainCore);
}

// Evaluate domain for brand impersonation
function checkBrandImpersonation(hostname) {
  const etld1 = getETLDPlusOne(hostname);
  const domainCore = etld1.split(".")[0];

  for (const [key, brand] of Object.entries(BRANDS)) {
    // 1. If it's already an official domain for this brand, it is fully safe
    if (brand.officialDomains.some(d => etld1 === d || etld1.endsWith("." + d))) {
      continue;
    }

    // 2. Keyword check: does domainCore contain a brand keyword with boundary separation (e.g. "poste-servizi", "bancoposta-online")?
    for (const kw of brand.keywords) {
      if (keywordMatches(domainCore, kw)) {
        return {
          spoofed: true,
          brandName: brand.displayName,
          officialDomains: brand.officialDomains,
          matchedKeyword: kw,
          hostname: hostname
        };
      }

      // 3. Typo/Levenshtein similarity check for near-miss spoofing (e.g. "paypa1", "intesasampaolo")
      if (kw.length >= 4 && damerauLevenshtein(domainCore, kw) <= 1) {
        return {
          spoofed: true,
          brandName: brand.displayName,
          officialDomains: brand.officialDomains,
          matchedKeyword: kw,
          hostname: hostname
        };
      }
    }
  }

  return { spoofed: false };
}

// Lifecycle events
chrome.runtime.onInstalled.addListener(() => {
  ensureDataLoaded();
});

chrome.runtime.onStartup.addListener(() => {
  ensureDataLoaded();
});

// Catch DNR network blocks on main_frame and seamlessly display local blocked.html without requiring host permissions.
// Disambiguates against uBlock Origin and other blockers by verifying the domain is in Sentinel Shield's ruleset.
chrome.webNavigation.onErrorOccurred.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only top-level window
  if (details.error === "net::ERR_BLOCKED_BY_CLIENT" && details.url && details.url.startsWith("http")) {
    try {
      await ensureDataLoaded();
      const hostname = new URL(details.url).hostname.toLowerCase();
      const etld1 = getETLDPlusOne(hostname);

      // Disambiguation: ONLY redirect if domain or eTLD+1 matches Sentinel Shield's blocked rules.
      // Other blockers (e.g. uBlock Origin) will NOT trigger our blocked page.
      if (BLOCKED_DOMAINS.has(hostname) || BLOCKED_DOMAINS.has(etld1)) {
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

    // Check user exceptions
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
      // Store in chrome.storage.session so state survives service worker sleep/wake lifecycle
      await chrome.storage.session.set({ [warningKey]: result });
      chrome.action.setBadgeText({ text: "!", tabId: details.tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#f57c00", tabId: details.tabId });
      console.warn(`[Sentinel Shield] Brand impersonation alert for tab ${details.tabId}:`, result);
    } else {
      await chrome.storage.session.remove(warningKey);
      chrome.action.setBadgeText({ text: "", tabId: details.tabId });
    }
  } catch (err) {
    // Ignore invalid URLs
  }
});

// Clean up tab tracking in session storage on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  const warningKey = `tab_${tabId}`;
  chrome.storage.session.remove(warningKey);
});

// Message handling for popup UI and bypass requests
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getTabWarning") {
    const warningKey = `tab_${request.tabId}`;
    chrome.storage.session.get([warningKey], (res) => {
      sendResponse({ warning: res[warningKey] || null });
    });
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

  // Session-scoped bypass for DNR blocked sites (overrides static block rules via priority 2 allow rule)
  if (request.action === "bypassDomain") {
    const domain = (request.domain || "").toLowerCase().trim();
    if (!domain) {
      sendResponse({ success: false, error: "Empty domain" });
      return true;
    }

    // Query existing session rules and session storage counter to compute a collision-free ID across worker restarts
    chrome.declarativeNetRequest.getSessionRules(async (existingRules) => {
      const alreadyAllowed = (existingRules || []).some(
        r => r.condition && r.condition.urlFilter === `||${domain}^` && r.action && r.action.type === "allow"
      );
      if (alreadyAllowed) {
        sendResponse({ success: true, alreadyAllowed: true });
        return;
      }

      // Persist counter in session storage to guarantee monotonic IDs even under concurrent calls
      const storage = await chrome.storage.session.get(["lastSessionRuleId"]);
      const existingMax = (existingRules || []).reduce((max, r) => Math.max(max, r.id || 0), 100000);
      const nextId = Math.max(existingMax, storage.lastSessionRuleId || 100000) + 1;
      await chrome.storage.session.set({ lastSessionRuleId: nextId });

      const allowRule = {
        id: nextId,
        priority: 2, // Higher than static priority 1 rules
        action: { type: "allow" },
        condition: {
          urlFilter: `||${domain}^`
        }
      };

      chrome.declarativeNetRequest.updateSessionRules({
        addRules: [allowRule]
      }, () => {
        if (chrome.runtime.lastError) {
          console.error("[Sentinel Shield] Failed to add session bypass rule:", chrome.runtime.lastError);
          sendResponse({ success: false, error: chrome.runtime.lastError.message });
        } else {
          console.log(`[Sentinel Shield] Added session bypass allow rule (id ${nextId}) for ${domain}`);
          sendResponse({ success: true, ruleId: nextId });
        }
      });
    });
    return true;
  }
});
