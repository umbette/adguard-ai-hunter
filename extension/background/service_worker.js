/**
 * AI Hunter Shield - Manifest V3 Background Service Worker
 * 100% Local Heuristic Inspection & Brand Impersonation Guard
 */

let BRANDS = {};
let PUBLIC_SUFFIXES = [];
let loadDataPromise = null;

// Atomically load local brand database and public suffix list on startup
function ensureDataLoaded() {
  if (!loadDataPromise) {
    loadDataPromise = (async () => {
      try {
        const brandsUrl = chrome.runtime.getURL("data/brands.json");
        const brandsResp = await fetch(brandsUrl);
        BRANDS = await brandsResp.json();

        const suffixesUrl = chrome.runtime.getURL("data/public_suffixes.json");
        const suffixesResp = await fetch(suffixesUrl);
        PUBLIC_SUFFIXES = await suffixesResp.json();

        console.log(
          `[Hunter Shield] Loaded verified brand database (${Object.keys(BRANDS).length} brands) and PSL (${PUBLIC_SUFFIXES.length} multi-part suffixes).`
        );
      } catch (err) {
        console.error("[Hunter Shield] Failed to load data files:", err);
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

  // Match against multi-part public suffixes (e.g. pages.dev, gov.it, co.uk)
  for (let i = Math.min(parts.length - 1, 3); i >= 2; i--) {
    const candidateSuffix = parts.slice(-i).join(".");
    if (PUBLIC_SUFFIXES.includes(candidateSuffix)) {
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

// Catch DNR network blocks on main_frame and seamlessly display local blocked.html without requiring host permissions
chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.frameId !== 0) return; // Only top-level window
  if (details.error === "net::ERR_BLOCKED_BY_CLIENT" && details.url && details.url.startsWith("http")) {
    try {
      const hostname = new URL(details.url).hostname;
      const blockedPageUrl = chrome.runtime.getURL(`pages/blocked.html?domain=${encodeURIComponent(hostname)}`);
      chrome.tabs.update(details.tabId, { url: blockedPageUrl });
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
      console.warn(`[Hunter Shield] Brand impersonation alert for tab ${details.tabId}:`, result);
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

    // Query existing session rules asynchronously to compute a collision-free ID across worker restarts
    chrome.declarativeNetRequest.getSessionRules((existingRules) => {
      const alreadyAllowed = (existingRules || []).some(
        r => r.condition && r.condition.urlFilter === `||${domain}^` && r.action && r.action.type === "allow"
      );
      if (alreadyAllowed) {
        sendResponse({ success: true, alreadyAllowed: true });
        return;
      }

      const maxId = (existingRules || []).reduce((max, r) => Math.max(max, r.id || 0), 100000);
      const ruleId = maxId + 1;

      const allowRule = {
        id: ruleId,
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
          console.error("[AI Hunter] Failed to add session bypass rule:", chrome.runtime.lastError);
          sendResponse({ success: false, error: chrome.runtime.lastError.message });
        } else {
          console.log(`[AI Hunter] Added session bypass allow rule (id ${ruleId}) for ${domain}`);
          sendResponse({ success: true, ruleId });
        }
      });
    });
    return true;
  }
});
