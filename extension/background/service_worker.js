/**
 * AI Hunter Shield - Manifest V3 Background Service Worker
 * 100% Local Heuristic Inspection & Brand Impersonation Guard
 */

let BRANDS = {};
const tabWarnings = new Map();

// Load local brand database on startup
async function loadBrands() {
  try {
    const url = chrome.runtime.getURL("data/brands.json");
    const resp = await fetch(url);
    BRANDS = await resp.json();
    console.log("[AI Hunter] Loaded verified brand database:", Object.keys(BRANDS).length, "brands.");
  } catch (err) {
    console.error("[AI Hunter] Failed to load brands.json:", err);
  }
}

// Minimalistic public suffix extractor for eTLD+1
function getETLDPlusOne(hostname) {
  if (!hostname) return "";
  const parts = hostname.toLowerCase().split(".");
  if (parts.length <= 2) return hostname.toLowerCase();

  // Common two-level TLDs
  const twoLevelTLDs = ["gov.it", "edu.it", "co.uk", "gov.uk", "com.br", "com.au"];
  const lastTwo = parts.slice(-2).join(".");
  if (twoLevelTLDs.includes(lastTwo)) {
    return parts.slice(-3).join(".");
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

// Evaluate domain for brand impersonation
function checkBrandImpersonation(hostname) {
  const etld1 = getETLDPlusOne(hostname);
  const domainCore = etld1.split(".")[0];

  for (const [key, brand] of Object.entries(BRANDS)) {
    // 1. If it's already an official domain for this brand, it is fully safe
    if (brand.officialDomains.some(d => etld1 === d || etld1.endsWith("." + d))) {
      continue;
    }

    // 2. Keyword check: does domainCore contain a brand keyword (e.g. "poste-servizi", "bancoposta-online")?
    for (const kw of brand.keywords) {
      if (domainCore.includes(kw)) {
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
  loadBrands();
});

chrome.runtime.onStartup.addListener(() => {
  loadBrands();
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
    if (exceptions.includes(hostname)) {
      tabWarnings.delete(details.tabId);
      chrome.action.setBadgeText({ text: "", tabId: details.tabId });
      return;
    }

    const result = checkBrandImpersonation(hostname);
    if (result.spoofed) {
      tabWarnings.set(details.tabId, result);
      chrome.action.setBadgeText({ text: "!", tabId: details.tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#f57c00", tabId: details.tabId });
      console.warn(`[AI Hunter Shield] Brand impersonation alert for tab ${details.tabId}:`, result);
    } else {
      tabWarnings.delete(details.tabId);
      chrome.action.setBadgeText({ text: "", tabId: details.tabId });
    }
  } catch (err) {
    // Ignore invalid URLs
  }
});

// Clean up tab tracking on close
chrome.tabs.onRemoved.addListener((tabId) => {
  tabWarnings.delete(tabId);
});

// Message handling for popup UI
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getTabWarning") {
    const warning = tabWarnings.get(request.tabId) || null;
    sendResponse({ warning });
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
            tabWarnings.delete(request.tabId);
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
});
