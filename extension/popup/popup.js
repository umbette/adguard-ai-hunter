document.addEventListener("DOMContentLoaded", async () => {
  let activeTab = null;
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTab = tabs[0];
  } catch (e) {}

  if (!activeTab || !activeTab.id) return;

  let activeHostname = "";
  let isOnBlockedPage = false;
  let isWebTab = false;
  try {
    if (activeTab.url) {
      const parsedUrl = new URL(activeTab.url);
      if (parsedUrl.protocol === "chrome-extension:" && parsedUrl.searchParams.has("domain")) {
        activeHostname = parsedUrl.searchParams.get("domain");
        isOnBlockedPage = true;
      } else if (parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:") {
        activeHostname = parsedUrl.hostname;
        isWebTab = Boolean(activeHostname);
      } else {
        activeHostname = parsedUrl.hostname;
      }
    }
  } catch (e) {}

  const container = document.getElementById("statusContainer");
  const title = document.getElementById("statusTitle");
  const desc = document.getElementById("statusDesc");
  const officialHint = document.getElementById("officialDomainHint");
  const btnException = document.getElementById("btnException");
  const btnBypassDnr = document.getElementById("btnBypassDnr");
  const togglePricing = document.getElementById("togglePricingShield");
  const toggleCookie = document.getElementById("toggleCookieGuard");
  const pricingTag = document.getElementById("pricingTag");
  const cookieTag = document.getElementById("cookieTag");
  const siteActions = document.getElementById("siteActions");
  const btnCleanCookies = document.getElementById("btnCleanCookies");
  const btnSitePrivacyToggle = document.getElementById("btnSitePrivacyToggle");
  const feedbackNote = document.getElementById("feedbackNote");

  function setFeedback(text) {
    if (!feedbackNote) return;
    feedbackNote.textContent = text;
    if (text) {
      setTimeout(() => {
        if (feedbackNote.textContent === text) {
          feedbackNote.textContent = "";
        }
      }, 3000);
    }
  }

  function refreshCookieButtonState(hasPermission) {
    if (!btnCleanCookies || !isWebTab || !activeHostname) return;
    if (!hasPermission) {
      btnCleanCookies.style.display = "none";
      return;
    }
    btnCleanCookies.style.display = "block";
    chrome.runtime.sendMessage(
      { action: "getSiteCookiesCount", domain: activeHostname },
      (cookieRes) => {
        if (cookieRes && cookieRes.permitted) {
          btnCleanCookies.textContent = `Pulisci Cookie di ${cookieRes.etld1 || activeHostname} (${cookieRes.count})`;
          btnCleanCookies.disabled = cookieRes.count === 0;
        }
      }
    );
  }

  function updateCookieUiState(enabled, permitted) {
    if (toggleCookie) toggleCookie.checked = Boolean(enabled);
    if (cookieTag) {
      if (enabled) {
        cookieTag.textContent = "ATTIVO";
        cookieTag.classList.add("active");
      } else {
        cookieTag.textContent = permitted ? "PAUSA" : "OPT-IN";
        cookieTag.classList.remove("active");
      }
    }
    refreshCookieButtonState(permitted);
  }

  // Query warning, block, and privacy shield state from background service worker
  chrome.runtime.sendMessage(
    { action: "getTabWarning", tabId: activeTab.id, domain: activeHostname },
    (response) => {
      const warning = response && response.warning;
      const isBlocked = (response && response.isBlocked) || isOnBlockedPage;

      if (warning && warning.spoofed) {
        container.className = "status-box status-warning";
        if (warning.vector === "drainer") {
          title.textContent = "⚠️ Possibile Wallet Drainer";
          desc.textContent = warning.description || `Il dominio (${warning.hostname}) presenta firme tipiche di drainer Web3.`;
        } else {
          title.textContent = "⚠️ Possibile Imitazione";
          const vectorDetail = warning.vector === "subdomain"
            ? `Questo sottodominio (${warning.hostname}) tenta di imitare ${warning.brandName}.`
            : `Questo sito (${warning.hostname}) somiglia a ${warning.brandName}, ma non è un dominio ufficiale registrato.`;
          desc.textContent = `${vectorDetail} Non inserire password o dati di pagamento.`;
        }

        if (officialHint && Array.isArray(warning.officialDomains) && warning.officialDomains.length > 0) {
          officialHint.textContent = `Dominio ufficiale: ${warning.officialDomains[0]}`;
          officialHint.style.display = "block";
        } else if (officialHint) {
          officialHint.style.display = "none";
        }

        btnException.style.display = "block";
        btnException.onclick = () => {
          chrome.runtime.sendMessage(
            { action: "addException", domain: warning.hostname, tabId: activeTab.id },
            () => {
              window.close();
            }
          );
        };
      } else {
        container.className = "status-box status-safe";
        title.textContent = "Nessun Avviso";
        desc.textContent = "Nessuna imitazione o anomalia censita. Verifica euristica locale Sentinel attiva.";
        if (officialHint) officialHint.style.display = "none";
        btnException.style.display = "none";
      }

      // Expose 1-click session bypass ONLY if the domain is genuinely blocked or on blocked.html
      if (isBlocked && activeHostname && !["chrome", "edge", "about", ""].includes(activeHostname)) {
        btnBypassDnr.style.display = "block";
        btnBypassDnr.textContent = `Sblocca ${activeHostname} (Sessione)`;
        btnBypassDnr.onclick = () => {
          btnBypassDnr.disabled = true;
          btnBypassDnr.textContent = "Sblocco in corso...";
          chrome.runtime.sendMessage(
            { action: "bypassDomain", domain: activeHostname, tabId: activeTab.id },
            (res) => {
              if (res && res.success) {
                if (isOnBlockedPage) {
                  const targetUrl = activeHostname.startsWith("http") ? activeHostname : `https://${activeHostname}`;
                  chrome.tabs.update(activeTab.id, { url: targetUrl }, () => {
                    window.close();
                  });
                } else {
                  chrome.tabs.reload(activeTab.id, () => {
                    window.close();
                  });
                }
              } else {
                setFeedback("Impossibile sbloccare: " + (res && res.error ? res.error : "Errore"));
                btnBypassDnr.disabled = false;
                btnBypassDnr.textContent = `Sblocca ${activeHostname} (Sessione)`;
              }
            }
          );
        };
      } else {
        btnBypassDnr.style.display = "none";
      }

      // Hydrate Privacy & Cookie shields
      const pricingEnabled = !response || response.pricingShieldEnabled !== false;
      if (togglePricing) togglePricing.checked = pricingEnabled;
      if (pricingTag) {
        pricingTag.textContent = pricingEnabled ? "ATTIVO" : "PAUSA";
        pricingTag.classList.toggle("active", pricingEnabled);
      }

      updateCookieUiState(
        Boolean(response && response.cookieGuardEnabled),
        Boolean(response && response.hasCookiePermission)
      );

      // Show per-site privacy controls on normal web tabs
      if (isWebTab && siteActions && activeHostname) {
        siteActions.style.display = "flex";
        const siteLabel = (response && response.etld1) || activeHostname;
        let isExempt = Boolean(response && response.sitePrivacyExempt);

        const renderSitePrivacyBtn = () => {
          btnSitePrivacyToggle.textContent = isExempt
            ? `Ripristina scudi su ${siteLabel}`
            : `Escludi ${siteLabel} dagli scudi privacy`;
        };
        renderSitePrivacyBtn();

        btnSitePrivacyToggle.onclick = () => {
          chrome.runtime.sendMessage(
            { action: "toggleSitePrivacyException", domain: activeHostname },
            (res) => {
              if (res && res.success) {
                isExempt = res.sitePrivacyExempt;
                renderSitePrivacyBtn();
                setFeedback(isExempt
                  ? `Scudi privacy disattivati su ${res.etld1}`
                  : `Scudi privacy riattivati su ${res.etld1}`);
              }
            }
          );
        };
      }
    }
  );

  if (togglePricing) {
    togglePricing.addEventListener("change", () => {
      const enabled = togglePricing.checked;
      chrome.runtime.sendMessage(
        { action: "setPricingShield", enabled },
        (res) => {
          const active = res ? res.pricingShieldEnabled : enabled;
          if (pricingTag) {
            pricingTag.textContent = active ? "ATTIVO" : "PAUSA";
            pricingTag.classList.toggle("active", active);
          }
          setFeedback(active ? "Scudo Anti-Dynamic Pricing attivo" : "Scudo Anti-Dynamic Pricing in pausa");
        }
      );
    });
  }

  if (toggleCookie) {
    toggleCookie.addEventListener("change", async () => {
      const wantsEnabled = toggleCookie.checked;
      if (wantsEnabled) {
        let granted = false;
        try {
          if (chrome.permissions && typeof chrome.permissions.request === "function") {
            granted = await chrome.permissions.request({
              permissions: ["cookies"],
              origins: ["<all_urls>"]
            });
          }
        } catch (e) {
          granted = false;
        }
        if (!granted) {
          updateCookieUiState(false, false);
          setFeedback("Permesso cookie non concesso");
          return;
        }
      }

      chrome.runtime.sendMessage(
        { action: "setCookieGuard", enabled: wantsEnabled },
        (res) => {
          const active = Boolean(res && res.success && res.cookieGuardEnabled);
          updateCookieUiState(active, wantsEnabled || active);
          setFeedback(active
            ? "Cookie & Tracking Param Guard attivo"
            : "Cookie & Tracking Param Guard disattivato");
        }
      );
    });
  }

  if (btnCleanCookies) {
    btnCleanCookies.addEventListener("click", () => {
      if (!activeHostname) return;
      btnCleanCookies.disabled = true;
      chrome.runtime.sendMessage(
        { action: "cleanSiteCookies", domain: activeHostname },
        (res) => {
          if (res && res.success) {
            setFeedback(`✓ Rimossi ${res.removed} cookie su ${res.etld1}`);
            refreshCookieButtonState(true);
          } else {
            setFeedback("Impossibile pulire i cookie");
            btnCleanCookies.disabled = false;
          }
        }
      );
    });
  }
});
