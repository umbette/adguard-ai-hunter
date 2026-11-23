document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  let rawDomain = urlParams.get("domain") || "";

  // Sanitize domain to prevent open redirect or malformed destinations
  let domain = "";
  try {
    if (rawDomain.includes("://")) {
      domain = new URL(rawDomain).hostname;
    } else {
      domain = rawDomain.split("/")[0].split(":")[0].trim();
    }
  } catch (e) {
    domain = rawDomain.replace(/[^a-zA-Z0-9.-]/g, "");
  }

  if (!domain) domain = "Destinazione non specificata";

  const domainDisplay = document.getElementById("domainDisplay");
  if (domainDisplay) {
    domainDisplay.textContent = domain;
  }

  const btnBack = document.getElementById("btnBack");
  if (btnBack) {
    btnBack.addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    });
  }

  const btnProceed = document.getElementById("btnProceed");
  if (btnProceed) {
    btnProceed.addEventListener("click", () => {
      btnProceed.disabled = true;
      btnProceed.textContent = "Sblocco in corso...";

      // Register session bypass rule with higher priority (priority 2 allow rule)
      chrome.runtime.sendMessage({ action: "bypassDomain", domain: domain }, (res) => {
        const targetUrl = `https://${domain}`;
        window.location.href = targetUrl;
      });
    });
  }
});
