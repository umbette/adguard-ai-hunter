document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const domain = urlParams.get("domain") || "Destinazione non specificata";

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
      const confirmProceed = confirm(
        `Attenzione: procedere su ${domain} potrebbe esporre a rischi informatici o truffe.\n\nVuoi davvero sbloccare questo sito per la sessione corrente?`
      );
      if (confirmProceed) {
        // Register session bypass rule with higher priority (priority 2 allow rule)
        // so that the browser does not block the site in an infinite loop
        chrome.runtime.sendMessage({ action: "bypassDomain", domain: domain }, (res) => {
          const targetUrl = domain.startsWith("http") ? domain : `https://${domain}`;
          window.location.href = targetUrl;
        });
      }
    });
  }
});
