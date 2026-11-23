document.addEventListener("DOMContentLoaded", async () => {
  let activeTab = null;
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTab = tabs[0];
  } catch (e) {}

  if (!activeTab || !activeTab.id) return;

  let activeHostname = "";
  let isOnBlockedPage = false;
  try {
    if (activeTab.url) {
      const parsedUrl = new URL(activeTab.url);
      if (parsedUrl.protocol === "chrome-extension:" && parsedUrl.searchParams.has("domain")) {
        // If the user opened the popup while on the blocked.html warning page, extract target domain
        activeHostname = parsedUrl.searchParams.get("domain");
        isOnBlockedPage = true;
      } else {
        activeHostname = parsedUrl.hostname;
      }
    }
  } catch (e) {}

  const container = document.getElementById("statusContainer");
  const title = document.getElementById("statusTitle");
  const desc = document.getElementById("statusDesc");
  const btnException = document.getElementById("btnException");
  const btnBypassDnr = document.getElementById("btnBypassDnr");

  // Query warning and block state from background service worker
  chrome.runtime.sendMessage(
    { action: "getTabWarning", tabId: activeTab.id, domain: activeHostname },
    (response) => {
      const warning = response && response.warning;
      const isBlocked = (response && response.isBlocked) || isOnBlockedPage;

      if (warning && warning.spoofed) {
        container.className = "status-box status-warning";
        title.textContent = "⚠️ Possibile Imitazione";
        const vectorDetail = warning.subdomainVector
          ? `Questo sottodominio (${warning.hostname}) tenta di imitare ${warning.brandName}.`
          : `Questo sito (${warning.hostname}) somiglia a ${warning.brandName}, ma non è un dominio ufficiale registrato.`;
        desc.textContent = `${vectorDetail} Non inserire password o dati di pagamento.`;

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
        desc.textContent = "Nessuna imitazione o anomalia censita. Verifica euristica locale attiva.";
        btnException.style.display = "none";
      }

      // Expose 1-click session bypass ONLY if the domain is genuinely blocked or on blocked.html
      // Prevents confusing users on safe domains (e.g. google.com, wikipedia.org)
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
                alert("Impossibile sbloccare: " + (res && res.error ? res.error : "Errore"));
                btnBypassDnr.disabled = false;
                btnBypassDnr.textContent = `Sblocca ${activeHostname} (Sessione)`;
              }
            }
          );
        };
      } else {
        btnBypassDnr.style.display = "none";
      }
    }
  );
});
