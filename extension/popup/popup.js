document.addEventListener("DOMContentLoaded", async () => {
  let activeTab = null;
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTab = tabs[0];
  } catch (e) {}

  if (!activeTab || !activeTab.id) return;

  let activeHostname = "";
  try {
    if (activeTab.url) {
      activeHostname = new URL(activeTab.url).hostname;
    }
  } catch (e) {}

  const container = document.getElementById("statusContainer");
  const title = document.getElementById("statusTitle");
  const desc = document.getElementById("statusDesc");
  const btnException = document.getElementById("btnException");
  const btnBypassDnr = document.getElementById("btnBypassDnr");

  // Query warning state stored in chrome.storage.session
  chrome.runtime.sendMessage({ action: "getTabWarning", tabId: activeTab.id }, (response) => {
    const warning = response && response.warning;

    if (warning && warning.spoofed) {
      container.className = "status-box status-warning";
      title.textContent = "⚠️ Possibile Imitazione";
      desc.textContent = `Questo sito (${warning.hostname}) somiglia a ${warning.brandName}, ma non è un dominio ufficiale registrato. Non inserire password o coordinate bancarie.`;

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
      desc.textContent = "Nessuna minaccia censita o imitazione di marchio rilevata da questo controllo locale.";
      btnException.style.display = "none";
    }

    // Expose 1-click session bypass if the tab is on a valid web domain
    if (activeHostname && !["chrome", "edge", "about", ""].includes(activeHostname)) {
      btnBypassDnr.style.display = "block";
      btnBypassDnr.textContent = `Sblocca ${activeHostname} (Sessione)`;
      btnBypassDnr.onclick = () => {
        btnBypassDnr.disabled = true;
        btnBypassDnr.textContent = "Sblocco in corso...";
        chrome.runtime.sendMessage({ action: "bypassDomain", domain: activeHostname }, (res) => {
          if (res && res.success) {
            chrome.tabs.reload(activeTab.id, () => {
              window.close();
            });
          } else {
            alert("Impossibile sbloccare il dominio: " + (res && res.error ? res.error : "Errore"));
            btnBypassDnr.disabled = false;
            btnBypassDnr.textContent = `Sblocca ${activeHostname} (Sessione)`;
          }
        });
      };
    } else {
      btnBypassDnr.style.display = "none";
    }
  });
});
