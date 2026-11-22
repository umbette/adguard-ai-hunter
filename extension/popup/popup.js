document.addEventListener("DOMContentLoaded", async () => {
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!activeTab || !activeTab.id) return;

  chrome.runtime.sendMessage({ action: "getTabWarning", tabId: activeTab.id }, (response) => {
    const warning = response && response.warning;
    const container = document.getElementById("statusContainer");
    const title = document.getElementById("statusTitle");
    const desc = document.getElementById("statusDesc");
    const btnException = document.getElementById("btnException");

    if (warning && warning.spoofed) {
      container.className = "status-box status-warning";
      title.textContent = "⚠️ Possibile Imitazione";
      desc.textContent = `Questo sito (${warning.hostname}) somiglia a ${warning.brandName}, ma non è un dominio ufficiale registrato. Non inserire password o coordinate bancarie.`;

      btnException.style.display = "block";
      btnException.addEventListener("click", () => {
        chrome.runtime.sendMessage(
          { action: "addException", domain: warning.hostname, tabId: activeTab.id },
          () => {
            window.close();
          }
        );
      });
    } else {
      container.className = "status-box status-safe";
      title.textContent = "Nessun Avviso";
      desc.textContent = "Nessuna minaccia censita o imitazione di marchio rilevata da questo controllo locale.";
      btnException.style.display = "none";
    }
  });
});
