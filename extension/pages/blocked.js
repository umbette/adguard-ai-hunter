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
        `Attenzione: procedere su ${domain} potrebbe esporre a rischi informatici o truffe.\n\nVuoi davvero continuare?`
      );
      if (confirmProceed && domain.startsWith("http")) {
        window.location.href = domain;
      } else if (confirmProceed) {
        window.location.href = "https://" + domain;
      }
    });
  }
});
