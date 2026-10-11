
(() => {
  if (window.top !== window.self) return;

  const host = window.location.hostname.toLowerCase();

  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    window.location.protocol === "chrome-extension:"
  ) {
    return;
  }

  let badge;

  function showBadge(text, color) {
    if (!document.documentElement) return;

    if (!badge) {
      badge = document.createElement("div");
      badge.id = "idps-shield-status";

      Object.assign(badge.style, {
        position: "fixed",
        right: "12px",
        bottom: "12px",
        zIndex: "2147483647",
        padding: "8px 12px",
        borderRadius: "10px",
        color: "#ffffff",
        background: "#0f172a",
        border: "1px solid #334155",
        font: "12px Segoe UI, Arial, sans-serif",
        boxShadow: "0 4px 20px #0005",
        pointerEvents: "none"
      });

      document.documentElement.appendChild(badge);
    }

    badge.textContent = `IDPS Shield · ${text}`;
    badge.style.borderColor = color;
  }

  chrome.storage.local.get({
    protectionEnabled: true,
    token: ""
  }).then((settings) => {
    if (!settings.protectionEnabled) {
      showBadge("Protection paused", "#64748b");
      return;
    }

    if (!settings.token) {
      showBadge("Setup required", "#d97706");
      return;
    }

    showBadge("Protection active · assessment may be pending", "#0891b2");
  }).catch(() => {
    // The page should continue normally if extension storage is unavailable.
  });
})();
