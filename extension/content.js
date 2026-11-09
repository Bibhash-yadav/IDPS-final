"use strict";

(() => {
  // Run only in the top-level website document.
  if (window.top !== window.self) return;

  const host = window.location.hostname.toLowerCase();

  // Do not display the badge on local development sites.
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "[::1]" ||
    window.location.protocol === "chrome-extension:"
  ) {
    return;
  }

  const BADGE_ID = "idps-shield-status";

  let badge = null;

  function showBadge(text, color) {
    if (!document.documentElement) return;

    if (!badge || !badge.isConnected) {
      badge = document.getElementById(BADGE_ID);

      if (!badge) {
        badge = document.createElement("div");
        badge.id = BADGE_ID;

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
          pointerEvents: "none",
          maxWidth: "calc(100vw - 24px)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          userSelect: "none"
        });

        document.documentElement.appendChild(badge);
      }
    }

    badge.textContent = `IDPS Shield · ${text}`;
    badge.style.borderColor = color;
  }

  function removeBadge() {
    const existing = document.getElementById(BADGE_ID);

    if (existing) {
      existing.remove();
    }

    badge = null;
  }

  async function updateBadge() {
    try {
      const settings = await chrome.storage.local.get({
        protectionEnabled: true,
        token: ""
      });

      const protectionEnabled = Boolean(
        settings.protectionEnabled
      );

      const hasToken = Boolean(
        String(settings.token || "").trim()
      );

      if (!protectionEnabled) {
        showBadge("Protection paused", "#64748b");
        return;
      }

      if (!hasToken) {
        showBadge("Setup required", "#d97706");
        return;
      }

      // This indicates that the extension is configured.
      // It does not claim that the current page has been scanned.
      showBadge("Protection enabled · monitoring", "#0891b2");
    } catch (error) {
      console.warn(
        "IDPS Shield could not read extension settings:",
        error
      );

      removeBadge();
    }
  }

  // Initial status.
  void updateBadge();

  // Reflect changes made from the popup or options page.
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (
      areaName !== "local" ||
      (!changes.protectionEnabled && !changes.token)
    ) {
      return;
    }

    void updateBadge();
  });
})();