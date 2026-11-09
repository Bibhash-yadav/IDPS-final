"use strict";

// IDPS Shield — Browser Popup
// Authentication and 2FA are handled in options.js.
// The background script handles authenticated backend requests.

const $ = (id) => document.getElementById(id);

let currentUrl = "";
let currentTabId = null;
let isChecking = false;
let isLoading = false;

const checkButton = $("checkButton");
const protectionToggle = $("protectionToggle");

function showError(message) {
  const errorElement = $("errorMessage");

  if (!errorElement) return;

  errorElement.textContent = message;
  errorElement.classList.remove("hidden");
}

function clearError() {
  const errorElement = $("errorMessage");

  if (!errorElement) return;

  errorElement.textContent = "";
  errorElement.classList.add("hidden");
}

function setStatusDot(status) {
  const dot = $("statusDot");

  dot.classList.remove("active", "error");

  if (status === "connected") {
    dot.classList.add("active");
    dot.title = "Connected to IDPS";
  } else if (status === "error") {
    dot.classList.add("error");
    dot.title = "Connection needs attention";
  } else {
    dot.title = "Not connected";
  }
}

function setCheckButton(enabled, text = "Check Current Website") {
  checkButton.disabled = !enabled;
  checkButton.textContent = text;
}

function getDecisionStyle(decision, riskLevel) {
  if (
    decision === "BLOCK" ||
    ["HIGH", "CRITICAL"].includes(riskLevel)
  ) {
    return {
      className: "danger",
      icon: "⛔",
      title: decision === "BLOCK"
        ? "Website blocked by IDPS Shield"
        : "High-risk website detected"
    };
  }

  if (decision === "WARN" || riskLevel === "MEDIUM") {
    return {
      className: "warn",
      icon: "⚠",
      title: "Caution advised"
    };
  }

  if (decision === "ALLOW") {
    return {
      className: "safe",
      icon: "✓",
      title: "No configured blocking indicators found"
    };
  }

  return {
    className: "warn",
    icon: "!",
    title: "Unknown security decision"
  };
}

function normalizeReasons(reasons) {
  if (!Array.isArray(reasons)) {
    return [];
  }

  return reasons
    .map((reason) => {
      if (typeof reason === "string") {
        return reason;
      }

      if (reason && typeof reason === "object") {
        return (
          reason.message ||
          reason.description ||
          reason.reason ||
          JSON.stringify(reason)
        );
      }

      return String(reason);
    })
    .filter(Boolean);
}

function displayResult(result) {
  if (!result || typeof result !== "object") {
    throw new Error("The backend returned an invalid scan result.");
  }

  const decision = String(
    result.decision || "UNKNOWN"
  ).toUpperCase();

  const riskLevel = String(
    result.risk_level || "UNKNOWN"
  ).toUpperCase();

  const style = getDecisionStyle(decision, riskLevel);

  const parsedScore = Number(result.risk_score);

  const score = Number.isFinite(parsedScore)
    ? Math.max(0, Math.min(100, parsedScore))
    : 0;

  const card = $("resultCard");

  card.className = `result ${style.className}`;

  $("resultIcon").textContent = style.icon;
  $("resultTitle").textContent = style.title;
  $("resultSubtitle").textContent =
    `${decision} · ${riskLevel} risk`;

  $("riskScore").textContent = `${score}/100`;
  $("scoreMeter").style.width = `${score}%`;

  $("scoreMeterContainer").setAttribute(
    "aria-valuenow",
    String(score)
  );

  $("scoreMeter").style.background =
    style.className === "danger"
      ? "#f87171"
      : style.className === "warn"
        ? "#fbbf24"
        : "#34d399";

  if (decision === "ALLOW") {
    $("resultExplanation").textContent =
      "The configured checks did not find a blocking condition. This does not guarantee the website is safe.";
  } else if (decision === "WARN") {
    $("resultExplanation").textContent =
      "The security engine recommends caution. Review the reported reasons.";
  } else if (decision === "BLOCK") {
    $("resultExplanation").textContent =
      "The security engine returned BLOCK. IDPS Shield will redirect this tab to its blocked page.";
  } else {
    $("resultExplanation").textContent =
      "The security engine returned an unknown decision. Do not assume this website is safe.";
  }

  const list = $("reasonList");
  list.replaceChildren();

  const reasons = normalizeReasons(result.reasons);

  if (reasons.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No specific reasons were returned.";
    list.appendChild(item);
  } else {
    for (const reason of reasons) {
      const item = document.createElement("li");
      item.textContent = reason;
      list.appendChild(item);
    }
  }

  card.classList.remove("hidden");
}

async function getCurrentTab() {
  const tabs = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  return tabs[0] || null;
}

function updateWebsiteDetails(tab) {
  currentUrl = tab?.url || "";
  currentTabId = tab?.id ?? null;

  $("resultCard").classList.add("hidden");

  if (!currentUrl) {
    $("domain").textContent = "No active website";
    $("url").textContent = "Open a website to check it.";
    setCheckButton(false);
    return;
  }

  let parsed;

  try {
    parsed = new URL(currentUrl);
  } catch {
    $("domain").textContent = "Browser internal page";
    $("url").textContent =
      "Only HTTP and HTTPS websites can be checked.";

    setCheckButton(false);
    return;
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    $("domain").textContent = parsed.hostname || "Browser page";
    $("url").textContent =
      "Only normal HTTP and HTTPS websites can be checked.";

    setCheckButton(false);
    return;
  }

  $("domain").textContent = parsed.hostname;
  $("url").textContent = currentUrl;

  setCheckButton(true);
}

async function loadPopup() {
  if (isLoading) return;

  isLoading = true;
  clearError();

  protectionToggle.disabled = true;
  setCheckButton(false, "Loading…");

  try {
    const tab = await getCurrentTab();

    updateWebsiteDetails(tab);

    const response = await chrome.runtime.sendMessage({
      type: "IDPS_GET_SETTINGS"
    });

    if (!response?.success) {
      throw new Error(
        response?.error || "Could not load extension settings."
      );
    }

    const settings = response.settings || {};

    const protectionEnabled = Boolean(
      settings.protectionEnabled
    );

    const configured = Boolean(response.configured);

    protectionToggle.checked = protectionEnabled;

    protectionToggle.disabled = false;

    if (!protectionEnabled) {
      $("protectionStatus").textContent = "Protection paused";

      $("configurationMessage").textContent = configured
        ? "Your IDPS account is connected, but navigation checks are paused."
        : "Sign in to your IDPS account to enable protection.";
    } else if (configured) {
      $("protectionStatus").textContent = "Protection enabled";

      $("configurationMessage").textContent =
        "Your IDPS account is connected and ready to scan websites.";
    } else {
      $("protectionStatus").textContent = "Sign-in required";

      $("configurationMessage").textContent =
        "Open Extension Settings and sign in to your IDPS account.";
    }

    setStatusDot(
      configured
        ? "connected"
        : "disconnected"
    );

    if (response.authStatus?.expired) {
      setStatusDot("error");

      showError(
        response.authStatus.message ||
          "Your session expired. Sign in again in Extension Settings."
      );
    }

    setCheckButton(
      configured && protectionEnabled && Boolean(currentUrl) &&
        /^https?:\/\//i.test(currentUrl)
    );

    if (!configured && protectionEnabled) {
      showError(
        "Connect your IDPS account in Extension Settings before scanning websites."
      );
    }
  } catch (error) {
    protectionToggle.disabled = true;
    setStatusDot("error");

    $("protectionStatus").textContent = "Connection error";
    $("configurationMessage").textContent =
      "Unable to load your protection settings.";

    setCheckButton(false);

    showError(
      error instanceof Error
        ? error.message
        : "Unable to load extension settings."
    );
  } finally {
    isLoading = false;
  }
}

// --------------------------------------------------
// Check current website
// --------------------------------------------------

checkButton.addEventListener("click", async () => {
  clearError();

  if (isChecking) return;

  if (!currentUrl || !/^https?:\/\//i.test(currentUrl)) {
    showError("Open a normal HTTP or HTTPS website first.");
    return;
  }

  isChecking = true;

  setCheckButton(false, "Checking website…");

  $("resultCard").classList.add("hidden");

  try {
    // The background script must use the saved access token
    // to authenticate this request with the FastAPI backend.
    const response = await chrome.runtime.sendMessage({
      type: "IDPS_CHECK_URL",
      url: currentUrl
    });

    if (!response?.success) {
      throw new Error(
        response?.error || "URL check failed."
      );
    }

    if (!response.result) {
      throw new Error(
        "The background script did not return a scan result."
      );
    }

    displayResult(response.result);

    const decision = String(
      response.result.decision || ""
    ).toUpperCase();

    if (decision === "BLOCK") {
      await redirectCurrentTabToBlockedPage(response.result);
      return;
    }
  } catch (error) {
    showError(
      error instanceof Error
        ? error.message
        : "URL check failed."
    );
  } finally {
    isChecking = false;

    // Restore the button only if the popup is still open.
    if (document.contains(checkButton)) {
      setCheckButton(
        Boolean(currentUrl) && /^https?:\/\//i.test(currentUrl)
      );
    }
  }
});

// --------------------------------------------------
// Redirect blocked website
// --------------------------------------------------

async function redirectCurrentTabToBlockedPage(result) {
  const tab = await getCurrentTab();

  if (
    !tab?.id ||
    tab.id !== currentTabId ||
    !tab.url ||
    !/^https?:\/\//i.test(tab.url)
  ) {
    throw new Error(
      "The current browser tab cannot be redirected to the blocked page."
    );
  }

  const reasons = normalizeReasons(result.reasons);

  const params = new URLSearchParams({
    url: tab.url,
    reason: reasons.length
      ? reasons.join("; ")
      : "Blocked by IDPS Shield security policy."
  });

  const blockedPageUrl = chrome.runtime.getURL(
    `blocked/blocked.html?${params.toString()}`
  );

  await chrome.tabs.update(tab.id, {
    url: blockedPageUrl
  });

  window.close();
}

// --------------------------------------------------
// Protection toggle
// --------------------------------------------------

protectionToggle.addEventListener("change", async (event) => {
  clearError();

  const toggle = event.currentTarget;
  const requestedState = toggle.checked;
  const previousState = !requestedState;

  toggle.disabled = true;

  try {
    const response = await chrome.runtime.sendMessage({
      type: "IDPS_SET_PROTECTION",
      enabled: requestedState
    });

    if (!response?.success) {
      throw new Error(
        response?.error || "Could not update protection."
      );
    }

    await loadPopup();
  } catch (error) {
    toggle.checked = previousState;

    showError(
      error instanceof Error
        ? error.message
        : "Could not update protection."
    );

    toggle.disabled = false;
  }
});

// --------------------------------------------------
// Open extension settings
// --------------------------------------------------

$("settingsButton").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

// --------------------------------------------------
// Initialize popup
// --------------------------------------------------

void loadPopup();