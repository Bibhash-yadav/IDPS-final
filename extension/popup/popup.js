
"use strict";

const $ = (id) => document.getElementById(id);

let currentUrl = "";
let isChecking = false;

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

function getDecisionStyle(decision, riskLevel) {
  if (decision === "BLOCK" || ["HIGH", "CRITICAL"].includes(riskLevel)) {
    return {
      className: "danger",
      icon: "⛔",
      title: decision === "BLOCK"
        ? "Website blocked by IDPS Shield"
        : "High-risk website detected",
    };
  }

  if (decision === "WARN" || riskLevel === "MEDIUM") {
    return {
      className: "warn",
      icon: "⚠",
      title: "Caution advised",
    };
  }

  if (decision === "ALLOW") {
    return {
      className: "safe",
      icon: "✓",
      title: "No configured blocking indicators found",
    };
  }

  return {
    className: "warn",
    icon: "!",
    title: "Unknown security decision",
  };
}

function displayResult(result) {
  const decision = String(result?.decision || "UNKNOWN").toUpperCase();
  const riskLevel = String(result?.risk_level || "UNKNOWN").toUpperCase();
  const style = getDecisionStyle(decision, riskLevel);

  const parsedScore = Number(result?.risk_score);
  const score = Number.isFinite(parsedScore)
    ? Math.max(0, Math.min(100, parsedScore))
    : 0;

  const card = $("resultCard");

  card.className = `result ${style.className}`;

  $("resultIcon").textContent = style.icon;
  $("resultTitle").textContent = style.title;
  $("resultSubtitle").textContent = `${decision} · ${riskLevel} risk`;
  $("riskScore").textContent = `${score}/100`;
  $("scoreMeter").style.width = `${score}%`;

  $("scoreMeter").style.background =
    style.className === "danger"
      ? "#f87171"
      : style.className === "warn"
        ? "#fbbf24"
        : "#34d399";

  $("resultExplanation").textContent =
    decision === "ALLOW"
      ? "The configured checks did not find a blocking condition. This does not guarantee the website is safe."
      : decision === "WARN"
        ? "The security engine recommends caution. Review the reported reasons."
        : decision === "BLOCK"
          ? "The security engine returned BLOCK. IDPS Shield will redirect this tab to its blocked page."
          : "The security engine returned an unknown decision. Do not assume this website is safe.";

  const list = $("reasonList");
  list.replaceChildren();

  const reasons = Array.isArray(result?.reasons)
    ? result.reasons
    : [];

  if (reasons.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No specific reasons were returned.";
    list.appendChild(item);
  } else {
    for (const reason of reasons) {
      const item = document.createElement("li");
      item.textContent = String(reason);
      list.appendChild(item);
    }
  }

  card.classList.remove("hidden");
}

async function getCurrentTab() {
  const tabs = await chrome.tabs.query({
    active: true,
    currentWindow: true,
  });

  return tabs[0] || null;
}

async function loadPopup() {
  clearError();

  try {
    const tab = await getCurrentTab();

    currentUrl = tab?.url || "";

    if (currentUrl) {
      try {
        const parsed = new URL(currentUrl);

        $("domain").textContent = parsed.hostname;
        $("url").textContent = currentUrl;
      } catch {
        $("domain").textContent = "Browser internal page";
        $("url").textContent =
          "Only HTTP and HTTPS websites can be checked.";
      }
    } else {
      $("domain").textContent = "No active website";
      $("url").textContent = "Open an HTTP or HTTPS website first.";
    }

    const response = await chrome.runtime.sendMessage({
      type: "IDPS_GET_SETTINGS",
    });

    if (!response?.success) {
      throw new Error(
        response?.error || "Could not load extension settings."
      );
    }

    const protectionEnabled = Boolean(
      response.settings?.protectionEnabled
    );
    const configured = Boolean(response.configured);

    $("protectionToggle").checked = protectionEnabled;

    $("protectionStatus").textContent = !protectionEnabled
      ? "Protection paused"
      : configured
        ? "Protection enabled"
        : "Sign-in required";

    $("configurationMessage").textContent = configured
      ? "Backend token configured."
      : "Open Extension Settings and sign in to your IDPS account.";

    $("statusDot").classList.toggle(
      "active",
      protectionEnabled && configured
    );

    if (response.authStatus?.expired) {
      showError(
        response.authStatus.message ||
          "Your session expired. Sign in again in Extension Settings."
      );
    }
  } catch (error) {
    showError(
      error instanceof Error
        ? error.message
        : "Unable to load extension settings."
    );
  }
}

async function redirectCurrentTabToBlockedPage(result) {
  const tab = await getCurrentTab();

  if (!tab?.id || !tab.url || !/^https?:\/\//i.test(tab.url)) {
    throw new Error(
      "The current browser tab cannot be redirected to the blocked page."
    );
  }

  const params = new URLSearchParams({
    url: tab.url,
    reason: Array.isArray(result.reasons)
      ? result.reasons.join("; ")
      : "Blocked by IDPS Shield security policy.",
  });

  await chrome.tabs.update(tab.id, {
    url: chrome.runtime.getURL(
      `blocked/blocked.html?${params.toString()}`
    ),
  });

  window.close();
}

$("checkButton").addEventListener("click", async () => {
  clearError();

  if (isChecking) return;

  if (!currentUrl || !/^https?:\/\//i.test(currentUrl)) {
    showError("Open a normal HTTP or HTTPS website first.");
    return;
  }

  isChecking = true;
  $("checkButton").disabled = true;
  $("checkButton").textContent = "Checking website…";

  try {
    const response = await chrome.runtime.sendMessage({
      type: "IDPS_CHECK_URL",
      url: currentUrl,
    });

    if (!response?.success) {
      throw new Error(response?.error || "URL check failed.");
    }

    const result = response.result;
    displayResult(result);

    if (
      String(result?.decision || "").toUpperCase() === "BLOCK"
    ) {
      await redirectCurrentTabToBlockedPage(result);
    }
  } catch (error) {
    showError(
      error instanceof Error ? error.message : "URL check failed."
    );
  } finally {
    isChecking = false;

    const checkButton = $("checkButton");

    if (checkButton) {
      checkButton.disabled = false;
      checkButton.textContent = "Check Current Website";
    }
  }
});

$("protectionToggle").addEventListener("change", async (event) => {
  clearError();

  const toggle = event.currentTarget;
  const requestedState = toggle.checked;

  toggle.disabled = true;

  try {
    const response = await chrome.runtime.sendMessage({
      type: "IDPS_SET_PROTECTION",
      enabled: requestedState,
    });

    if (!response?.success) {
      throw new Error(
        response?.error || "Could not update protection."
      );
    }

    await loadPopup();
  } catch (error) {
    toggle.checked = !requestedState;

    showError(
      error instanceof Error
        ? error.message
        : "Could not update protection."
    );
  } finally {
    toggle.disabled = false;
  }
});

$("settingsButton").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

void loadPopup();
