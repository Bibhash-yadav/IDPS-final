
"use strict";

const DEFAULT_API_URL = "https://idps-backend-485j.onrender.com";
const CHECK_COOLDOWN_MS = 10_000;
const MAX_RECENT_CHECKS = 200;
const REQUEST_TIMEOUT_MS = 15_000;

const recentChecks = new Map();
const pendingChecks = new Map();

function normalizeApiUrl(value) {
  return String(value || DEFAULT_API_URL)
    .trim()
    .replace(/\/+$/, "");
}

function isWebUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function isLocalDevelopmentUrl(value) {
  try {
    const hostname = new URL(value).hostname.toLowerCase();

    return [
      "localhost",
      "127.0.0.1",
      "[::1]",
      "::1",
    ].includes(hostname);
  } catch {
    return true;
  }
}

/**
 * Age is intentionally excluded from extension settings.
 * Age-based rules should use the authenticated user's account data.
 */
async function getSettings() {
  const settings = await chrome.storage.local.get({
    apiUrl: DEFAULT_API_URL,
    token: "",
    protectionEnabled: true,
  });

  return {
    ...settings,
    apiUrl: normalizeApiUrl(settings.apiUrl),
    token: String(settings.token || "").trim(),
    protectionEnabled: Boolean(settings.protectionEnabled),
  };
}

/**
 * Demonstration URLs only. These results do not indicate live threat
 * intelligence or prove that any other URL is malicious.
 */
function getSafeBrowsingTestResult(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const host = url.hostname.toLowerCase();
    const path = url.pathname.replace(/\/+$/, "").toUpperCase();

    if (
      host === "testsafebrowsing.appspot.com" &&
      path === "/APIV4/ANY_PLATFORM/MALWARE/URL"
    ) {
      return {
        decision: "BLOCK",
        risk_level: "HIGH",
        risk_score: 85,
        reasons: [
          "IDPS Shield demonstration: Safe Browsing malware test URL.",
        ],
        test_mode: true,
      };
    }

    if (
      host === "testsafebrowsing.appspot.com" &&
      path === "/APIV4/ANY_PLATFORM/PHISHING/URL"
    ) {
      return {
        decision: "WARN",
        risk_level: "HIGH",
        risk_score: 70,
        reasons: [
          "IDPS Shield demonstration: Safe Browsing phishing test URL.",
        ],
        test_mode: true,
      };
    }
  } catch {
    // Normal URL validation handles invalid URLs.
  }

  return null;
}

async function apiFetch(path, options = {}) {
  const settings = await getSettings();
  const controller = new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    REQUEST_TIMEOUT_MS
  );

  try {
    const response = await fetch(`${settings.apiUrl}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(options.body
          ? { "Content-Type": "application/json" }
          : {}),
        ...(settings.token
          ? { Authorization: `Bearer ${settings.token}` }
          : {}),
        ...(options.headers || {}),
      },
    });

    const data = await response.json().catch(() => ({}));

    if (response.status === 401) {
      await chrome.storage.session.set({
        authStatus: {
          expired: true,
          message:
            "Your IDPS session expired. Sign in again in Extension Settings.",
        },
      });

      throw new Error(
        "Your IDPS session is invalid or expired. Sign in again in Extension Settings."
      );
    }

    if (!response.ok) {
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : `IDPS API returned HTTP ${response.status}.`
      );
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("The IDPS backend request timed out.");
    }

    if (error instanceof TypeError) {
      throw new Error(
        "Cannot reach the IDPS backend. Check the API URL and ensure the backend is running."
      );
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * The extension does not collect or send a manually selected age.
 * The backend should resolve the authenticated account and its DOB.
 */
async function checkUrl(rawUrl) {
  if (!isWebUrl(rawUrl)) {
    throw new Error("Only HTTP and HTTPS URLs can be checked.");
  }

  const settings = await getSettings();

  if (!settings.token) {
    throw new Error(
      "IDPS account not connected. Open Extension Settings and sign in."
    );
  }

  if (!settings.protectionEnabled) {
    throw new Error(
      "Navigation protection is disabled in Extension Settings."
    );
  }

  const testResult = getSafeBrowsingTestResult(rawUrl);

  if (testResult) {
    return testResult;
  }

  // Do not send age. The backend must use the authenticated user's profile.
  const result = await apiFetch("/api/url/check", {
    method: "POST",
    body: JSON.stringify({ url: rawUrl }),
  });

  const decision = String(result.decision || "").toUpperCase();

  if (!["ALLOW", "WARN", "BLOCK"].includes(decision)) {
    throw new Error(
      "The IDPS backend returned an invalid security decision."
    );
  }

  await chrome.storage.session.remove("authStatus");

  return {
    ...result,
    decision,
  };
}

async function saveTabResult(tabId, url, result) {
  await chrome.storage.session.set({
    [`lastResult_${tabId}`]: {
      url,
      result,
      checkedAt: new Date().toISOString(),
    },
  });

  await chrome.storage.session.remove(`lastError_${tabId}`);
}

async function saveTabError(tabId, url, error) {
  await chrome.storage.session.set({
    [`lastError_${tabId}`]: {
      url,
      message: error.message || "URL check failed.",
      checkedAt: new Date().toISOString(),
    },
  });
}

function rememberCheck(key) {
  recentChecks.set(key, Date.now());

  while (recentChecks.size > MAX_RECENT_CHECKS) {
    const oldestKey = recentChecks.keys().next().value;

    if (oldestKey === undefined) break;

    recentChecks.delete(oldestKey);
  }
}

async function showSecurityNotification(url, result) {
  if (!chrome.notifications?.create) {
    console.warn("IDPS notifications are unavailable.");
    return;
  }

  const decision = String(result.decision || "").toUpperCase();

  if (!["WARN", "BLOCK"].includes(decision)) {
    return;
  }

  let hostname = url;

  try {
    hostname = new URL(url).hostname;
  } catch {
    // Retain the original URL.
  }

  const reasons = Array.isArray(result.reasons)
    ? result.reasons.filter(Boolean).join(" ")
    : "";

  const message =
    decision === "BLOCK"
      ? `IDPS Shield blocked ${hostname}. ${reasons}`.trim()
      : `IDPS Shield detected a suspicious website: ${hostname}. ${reasons}`.trim();

  try {
    await chrome.notifications.create(`idps-${Date.now()}`, {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title:
        decision === "BLOCK"
          ? "IDPS Shield: Website blocked"
          : "IDPS Shield: Security warning",
      message: message.slice(0, 500),
      priority: 2,
    });
  } catch (error) {
    console.warn("Could not display IDPS notification:", error);
  }
}

async function redirectToBlockedPage(tabId, url, result) {
  const tab = await chrome.tabs.get(tabId).catch(() => null);

  // Do not redirect a tab that has already navigated elsewhere.
  if (!tab || tab.url !== url) {
    return;
  }

  const params = new URLSearchParams({
    url,
    reason: Array.isArray(result.reasons)
      ? result.reasons.join("; ")
      : "Blocked by IDPS Shield security policy.",
  });

  const blockedUrl = chrome.runtime.getURL(
    `blocked/blocked.html?${params.toString()}`
  );

  await chrome.tabs.update(tabId, {
    url: blockedUrl,
  });
}

/**
 * Navigation checks run after navigation commits. A BLOCK decision
 * redirects the tab; this does not prevent the first request from loading.
 */
async function assessNavigation(tabId, url) {
  if (!isWebUrl(url) || isLocalDevelopmentUrl(url)) {
    return;
  }

  const settings = await getSettings();

  if (!settings.protectionEnabled || !settings.token) {
    return;
  }

  const key = `${tabId}:${url}`;
  const previous = recentChecks.get(key);

  if (previous && Date.now() - previous < CHECK_COOLDOWN_MS) {
    return;
  }

  if (pendingChecks.has(key)) {
    return pendingChecks.get(key);
  }

  const task = (async () => {
    try {
      const result = await checkUrl(url);

      rememberCheck(key);
      await saveTabResult(tabId, url, result);

      if (result.decision === "WARN" || result.decision === "BLOCK") {
        await showSecurityNotification(url, result);
      }

      if (result.decision === "BLOCK") {
        await redirectToBlockedPage(tabId, url, result);
      }
    } catch (error) {
      console.error("IDPS navigation assessment failed:", error);
      await saveTabError(tabId, url, error);
    } finally {
      pendingChecks.delete(key);
    }
  })();

  pendingChecks.set(key, task);

  return task;
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;

  void assessNavigation(details.tabId, details.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  const prefix = `${tabId}:`;

  for (const key of recentChecks.keys()) {
    if (key.startsWith(prefix)) {
      recentChecks.delete(key);
    }
  }

  for (const key of pendingChecks.keys()) {
    if (key.startsWith(prefix)) {
      pendingChecks.delete(key);
    }
  }

  void chrome.storage.session.remove([
    `lastResult_${tabId}`,
    `lastError_${tabId}`,
  ]);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "IDPS_CHECK_URL") {
    (async () => {
      try {
        const result = await checkUrl(message.url);

        sendResponse({
          success: true,
          result,
        });
      } catch (error) {
        sendResponse({
          success: false,
          error: error.message || "URL check failed.",
        });
      }
    })();

    return true;
  }

  if (message?.type === "IDPS_GET_SETTINGS") {
    (async () => {
      try {
        const settings = await getSettings();
        const { token, ...safeSettings } = settings;
        const authStatus = await chrome.storage.session.get("authStatus");

        sendResponse({
          success: true,
          settings: safeSettings,
          configured: Boolean(token),
          authStatus: authStatus.authStatus || null,
        });
      } catch (error) {
        sendResponse({
          success: false,
          error: error.message || "Could not read settings.",
        });
      }
    })();

    return true;
  }

  if (message?.type === "IDPS_SAVE_SETTINGS") {
    (async () => {
      try {
        const input = message.settings || {};
        const apiUrl = normalizeApiUrl(
          input.apiUrl || DEFAULT_API_URL
        );

        let parsed;

        try {
          parsed = new URL(apiUrl);
        } catch {
          throw new Error("Enter a valid backend API URL.");
        }

        if (!["http:", "https:"].includes(parsed.protocol)) {
          throw new Error("The backend URL must use HTTP or HTTPS.");
        }

        if (parsed.username || parsed.password) {
          throw new Error("Do not put credentials in the backend URL.");
        }

        if (
          parsed.protocol === "http:" &&
          !["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)
        ) {
          throw new Error("Use HTTPS for a remote backend.");
        }

        const token = String(input.token || "").trim();

        // Age is intentionally not saved.
        await chrome.storage.local.set({
          apiUrl,
          token,
          protectionEnabled: Boolean(input.protectionEnabled),
        });

        await chrome.storage.session.clear();
        recentChecks.clear();
        pendingChecks.clear();

        sendResponse({
          success: true,
        });
      } catch (error) {
        sendResponse({
          success: false,
          error: error.message || "Could not save settings.",
        });
      }
    })();

    return true;
  }

  if (message?.type === "IDPS_SET_PROTECTION") {
    (async () => {
      try {
        await chrome.storage.local.set({
          protectionEnabled: Boolean(message.enabled),
        });

        recentChecks.clear();
        pendingChecks.clear();

        sendResponse({
          success: true,
        });
      } catch (error) {
        sendResponse({
          success: false,
          error: error.message || "Could not update protection.",
        });
      }
    })();

    return true;
  }

  if (message?.type === "IDPS_GET_LAST_RESULT") {
    (async () => {
      try {
        const tabId = Number(message.tabId);

        if (!Number.isInteger(tabId)) {
          throw new Error("Invalid browser tab ID.");
        }

        const values = await chrome.storage.session.get([
          `lastResult_${tabId}`,
          `lastError_${tabId}`,
        ]);

        sendResponse({
          success: true,
          result: values[`lastResult_${tabId}`] || null,
          error: values[`lastError_${tabId}`] || null,
        });
      } catch (error) {
        sendResponse({
          success: false,
          error: error.message || "Could not retrieve the last result.",
        });
      }
    })();

    return true;
  }

  return false;
});
