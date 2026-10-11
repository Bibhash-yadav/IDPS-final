
"use strict";

const DEFAULT_API_URL = "http://127.0.0.1:8000";
const $ = (id) => document.getElementById(id);

const loginForm = $("loginForm");
const settingsForm = $("settingsForm");
const message = $("message");
const loginButton = $("loginButton");
const saveButton = $("saveButton");
const disconnectButton = $("disconnectButton");

function normalizeApiUrl(value) {
  return String(value || DEFAULT_API_URL).trim().replace(/\/+$/, "");
}

function showMessage(text, type = "") {
  message.textContent = text;
  message.className = `message ${type}`.trim();
}

function setConnection(status, title, description) {
  const badge = $("statusBadge");
  const panel = $("connectionPanel");

  badge.className = "badge";
  panel.className = "connection-panel";

  if (status === "connected") {
    badge.classList.add("connected");
    badge.textContent = "Connected";
    panel.classList.add("connected");
  } else if (status === "error") {
    badge.classList.add("error");
    badge.textContent = "Needs attention";
    panel.classList.add("error");
  } else {
    badge.textContent = "Not connected";
  }

  $("statusTitle").textContent = title;
  $("statusDescription").textContent = description;
  disconnectButton.hidden = status !== "connected";
}

async function getStoredSettings() {
  return chrome.storage.local.get({
    apiUrl: DEFAULT_API_URL,
    token: "",
    age: 18,
    protectionEnabled: true
  });
}

function validateApiUrl(value) {
  let parsed;

  try {
    parsed = new URL(normalizeApiUrl(value));
  } catch {
    throw new Error("Enter a valid backend URL.");
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
    throw new Error(
      "Use HTTPS for a remote backend. HTTP is allowed only for local development."
    );
  }

  return parsed.origin;
}

async function apiRequest(apiUrl, path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(`${apiUrl}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {})
      }
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      if (response.status === 401) {
        const error = new Error(
          "Your saved session has expired or is invalid. Please sign in again."
        );
        error.status = 401;
        throw error;
      }

      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : `Request failed with HTTP ${response.status}.`
      );
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("The backend request timed out. Your saved login has been kept.");
    }

    if (error instanceof TypeError) {
      throw new Error(
        "Cannot reach the backend. Start the backend and try again. Your saved login has been kept."
      );
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function saveExtensionSettings(settings) {
  const response = await chrome.runtime.sendMessage({
    type: "IDPS_SAVE_SETTINGS",
    settings
  });

  if (!response?.success) {
    throw new Error(response?.error || "Could not save extension settings.");
  }
}

async function validateToken(apiUrl, token) {
  return apiRequest(apiUrl, "/api/auth/me", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
}

function getUserEmail(data) {
  return data?.user?.email || data?.email || "";
}

async function loadSettings() {
  const settings = await getStoredSettings();

  $("apiUrl").value = settings.apiUrl || DEFAULT_API_URL;
  $("age").value = settings.age || 18;
  $("protectionEnabled").checked = Boolean(settings.protectionEnabled);

  if (!settings.token) {
    setConnection(
      "disconnected",
      "Connection required",
      "Sign in once. Your access token will be saved in extension storage."
    );
    return;
  }

  // Keep the saved token. A temporary network failure must not log the
  // user out or delete their stored authentication.
  try {
    const apiUrl = validateApiUrl(settings.apiUrl);
    const user = await validateToken(apiUrl, settings.token);

    setConnection(
      "connected",
      `Connected${getUserEmail(user) ? ` as ${getUserEmail(user)}` : ""}`,
      "Your saved login is valid. You do not need to sign in again while the session remains valid."
    );
  } catch (error) {
    if (error.status === 401) {
      setConnection(
        "error",
        "Session expired",
        "Your saved token was rejected by the backend. Sign in again to obtain a new token."
      );
    } else {
      setConnection(
        "error",
        "Backend unavailable",
        `${error.message} Your saved login has not been deleted.`
      );
    }
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  showMessage("");

  const email = $("email").value.trim().toLowerCase();
  const password = $("password").value;
  let apiUrl;

  try {
    apiUrl = validateApiUrl($("apiUrl").value);
  } catch (error) {
    showMessage(error.message, "error");
    return;
  }

  if (!email || !password) {
    showMessage("Enter your email and password.", "error");
    return;
  }

  loginButton.disabled = true;
  loginButton.textContent = "Signing in…";

  try {
    const auth = await apiRequest(apiUrl, "/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    const token = auth.access_token;

    if (!token) {
      throw new Error("The backend did not return an access token.");
    }

    const age = Number($("age").value);

    if (!Number.isInteger(age) || age < 1 || age > 120) {
      throw new Error("Age must be an integer between 1 and 120.");
    }

    // Save the token persistently before checking the profile.
    // chrome.storage.local survives popup closure and browser restarts.
    await saveExtensionSettings({
      apiUrl,
      token,
      age,
      protectionEnabled: $("protectionEnabled").checked
    });

    $("password").value = "";

    try {
      const user = await validateToken(apiUrl, token);

      setConnection(
        "connected",
        `Connected${getUserEmail(user) ? ` as ${getUserEmail(user)}` : ""}`,
        "Your login has been saved. You can close this page and continue browsing."
      );

      showMessage("Signed in successfully. Your login is saved.", "success");
    } catch (validationError) {
      // Do not discard a successfully issued token because the profile
      // endpoint is temporarily unavailable.
      if (validationError.status === 401) {
        await chrome.storage.local.set({ token: "" });
        throw validationError;
      }

      setConnection(
        "error",
        "Login saved; backend unavailable",
        "Your token is saved, but the account could not be verified. Check the backend connection."
      );

      showMessage(
        "Login token saved, but account verification failed. Check the backend and reopen settings.",
        "error"
      );
    }
  } catch (error) {
    showMessage(error.message || "Sign-in failed.", "error");

    if (error.status === 401) {
      setConnection("error", "Sign-in failed", error.message);
    }
  } finally {
    loginButton.disabled = false;
    loginButton.textContent = "Sign in and connect";
  }
});

settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  showMessage("");

  saveButton.disabled = true;

  try {
    const apiUrl = validateApiUrl($("apiUrl").value);
    const age = Number($("age").value);
    const protectionEnabled = $("protectionEnabled").checked;

    if (!Number.isInteger(age) || age < 1 || age > 120) {
      throw new Error("Age must be an integer between 1 and 120.");
    }

    const stored = await getStoredSettings();
    const apiUrlChanged = apiUrl !== normalizeApiUrl(stored.apiUrl);

    if (stored.token && apiUrlChanged) {
      await validateToken(apiUrl, stored.token);
    }

    // Update preferences without overwriting or deleting the saved token.
    await saveExtensionSettings({
      apiUrl,
      token: stored.token,
      age,
      protectionEnabled
    });

    showMessage("Protection settings saved. Your saved login was preserved.", "success");
    await loadSettings();
  } catch (error) {
    showMessage(error.message || "Could not save settings.", "error");
  } finally {
    saveButton.disabled = false;
  }
});

disconnectButton.addEventListener("click", async () => {
  disconnectButton.disabled = true;

  try {
    const settings = await getStoredSettings();

    await saveExtensionSettings({
      apiUrl: settings.apiUrl,
      token: "",
      age: settings.age,
      protectionEnabled: settings.protectionEnabled
    });

    setConnection(
      "disconnected",
      "Disconnected",
      "Your saved access token was removed. Sign in again whenever you want to reconnect."
    );

    showMessage("Disconnected from your IDPS account.", "success");
  } catch (error) {
    showMessage(error.message || "Could not disconnect.", "error");
  } finally {
    disconnectButton.disabled = false;
  }
});

void loadSettings();
