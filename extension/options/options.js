
"use strict";

// IDPS Shield — Extension Options
// Age-based policies are handled by the backend using
// the authenticated user's registered date of birth.

const DEFAULT_API_URL = "https://idps-backend-485j.onrender.com";

const $ = (id) => document.getElementById(id);

const loginForm = $("loginForm");
const settingsForm = $("settingsForm");
const message = $("message");
const loginButton = $("loginButton");
const saveButton = $("saveButton");
const disconnectButton = $("disconnectButton");

function normalizeApiUrl(value) {
  return String(value || DEFAULT_API_URL)
    .trim()
    .replace(/\/+$/, "");
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
    badge.classList.add("pending");
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
    throw new Error(
      "The backend URL must use HTTP or HTTPS."
    );
  }

  if (parsed.username || parsed.password) {
    throw new Error(
      "Do not put credentials in the backend URL."
    );
  }

  if (
    parsed.protocol === "http:" &&
    !["localhost", "127.0.0.1", "[::1]"].includes(
      parsed.hostname
    )
  ) {
    throw new Error(
      "Use HTTPS for a remote backend. HTTP is allowed only for local development."
    );
  }

  return parsed.origin;
}

async function apiRequest(apiUrl, path, options = {}) {
  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, 15000);

  try {
    const response = await fetch(`${apiUrl}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(options.body
          ? { "Content-Type": "application/json" }
          : {}),
        ...(options.headers || {})
      }
    });

    const data = await response
      .json()
      .catch(() => ({}));

    if (!response.ok) {
      if (response.status === 401) {
        const error = new Error(
          "Your session has expired or is invalid. Please sign in again."
        );

        error.status = 401;
        throw error;
      }

      let errorMessage =
        `Request failed with HTTP ${response.status}.`;

      if (typeof data.detail === "string") {
        errorMessage = data.detail;
      } else if (Array.isArray(data.detail)) {
        errorMessage = data.detail
          .map((item) => item.msg || "Validation error")
          .join(", ");
      }

      throw new Error(errorMessage);
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(
        "The backend request timed out. Your saved login has been kept."
      );
    }

    if (error instanceof TypeError) {
      throw new Error(
        "Cannot reach the backend. Check the backend URL and internet connection. Your saved login has been kept."
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
    throw new Error(
      response?.error ||
      "Could not save extension settings."
    );
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

  $("apiUrl").value =
    settings.apiUrl || DEFAULT_API_URL;

  $("protectionEnabled").checked =
    Boolean(settings.protectionEnabled);

  if (!settings.token) {
    setConnection(
      "disconnected",
      "Connection required",
      "Sign in once. Your access token will be saved in extension storage."
    );

    return;
  }

  // A temporary network failure must not delete
  // the user's saved authentication token.
  try {
    const apiUrl = validateApiUrl(settings.apiUrl);

    const user = await validateToken(
      apiUrl,
      settings.token
    );

    const email = getUserEmail(user);

    setConnection(
      "connected",
      email ? `Connected as ${email}` : "Connected",
      "Your saved login is valid. You can continue browsing with protection enabled."
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

// --------------------------------------------------
// Login
// --------------------------------------------------

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  showMessage("");

  const email = $("email").value
    .trim()
    .toLowerCase();

  const password = $("password").value;

  let apiUrl;

  try {
    apiUrl = validateApiUrl($("apiUrl").value);
  } catch (error) {
    showMessage(error.message, "error");
    return;
  }

  if (!email || !password) {
    showMessage(
      "Enter your email and password.",
      "error"
    );
    return;
  }

  loginButton.disabled = true;
  loginButton.textContent = "Signing in…";

  try {
    const auth = await apiRequest(
      apiUrl,
      "/api/auth/login",
      {
        method: "POST",
        body: JSON.stringify({
          email,
          password
        })
      }
    );

    const token = auth.access_token;

    if (!token) {
      throw new Error(
        "The backend did not return an access token."
      );
    }

    // Save the account token and protection settings.
    // Age is NOT collected or stored by the extension.
    await saveExtensionSettings({
      apiUrl,
      token,
      protectionEnabled:
        $("protectionEnabled").checked
    });

    $("password").value = "";

    try {
      const user = await validateToken(
        apiUrl,
        token
      );

      const userEmail = getUserEmail(user);

      setConnection(
        "connected",
        userEmail
          ? `Connected as ${userEmail}`
          : "Connected",
        "Your login has been saved. You can close this page and continue browsing."
      );

      showMessage(
        "Signed in successfully. Your login is saved.",
        "success"
      );
    } catch (validationError) {
      if (validationError.status === 401) {
        await chrome.storage.local.set({
          token: ""
        });

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
    showMessage(
      error.message || "Sign-in failed.",
      "error"
    );

    if (error.status === 401) {
      setConnection(
        "error",
        "Sign-in failed",
        error.message
      );
    }
  } finally {
    loginButton.disabled = false;
    loginButton.textContent = "Sign in and connect";
  }
});

// --------------------------------------------------
// Save protection settings
// --------------------------------------------------

settingsForm.addEventListener(
  "submit",
  async (event) => {
    event.preventDefault();
    showMessage("");

    saveButton.disabled = true;

    try {
      const apiUrl = validateApiUrl(
        $("apiUrl").value
      );

      const protectionEnabled =
        $("protectionEnabled").checked;

      const stored = await getStoredSettings();

      const apiUrlChanged =
        apiUrl !== normalizeApiUrl(stored.apiUrl);

      // Verify that the saved token also works
      // against a newly selected backend.
      if (stored.token && apiUrlChanged) {
        await validateToken(apiUrl, stored.token);
      }

      // Save settings without overwriting
      // or deleting the account token.
      await saveExtensionSettings({
        apiUrl,
        token: stored.token,
        protectionEnabled
      });

      showMessage(
        "Protection settings saved. Your saved login was preserved.",
        "success"
      );

      await loadSettings();
    } catch (error) {
      showMessage(
        error.message || "Could not save settings.",
        "error"
      );
    } finally {
      saveButton.disabled = false;
    }
  }
);

// --------------------------------------------------
// Disconnect account
// --------------------------------------------------

disconnectButton.addEventListener(
  "click",
  async () => {
    disconnectButton.disabled = true;

    try {
      const settings = await getStoredSettings();

      await saveExtensionSettings({
        apiUrl: settings.apiUrl,
        token: "",
        protectionEnabled:
          settings.protectionEnabled
      });

      $("password").value = "";

      setConnection(
        "disconnected",
        "Disconnected",
        "Your saved access token was removed. Sign in again whenever you want to reconnect."
      );

      showMessage(
        "Disconnected from your IDPS account.",
        "success"
      );
    } catch (error) {
      showMessage(
        error.message || "Could not disconnect.",
        "error"
      );
    } finally {
      disconnectButton.disabled = false;
    }
  }
);

// --------------------------------------------------
// Initialize extension settings
// --------------------------------------------------

void loadSettings().catch((error) => {
  showMessage(
    error.message || "Could not load settings.",
    "error"
  );
});
