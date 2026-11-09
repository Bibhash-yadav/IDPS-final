"use strict";

// IDPS Shield — Extension Options
// Authentication uses the backend's mandatory two-factor flow.
// Age-based policies remain handled by the backend.

const DEFAULT_API_URL = "https://idps-backend-485j.onrender.com";

const $ = (id) => document.getElementById(id);

const loginForm = $("loginForm");
const settingsForm = $("settingsForm");
const message = $("message");

const loginButton = $("loginButton");
const verifyButton = $("verifyButton");
const resendButton = $("resendButton");
const backToLoginButton = $("backToLoginButton");
const saveButton = $("saveButton");
const disconnectButton = $("disconnectButton");

const credentialsSection = $("credentialsSection");
const twoFactorSection = $("twoFactorSection");

// Keep the short-lived challenge token in memory.
// Never save a challenge token as the user's access token.
let challengeToken = "";
let availableMethods = [];

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

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      if (response.status === 401) {
        const error = new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Your session has expired or is invalid. Please sign in again."
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
      } else if (typeof data.message === "string") {
        errorMessage = data.message;
      }

      const error = new Error(errorMessage);
      error.status = response.status;
      throw error;
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(
        "The backend request timed out. Please try again."
      );
    }

    if (error instanceof TypeError) {
      throw new Error(
        "Cannot reach the backend. Check the backend URL and internet connection."
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
      response?.error || "Could not save extension settings."
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

function resetTwoFactor() {
  challengeToken = "";
  availableMethods = [];

  credentialsSection.hidden = false;
  twoFactorSection.hidden = true;

  $("verificationCode").value = "";
  $("password").value = "";

  resendButton.hidden = true;
  resendButton.disabled = false;
  verifyButton.disabled = false;

  loginButton.disabled = false;
  loginButton.textContent = "Sign in and continue";
}

function showTwoFactor(auth) {
  challengeToken = auth.challenge_token;
  availableMethods = Array.isArray(auth.available_methods)
    ? auth.available_methods
    : [];

  if (!challengeToken) {
    throw new Error(
      "The backend did not return a 2FA challenge token."
    );
  }

  credentialsSection.hidden = true;
  twoFactorSection.hidden = false;

  $("verificationCode").value = "";

  const supportsEmail = availableMethods.includes("email");
  const supportsTotp = availableMethods.includes("totp");

  if (supportsEmail && supportsTotp) {
    $("twoFactorDescription").textContent =
      "Enter the code from your configured verification method.";
  } else if (supportsEmail) {
    $("twoFactorDescription").textContent =
      "Enter the verification code sent to your registered email address.";
  } else if (supportsTotp) {
    $("twoFactorDescription").textContent =
      "Open your authenticator app and enter the current verification code.";
  } else {
    $("twoFactorDescription").textContent =
      "Enter the verification code requested by your IDPS account.";
  }

  resendButton.hidden = !supportsEmail;

  showMessage(
    auth.message || "Two-factor verification is required to sign in.",
    "success"
  );

  $("verificationCode").focus();
}

function getBearerHeaders(token) {
  return {
    Authorization: `Bearer ${token}`
  };
}

async function completeLogin(accessToken, apiUrl) {
  if (!accessToken) {
    throw new Error(
      "The backend did not return an access token after verification."
    );
  }

  // Validate the actual access token before saving it.
  const user = await validateToken(apiUrl, accessToken);
  const userEmail = getUserEmail(user);

  // Save only the verified access token.
  await saveExtensionSettings({
    apiUrl,
    token: accessToken,
    protectionEnabled: $("protectionEnabled").checked
  });

  $("password").value = "";
  $("verificationCode").value = "";

  challengeToken = "";
  availableMethods = [];

  credentialsSection.hidden = false;
  twoFactorSection.hidden = true;

  setConnection(
    "connected",
    userEmail ? `Connected as ${userEmail}` : "Connected",
    "Your login has been verified and saved. You can close this page and continue browsing."
  );

  showMessage(
    "Two-factor verification successful. Your account is connected.",
    "success"
  );
}

// --------------------------------------------------
// Load settings and validate existing login
// --------------------------------------------------

async function loadSettings() {
  const settings = await getStoredSettings();

  $("apiUrl").value = settings.apiUrl || DEFAULT_API_URL;

  $("protectionEnabled").checked =
    Boolean(settings.protectionEnabled);

  if (!settings.token) {
    setConnection(
      "disconnected",
      "Connection required",
      "Sign in to connect this extension. Two-factor verification will be required."
    );

    return;
  }

  // A temporary network failure must not delete
  // the user's saved authentication token.
  try {
    const apiUrl = validateApiUrl(settings.apiUrl);

    const user = await validateToken(apiUrl, settings.token);
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
// Step 1: Email and password login
// --------------------------------------------------

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

    // Backend requires 2FA before issuing an access token.
    if (auth.requires_two_factor) {
      showTwoFactor(auth);
      return;
    }

    // Compatibility fallback if the backend is configured
    // to return an access token directly.
    if (auth.access_token) {
      await completeLogin(auth.access_token, apiUrl);
      return;
    }

    throw new Error(
      "Unexpected login response. The backend did not return a 2FA challenge or access token."
    );
  } catch (error) {
    showMessage(error.message || "Sign-in failed.", "error");

    if (error.status === 401) {
      setConnection(
        "error",
        "Sign-in failed",
        error.message
      );
    }
  } finally {
    loginButton.disabled = false;
    loginButton.textContent = "Sign in and continue";
  }
});

// --------------------------------------------------
// Step 2: Verify 2FA code
// --------------------------------------------------

verifyButton.addEventListener("click", async () => {
  showMessage("");

  const code = $("verificationCode").value.trim();

  if (!challengeToken) {
    showMessage(
      "Your verification session has expired. Please sign in again.",
      "error"
    );

    resetTwoFactor();
    return;
  }

  if (!code) {
    showMessage("Enter your verification code.", "error");
    $("verificationCode").focus();
    return;
  }

  let apiUrl;

  try {
    apiUrl = validateApiUrl($("apiUrl").value);
  } catch (error) {
    showMessage(error.message, "error");
    return;
  }

  verifyButton.disabled = true;
  verifyButton.textContent = "Verifying…";

  try {
    const result = await apiRequest(
      apiUrl,
      "/api/auth/verify-2fa",
      {
        method: "POST",
        headers: getBearerHeaders(challengeToken),
        body: JSON.stringify({
          code
        })
      }
    );

    await completeLogin(result.access_token, apiUrl);
  } catch (error) {
    showMessage(
      error.message || "Two-factor verification failed.",
      "error"
    );

    if (error.status === 401) {
      challengeToken = "";

      showMessage(
        "Your verification session expired or was rejected. Please sign in again.",
        "error"
      );

      resetTwoFactor();
    }
  } finally {
    verifyButton.disabled = false;
    verifyButton.textContent = "Verify and connect";
  }
});

// Allow Enter to submit the verification code.
$("verificationCode").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    verifyButton.click();
  }
});

// --------------------------------------------------
// Resend email verification code
// --------------------------------------------------

resendButton.addEventListener("click", async () => {
  showMessage("");

  if (!challengeToken) {
    showMessage(
      "Your verification session has expired. Please sign in again.",
      "error"
    );

    resetTwoFactor();
    return;
  }

  if (!availableMethods.includes("email")) {
    showMessage(
      "Email verification is not available for this login.",
      "error"
    );
    return;
  }

  let apiUrl;

  try {
    apiUrl = validateApiUrl($("apiUrl").value);
  } catch (error) {
    showMessage(error.message, "error");
    return;
  }

  resendButton.disabled = true;
  resendButton.textContent = "Sending…";

  try {
    const result = await apiRequest(
      apiUrl,
      "/api/auth/2fa/resend-email",
      {
        method: "POST",
        headers: getBearerHeaders(challengeToken)
      }
    );

    showMessage(
      result.message || "A new verification code has been requested.",
      "success"
    );
  } catch (error) {
    showMessage(
      error.message || "Could not resend the verification code.",
      "error"
    );

    if (error.status === 401) {
      resetTwoFactor();
    }
  } finally {
    resendButton.disabled = false;
    resendButton.textContent = "Resend email code";
  }
});

// --------------------------------------------------
// Return to login
// --------------------------------------------------

backToLoginButton.addEventListener("click", () => {
  resetTwoFactor();
  showMessage("Enter your login details to start again.");
});

// --------------------------------------------------
// Save protection settings
// --------------------------------------------------

settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  showMessage("");

  saveButton.disabled = true;
  saveButton.textContent = "Saving…";

  try {
    const apiUrl = validateApiUrl($("apiUrl").value);
    const protectionEnabled = $("protectionEnabled").checked;

    const stored = await getStoredSettings();

    const previousApiUrl = validateApiUrl(stored.apiUrl);

    const apiUrlChanged = apiUrl !== previousApiUrl;

    // Verify the existing access token against a newly selected backend.
    if (stored.token && apiUrlChanged) {
      await validateToken(apiUrl, stored.token);
    }

    // Preserve the saved account token.
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
    saveButton.textContent = "Save protection settings";
  }
});

// --------------------------------------------------
// Disconnect account
// --------------------------------------------------

disconnectButton.addEventListener("click", async () => {
  disconnectButton.disabled = true;

  try {
    const settings = await getStoredSettings();

    await saveExtensionSettings({
      apiUrl: settings.apiUrl,
      token: "",
      protectionEnabled: settings.protectionEnabled
    });

    $("password").value = "";
    $("verificationCode").value = "";

    resetTwoFactor();

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
});

// --------------------------------------------------
// Initialize extension settings
// --------------------------------------------------

void loadSettings().catch((error) => {
  showMessage(
    error.message || "Could not load settings.",
    "error"
  );
});