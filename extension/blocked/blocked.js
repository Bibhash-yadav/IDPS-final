
"use strict";

// ==========================================
// IDPS SHIELD — BLOCKED WEBSITE PAGE
// ==========================================

const params = new URLSearchParams(window.location.search);

const requestedUrl = params.get("url") || "";

const reasonText =
  params.get("reason") || "No detailed detection reason was provided.";

// ==========================================
// DOM ELEMENTS
// ==========================================

const requestedUrlElement =
  document.getElementById("requestedUrl");

const reasonsList =
  document.getElementById("reasons");

const backButton =
  document.getElementById("backButton");

const continueButton =
  document.getElementById("continueButton");

// ==========================================
// URL VALIDATION
// ==========================================

function validateRequestedUrl(value) {
  try {
    const parsed = new URL(value);

    if (
      parsed.protocol !== "https:" &&
      parsed.protocol !== "http:"
    ) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

const parsedUrl = validateRequestedUrl(requestedUrl);

// ==========================================
// DISPLAY REQUESTED WEBSITE
// ==========================================

if (parsedUrl) {
  requestedUrlElement.textContent = parsedUrl.href;
} else {
  requestedUrlElement.textContent =
    "Invalid or unavailable website URL.";

  continueButton.disabled = true;
}

// ==========================================
// DISPLAY DETECTION REASONS
// ==========================================

function displayReasons(text) {
  reasonsList.replaceChildren();

  let reasons = [];

  // Support JSON array format if supplied.
  try {
    const parsed = JSON.parse(text);

    if (Array.isArray(parsed)) {
      reasons = parsed;
    } else {
      reasons = [text];
    }
  } catch {
    // Existing extension format uses semicolon-separated reasons.
    reasons = text.split(";");
  }

  reasons = reasons
    .map(reason => String(reason).trim())
    .filter(Boolean);

  if (reasons.length === 0) {
    reasons = [
      "No detailed detection information was returned by the security engine."
    ];
  }

  for (const reason of reasons) {
    const item = document.createElement("li");

    // textContent prevents HTML injection.
    item.textContent = reason;

    reasonsList.appendChild(item);
  }
}

displayReasons(reasonText);

// ==========================================
// GO BACK
// ==========================================

backButton.addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
});

// ==========================================
// CONTINUE ANYWAY
// ==========================================

continueButton.addEventListener("click", () => {
  if (!parsedUrl) {
    alert("Invalid website URL.");
    return;
  }

  const confirmed = window.confirm(
    "WARNING: IDPS Shield blocked this website.\n\n" +
    "The destination may contain phishing, malware, " +
    "or other security threats.\n\n" +
    "Are you sure you want to continue?"
  );

  if (!confirmed) {
    return;
  }

  // Only HTTP and HTTPS URLs are permitted.
  window.location.assign(parsedUrl.href);
});
