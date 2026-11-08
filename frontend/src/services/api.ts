
import axios from "axios";

// =====================================================
// API CONFIGURATION
// =====================================================

const API_URL = (
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const api = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
});

// =====================================================
// REQUEST INTERCEPTOR
// =====================================================

api.interceptors.request.use(
  (config) => {
    const token = sessionStorage.getItem("idps_token");

    // Preserve explicitly supplied challenge tokens.
    const hasAuthorization =
      config.headers.has("Authorization");

    if (!hasAuthorization && token) {
      config.headers.set(
        "Authorization",
        `Bearer ${token}`
      );
    }

    return config;
  },
  (error) => Promise.reject(error)
);

// =====================================================
// RESPONSE INTERCEPTOR
// =====================================================

api.interceptors.response.use(
  (response) => response,
  (error) => {
    return Promise.reject(error);
  }
);

// =====================================================
// SOCIAL LOGIN
// =====================================================

// These endpoints must be implemented by FastAPI.
// The backend should redirect to the configured OAuth
// provider and validate the callback server-side.

export function startGoogleOAuth(): void {
  window.location.assign(
    `${API_URL}/api/auth/oauth/google/start`
  );
}

export function startGitHubOAuth(): void {
  window.location.assign(
    `${API_URL}/api/auth/oauth/github/start`
  );
}

// =====================================================
// EXPORT
// =====================================================

export { API_URL };

export default api;
