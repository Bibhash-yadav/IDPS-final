import { useState, type FormEvent } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Globe,
  LockKeyhole,
  Bug,
  Fingerprint,
  Search,
  LoaderCircle,
  RotateCcw,
  ExternalLink,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";
import api from "../services/api";

interface URLReport {
  check_id: number;
  url: string;
  domain: string;
  https_enabled: boolean;
  ssl_valid: boolean | null;
  ssl_status: string;

  malware: {
    malware_detected: boolean;
    malware_confidence: number;
    reason: string;
  };

  phishing: {
    phishing_detected: boolean;
    phishing_confidence: number;
    findings: string[];
  };

  domain_reputation: string;
  age_restricted: boolean;
  required_age: number | null;
  user_age: number;
  age_decision: string;
  risk_score: number;
  risk_level: string;
  decision: "ALLOW" | "WARN" | "BLOCK";
  reasons: string[];
  recommendation: string;
  analysis_method: string;
  adult_content_detected?: boolean;
}

type ApiError = {
  response?: {
    status?: number;
    data?: {
      detail?: string | { msg?: string; message?: string }[];
      message?: string;
    };
  };
  message?: string;
};

const decisionStyles = {
  ALLOW: {
    color: "text-emerald-400",
    background: "bg-emerald-500/10 border-emerald-500/30",
    icon: ShieldCheck,
    title: "LOW-RISK RESULT",
    bar: "bg-emerald-400",
  },
  WARN: {
    color: "text-amber-400",
    background: "bg-amber-500/10 border-amber-500/30",
    icon: ShieldAlert,
    title: "CAUTION ADVISED",
    bar: "bg-amber-400",
  },
  BLOCK: {
    color: "text-red-400",
    background: "bg-red-500/10 border-red-500/30",
    icon: ShieldX,
    title: "WEBSITE BLOCKED",
    bar: "bg-red-500",
  },
};

function getErrorMessage(error: unknown): string {
  const apiError = error as ApiError;
  const status = apiError.response?.status;
  const detail = apiError.response?.data?.detail;

  if (typeof detail === "string" && detail.trim()) {
    return detail;
  }

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => item.msg || item.message || "")
      .filter(Boolean);

    if (messages.length > 0) {
      return messages.join(" ");
    }
  }

  if (apiError.response?.data?.message) {
    return apiError.response.data.message;
  }

  if (status === 401) {
    return "Your session has expired. Please sign in again.";
  }

  if (status === 403) {
    return (
      "The request was denied. Check that your account has a registered " +
      "date of birth and that the age restriction policy allows this website."
    );
  }

  if (status === 404) {
    return "The URL-checking endpoint was not found. Check the backend route.";
  }

  if (status === 422) {
    return "The URL was rejected. Enter a valid website address.";
  }

  if (status && status >= 500) {
    return (
      "The backend encountered an error. Check the backend terminal for " +
      "the detailed error message."
    );
  }

  if (!apiError.response) {
    return (
      "Cannot connect to the backend. Make sure the FastAPI server is " +
      "running and the API base URL is configured correctly."
    );
  }

  return apiError.message || "Website analysis failed. Please try again.";
}

function normalizeUrl(value: string): string {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error("Please enter a website URL.");
  }

  const candidate = /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  let parsed: URL;

  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("Enter a valid website address, such as example.com.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS website addresses are supported.");
  }

  if (!parsed.hostname || !parsed.hostname.includes(".")) {
    throw new Error("Enter a valid domain, such as example.com.");
  }

  if (parsed.username || parsed.password) {
    throw new Error("Website URLs containing embedded credentials are not accepted.");
  }

  return parsed.href;
}

export default function URLChecker() {
  const { user, loading: authLoading } = useAuth();

  const [url, setUrl] = useState("");
  const [report, setReport] = useState<URLReport | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleCheck(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (loading) return;

    setError("");
    setReport(null);

    if (authLoading) {
      setError("Your account is still loading. Please try again.");
      return;
    }

    if (!user) {
      setError("Please sign in before checking a website.");
      return;
    }

    let normalizedUrl: string;

    try {
      normalizedUrl = normalizeUrl(url);
    } catch (validationError) {
      setError(
        validationError instanceof Error
          ? validationError.message
          : "Enter a valid website URL."
      );
      return;
    }

    setLoading(true);

    try {
      // The backend obtains the registered date of birth from the
      // authenticated database user. Do not send a client-supplied age.
      const response = await api.post<URLReport>("/api/url/check", {
        url: normalizedUrl,
      });

      setReport(response.data);
    } catch (requestError: unknown) {
      setError(getErrorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }

  function resetForm() {
    if (loading) return;

    setUrl("");
    setReport(null);
    setError("");
  }

  if (authLoading) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#080d18] text-cyan-400">
        <LoaderCircle size={22} className="mr-3 animate-spin" />
        Loading account...
      </main>
    );
  }

  const currentStyle = report
    ? decisionStyles[report.decision] ?? decisionStyles.WARN
    : null;

  return (
    <main className="min-h-screen bg-[#080d18] p-5 text-slate-100 md:p-8">
      <header className="mb-8">
        <p className="text-sm font-medium tracking-widest text-cyan-400">
          THREAT ANALYSIS
        </p>

        <h1 className="mt-2 text-3xl font-bold">
          URL Security Checker
        </h1>

        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
          Analyze websites for malware indicators, phishing, encryption
          status, domain reputation, and applicable age restrictions.
        </p>
      </header>

      {!user && (
        <div
          role="alert"
          className="mb-5 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-300"
        >
          Please sign in to use the URL Security Checker.
        </div>
      )}

      <section className="rounded-2xl border border-slate-800 bg-[#101827] p-5 md:p-7">
        <div className="mb-6 flex items-center gap-3">
          <div className="rounded-xl bg-cyan-400/10 p-3 text-cyan-400">
            <Search size={23} />
          </div>

          <div>
            <h2 className="font-semibold text-white">
              Analyze a website
            </h2>
            <p className="text-sm text-slate-400">
              Your registered date of birth is checked by the backend.
            </p>
          </div>
        </div>

        <form onSubmit={handleCheck} className="space-y-5">
          <div>
            <label
              htmlFor="website-url"
              className="mb-2 block text-sm text-slate-300"
            >
              Website URL
            </label>

            <div className="flex items-center gap-3 rounded-xl border border-slate-700 bg-[#080d18] px-4 focus-within:border-cyan-400">
              <Globe size={20} className="shrink-0 text-slate-500" />

              <input
                id="website-url"
                type="text"
                value={url}
                onChange={(event) => {
                  setUrl(event.target.value);
                  if (error) setError("");
                }}
                placeholder="https://example.com"
                maxLength={2048}
                autoComplete="url"
                required
                disabled={loading || !user}
                className="w-full min-w-0 bg-transparent py-4 text-white outline-none placeholder:text-slate-600 disabled:cursor-not-allowed disabled:opacity-60"
              />
            </div>

            <p className="mt-2 text-xs text-slate-500">
              You can enter example.com or https://example.com.
            </p>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm leading-6 text-red-300"
            >
              {error}
            </div>
          )}

          <div className="flex flex-wrap gap-3">
            <button
              type="submit"
              disabled={loading || !user || authLoading}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-500 px-6 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? (
                <>
                  <LoaderCircle size={18} className="animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Search size={18} />
                  Check Website
                </>
              )}
            </button>

            <button
              type="button"
              onClick={resetForm}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-5 py-3 text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RotateCcw size={16} />
              Reset
            </button>
          </div>
        </form>
      </section>

      {report && currentStyle && (
        <section className="mt-7 space-y-5">
          <article
            className={`rounded-2xl border p-6 ${currentStyle.background}`}
          >
            <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-4">
                <currentStyle.icon
                  size={36}
                  className={currentStyle.color}
                />

                <div>
                  <p
                    className={`text-sm font-semibold tracking-widest ${currentStyle.color}`}
                  >
                    {currentStyle.title}
                  </p>

                  <h2 className="mt-2 break-all text-xl font-bold text-white">
                    {report.domain}
                  </h2>

                  <p className="mt-2 text-sm leading-6 text-slate-300">
                    {report.recommendation}
                  </p>
                </div>
              </div>

              <div className="shrink-0 sm:text-right">
                <p className="text-sm text-slate-400">Risk score</p>
                <p className={`text-5xl font-bold ${currentStyle.color}`}>
                  {report.risk_score}
                  <span className="text-lg text-slate-500">/100</span>
                </p>
                <p className={`mt-1 text-sm font-semibold ${currentStyle.color}`}>
                  {report.risk_level}
                </p>
              </div>
            </div>

            <div className="mt-6 h-2 overflow-hidden rounded-full bg-slate-800">
              <div
                className={`h-full rounded-full transition-all ${currentStyle.bar}`}
                style={{
                  width: `${Math.max(
                    0,
                    Math.min(100, Number(report.risk_score) || 0)
                  )}%`,
                }}
              />
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-3 text-sm">
              <span className="rounded-lg border border-slate-700 bg-slate-950/40 px-3 py-2">
                Decision: <strong>{report.decision}</strong>
              </span>

              <span className="rounded-lg border border-slate-700 bg-slate-950/40 px-3 py-2">
                Check ID: {report.check_id}
              </span>
            </div>
          </article>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <article className="rounded-xl border border-slate-800 bg-[#101827] p-5">
              <LockKeyhole className="mb-3 text-cyan-400" size={23} />
              <p className="text-sm text-slate-400">HTTPS</p>
              <p className="mt-2 font-semibold">
                {report.https_enabled ? "Enabled" : "Not enabled"}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Encryption status only
              </p>
            </article>

            <article className="rounded-xl border border-slate-800 bg-[#101827] p-5">
              <ShieldCheck className="mb-3 text-cyan-400" size={23} />
              <p className="text-sm text-slate-400">SSL/TLS</p>
              <p className="mt-2 font-semibold">
                {report.ssl_valid === true
                  ? "Valid"
                  : report.ssl_valid === false
                    ? "Invalid"
                    : "Not checked"}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                {report.ssl_status}
              </p>
            </article>

            <article className="rounded-xl border border-slate-800 bg-[#101827] p-5">
              <Bug className="mb-3 text-cyan-400" size={23} />
              <p className="text-sm text-slate-400">Malware</p>
              <p className="mt-2 font-semibold">
                {report.malware?.malware_detected
                  ? "Indicator detected"
                  : "No list match"}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                {report.malware?.reason ?? "No details returned"}
              </p>
            </article>

            <article className="rounded-xl border border-slate-800 bg-[#101827] p-5">
              <Fingerprint className="mb-3 text-cyan-400" size={23} />
              <p className="text-sm text-slate-400">Phishing</p>
              <p className="mt-2 font-semibold">
                {report.phishing?.phishing_detected
                  ? "Suspicious indicators"
                  : "No rule triggered"}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Local heuristic analysis
              </p>
            </article>
          </div>

          <article className="rounded-xl border border-slate-800 bg-[#101827] p-5 md:p-6">
            <h3 className="text-lg font-semibold">Detection details</h3>

            {report.adult_content_detected && (
              <p className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
                Adult-content indicators were detected by configured rules.
              </p>
            )}

            {report.age_restricted && (
              <p className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-300">
                This website has an age restriction.
                {report.required_age !== null &&
                  ` Required age: ${report.required_age} or older.`}
              </p>
            )}

            <div className="mt-4 space-y-3">
              {!report.reasons || report.reasons.length === 0 ? (
                <p className="text-sm text-slate-400">
                  No risk indicators were returned by the configured rules.
                  This does not guarantee the website is safe.
                </p>
              ) : (
                report.reasons.map((reason, index) => (
                  <div
                    key={`${index}-${reason}`}
                    className="flex gap-3 text-sm"
                  >
                    <ShieldAlert
                      size={18}
                      className="mt-0.5 shrink-0 text-amber-400"
                    />
                    <p className="text-slate-300">{reason}</p>
                  </div>
                ))
              )}
            </div>

            <div className="mt-5 grid gap-3 border-t border-slate-800 pt-5 sm:grid-cols-2">
              <div>
                <p className="text-xs text-slate-500">Domain reputation</p>
                <p className="mt-1 text-sm font-medium">
                  {report.domain_reputation}
                </p>
              </div>

              <div>
                <p className="text-xs text-slate-500">Age policy</p>
                <p className="mt-1 text-sm font-medium">
                  {report.age_decision === "NOT_ESTABLISHED"
                    ? "Not established"
                    : report.age_decision}
                </p>
              </div>

              <div>
                <p className="text-xs text-slate-500">Analysis method</p>
                <p className="mt-1 text-sm font-medium">
                  {report.analysis_method}
                </p>
              </div>

              <div>
                <p className="text-xs text-slate-500">Analyzed URL</p>
                <p className="mt-1 break-all text-sm font-medium">
                  {report.url}
                </p>
              </div>
            </div>

            {report.decision === "ALLOW" && (
              <a
                href={report.url}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-6 inline-flex items-center gap-2 rounded-lg border border-emerald-500/30 px-4 py-3 text-sm font-semibold text-emerald-400 hover:bg-emerald-500/10"
              >
                Open website <ExternalLink size={16} />
              </a>
            )}

            {report.decision === "BLOCK" && (
              <p className="mt-5 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-sm text-red-300">
                Opening this link is disabled in this result because the
                security policy returned BLOCK.
              </p>
            )}

            {report.decision === "WARN" && (
              <p className="mt-5 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-amber-300">
                Exercise caution. The analysis returned a warning.
              </p>
            )}
          </article>
        </section>
      )}
    </main>
  );
}
