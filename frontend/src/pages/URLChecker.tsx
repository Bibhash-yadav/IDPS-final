
import { useEffect, useState, type FormEvent } from "react";
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
  Copy,
  Check,
  Link2,
  AlertCircle,
  Info,
  Activity,
  Server,
  Cloud,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";
import api from "../services/api";

/* ================= TYPES ================= */

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

  dns_status?: string;
  resolved_ips?: string[];

  cloudflare?: {
    enabled: boolean;

    url_scan: {
      status: string;
      scan_id: string | null;
      url?: string;
      visibility?: string | null;
      message?: string;
    };

    domain_intelligence: {
      status: string;
      domain: string;
      intelligence: unknown;
      message?: string;
    };
  };
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

type Decision = "ALLOW" | "WARN" | "BLOCK";

/* ================= THEME HOOK ================= */

function useThemeMode() {
  const [isDark, setIsDark] = useState(
    () => document.documentElement.dataset.theme !== "light"
  );

  useEffect(() => {
    const updateTheme = () => {
      setIsDark(document.documentElement.dataset.theme !== "light");
    };

    updateTheme();

    const observer = new MutationObserver(updateTheme);

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });

    return () => observer.disconnect();
  }, []);

  return isDark;
}

/* ================= ERROR HANDLING ================= */

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

/* ================= URL VALIDATION ================= */

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
    throw new Error(
      "Enter a valid website address, such as example.com."
    );
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(
      "Only HTTP and HTTPS website addresses are supported."
    );
  }

  if (!parsed.hostname || !parsed.hostname.includes(".")) {
    throw new Error(
      "Enter a valid domain, such as example.com."
    );
  }

  if (parsed.username || parsed.password) {
    throw new Error(
      "Website URLs containing embedded credentials are not accepted."
    );
  }

  return parsed.href;
}

/* ================= SMALL COMPONENTS ================= */

function SectionCard({
  children,
  isDark,
  className = "",
}: {
  children: React.ReactNode;
  isDark: boolean;
  className?: string;
}) {
  return (
    <section
      className={`rounded-3xl border p-5 backdrop-blur-2xl transition-colors duration-300 sm:p-6 ${
        isDark
          ? "border-white/[0.08] bg-white/[0.045] shadow-[0_15px_45px_rgba(0,0,0,0.18)]"
          : "border-white/80 bg-white/75 shadow-[0_15px_45px_rgba(31,41,55,0.06)]"
      } ${className}`}
    >
      {children}
    </section>
  );
}

function InfoBox({
  label,
  value,
  isDark,
}: {
  label: string;
  value: React.ReactNode;
  isDark: boolean;
}) {
  return (
    <div
      className={`min-w-0 rounded-xl border p-3 ${
        isDark
          ? "border-white/[0.07] bg-slate-950/30"
          : "border-slate-200/80 bg-slate-50/70"
      }`}
    >
      <p
        className={`text-xs ${
          isDark ? "text-slate-500" : "text-slate-400"
        }`}
      >
        {label}
      </p>

      <div
        className={`mt-1 break-all text-sm font-medium ${
          isDark ? "text-slate-200" : "text-slate-800"
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function IndicatorCard({
  icon: Icon,
  title,
  value,
  description,
  isDark,
  color = "text-cyan-500",
}: {
  icon: React.ElementType;
  title: string;
  value: React.ReactNode;
  description: string;
  isDark: boolean;
  color?: string;
}) {
  return (
    <article
      className={`rounded-2xl border p-5 transition-all duration-300 hover:-translate-y-1 ${
        isDark
          ? "border-white/[0.08] bg-white/[0.04] hover:bg-white/[0.07]"
          : "border-white/80 bg-white/75 hover:bg-white"
      }`}
    >
      <div
        className={`mb-4 flex h-11 w-11 items-center justify-center rounded-xl border ${
          isDark
            ? "border-cyan-400/15 bg-cyan-400/10"
            : "border-cyan-200 bg-cyan-50"
        } ${color}`}
      >
        <Icon size={22} />
      </div>

      <p
        className={`text-sm ${
          isDark ? "text-slate-400" : "text-slate-500"
        }`}
      >
        {title}
      </p>

      <p
        className={`mt-2 text-lg font-bold ${
          isDark ? "text-white" : "text-slate-900"
        }`}
      >
        {value}
      </p>

      <p
        className={`mt-1 text-xs leading-5 ${
          isDark ? "text-slate-500" : "text-slate-400"
        }`}
      >
        {description}
      </p>
    </article>
  );
}

/* ================= MAIN COMPONENT ================= */

export default function URLChecker() {
  const { user, loading: authLoading } = useAuth();
  const isDark = useThemeMode();

  const [url, setUrl] = useState("");
  const [report, setReport] = useState<URLReport | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [copied, setCopied] = useState(false);

  const [cloudflareScanReport, setCloudflareScanReport] =
    useState<unknown>(null);

  const [cloudflareScanLoading, setCloudflareScanLoading] =
    useState(false);

  const [cloudflareScanError, setCloudflareScanError] =
    useState("");

  /* ================= THEME STYLES ================= */

  const headingClass = isDark ? "text-white" : "text-slate-900";

  const mutedClass = isDark ? "text-slate-400" : "text-slate-500";

  const inputClass = isDark
    ? "border-white/10 bg-slate-950/40 text-white placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10"
    : "border-slate-200 bg-white/80 text-slate-900 placeholder:text-slate-400 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/10";

  const innerCardClass = isDark
    ? "border-white/[0.07] bg-slate-950/30"
    : "border-slate-200/80 bg-slate-50/70";

  const dividerClass = isDark
    ? "border-white/[0.08]"
    : "border-slate-200";

  /* ================= DECISION STYLES ================= */

  const decisionStyles: Record<
    Decision,
    {
      color: string;
      background: string;
      icon: React.ElementType;
      title: string;
      bar: string;
    }
  > = {
    ALLOW: {
      color: isDark ? "text-emerald-300" : "text-emerald-700",
      background: isDark
        ? "border-emerald-400/25 bg-emerald-400/[0.07]"
        : "border-emerald-200 bg-emerald-50/80",
      icon: ShieldCheck,
      title: "LOW-RISK RESULT",
      bar: "bg-emerald-500",
    },

    WARN: {
      color: isDark ? "text-amber-300" : "text-amber-700",
      background: isDark
        ? "border-amber-400/25 bg-amber-400/[0.07]"
        : "border-amber-200 bg-amber-50/80",
      icon: ShieldAlert,
      title: "CAUTION ADVISED",
      bar: "bg-amber-500",
    },

    BLOCK: {
      color: isDark ? "text-red-300" : "text-red-700",
      background: isDark
        ? "border-red-400/25 bg-red-400/[0.07]"
        : "border-red-200 bg-red-50/80",
      icon: ShieldX,
      title: "WEBSITE BLOCKED",
      bar: "bg-red-500",
    },
  };

  /* ================= COPY URL ================= */

  async function copyFullUrl() {
    if (!report?.url) return;

    try {
      await navigator.clipboard.writeText(report.url);
      setCopied(true);

      window.setTimeout(() => {
        setCopied(false);
      }, 2000);
    } catch {
      setError(
        "Could not copy the URL. Please select and copy it manually."
      );
    }
  }

  /* ================= CLOUDFLARE REPORT ================= */

  async function fetchCloudflareScanReport() {
    const scanId = report?.cloudflare?.url_scan?.scan_id;

    if (!scanId || cloudflareScanLoading) {
      return;
    }

    setCloudflareScanLoading(true);
    setCloudflareScanError("");

    try {
      const response = await api.get(
        `/api/cloudflare/scan/${encodeURIComponent(scanId)}`
      );

      if (response.data?.processing) {
        setCloudflareScanError(
          "Cloudflare is still processing this scan. Please try again in 10–30 seconds."
        );

        setCloudflareScanReport(null);
      } else {
        setCloudflareScanReport(response.data);
      }
    } catch (scanError: unknown) {
      setCloudflareScanError(getErrorMessage(scanError));
    } finally {
      setCloudflareScanLoading(false);
    }
  }

  /* ================= CHECK URL ================= */

  async function handleCheck(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (loading) return;

    setError("");
    setReport(null);
    setCloudflareScanReport(null);
    setCloudflareScanError("");
    setCopied(false);

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
      const response = await api.post<URLReport>(
        "/api/url/check",
        {
          url: normalizedUrl,
        }
      );

      setReport(response.data);
    } catch (requestError: unknown) {
      setError(getErrorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }

  /* ================= RESET ================= */

  function resetForm() {
    if (loading) return;

    setUrl("");
    setReport(null);
    setCloudflareScanReport(null);
    setCloudflareScanError("");
    setError("");
    setCopied(false);
  }

  /* ================= AUTH LOADING ================= */

  if (authLoading) {
    return (
      <main
        className={`flex min-h-64 items-center justify-center ${
          isDark ? "text-cyan-400" : "text-cyan-600"
        }`}
      >
        <LoaderCircle size={22} className="mr-3 animate-spin" />
        Loading account...
      </main>
    );
  }

  const currentStyle = report
    ? decisionStyles[report.decision] ?? decisionStyles.WARN
    : null;

  const parsedReportUrl = (() => {
    if (!report?.url) return null;

    try {
      return new URL(report.url);
    } catch {
      return null;
    }
  })();

  const ResultIcon = currentStyle?.icon;

  /* ================= MAIN UI ================= */

  return (
    <main
      className={`relative mx-auto min-h-screen w-full max-w-7xl space-y-6 overflow-hidden p-4 transition-colors duration-300 sm:p-6 lg:p-8 ${
        isDark ? "text-slate-100" : "text-slate-800"
      }`}
    >
      {/* Background effects */}

      <div className="pointer-events-none absolute -left-32 top-10 h-80 w-80 rounded-full bg-cyan-500/[0.06] blur-[110px]" />

      <div className="pointer-events-none absolute -right-32 top-96 h-80 w-80 rounded-full bg-blue-500/[0.06] blur-[110px]" />

      {/* PAGE HEADER */}

      <header className="relative flex flex-col gap-4 sm:flex-row sm:items-center">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-500 shadow-lg shadow-cyan-500/10">
          <ShieldCheck size={28} />
        </div>

        <div>
          <p className="text-xs font-bold tracking-[0.2em] text-cyan-500">
            THREAT ANALYSIS
          </p>

          <h1
            className={`mt-1 text-2xl font-bold tracking-tight sm:text-3xl ${headingClass}`}
          >
            URL Security Checker
          </h1>

          <p className={`mt-2 max-w-3xl text-sm leading-6 ${mutedClass}`}>
            Analyze complete website URLs for malware indicators, phishing,
            encryption status, domain reputation, and applicable age restrictions.
          </p>
        </div>
      </header>

      {/* AUTH WARNING */}

      {!user && (
        <div
          role="alert"
          className="relative flex items-start gap-3 rounded-2xl border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-500"
        >
          <AlertCircle size={19} className="mt-0.5 shrink-0" />
          Please sign in to use the URL Security Checker.
        </div>
      )}

      {/* URL INPUT CARD */}

      <SectionCard isDark={isDark}>
        <div className="mb-6 flex items-center gap-3">
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-3 text-cyan-500">
            <Search size={23} />
          </div>

          <div>
            <h2 className={`font-semibold ${headingClass}`}>
              Analyze a website
            </h2>

            <p className={`mt-1 text-sm ${mutedClass}`}>
              Enter the complete website URL, including its page path.
            </p>
          </div>
        </div>

        <form onSubmit={handleCheck} className="space-y-5">
          <div>
            <label
              htmlFor="website-url"
              className={`mb-2 block text-sm font-semibold ${headingClass}`}
            >
              Complete Website URL
            </label>

            <div
              className={`flex items-center gap-3 rounded-xl border px-4 transition-all focus-within:border-cyan-400/60 focus-within:ring-2 focus-within:ring-cyan-400/10 ${inputClass}`}
            >
              <Globe
                size={20}
                className={`shrink-0 ${mutedClass}`}
              />

              <input
                id="website-url"
                type="text"
                value={url}
                onChange={(event) => {
                  setUrl(event.target.value);
                  if (error) setError("");
                }}
                placeholder="https://example.com/login?user=test"
                maxLength={2048}
                autoComplete="url"
                required
                disabled={loading || !user}
                className="w-full min-w-0 bg-transparent py-4 text-sm outline-none disabled:cursor-not-allowed disabled:opacity-60"
              />
            </div>

            <p className={`mt-2 text-xs ${mutedClass}`}>
              Enter the entire URL, for example:
              <span className="ml-1 text-cyan-500">
                https://example.com/account/login
              </span>
            </p>
          </div>

          {/* ERROR */}

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm leading-6 text-red-500"
            >
              <AlertCircle size={18} className="mt-0.5 shrink-0" />
              {error}
            </div>
          )}

          {/* BUTTONS */}

          <div className="flex flex-col gap-3 sm:flex-row">
            <button
              type="submit"
              disabled={loading || !user || authLoading}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition-all hover:-translate-y-0.5 hover:shadow-xl disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:translate-y-0"
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
              className={`inline-flex items-center justify-center gap-2 rounded-xl border px-5 py-3 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-50 ${
                isDark
                  ? "border-white/10 bg-white/[0.04] text-slate-300 hover:bg-white/[0.09]"
                  : "border-slate-200 bg-white/80 text-slate-600 hover:bg-slate-100"
              }`}
            >
              <RotateCcw size={16} />
              Reset
            </button>
          </div>
        </form>
      </SectionCard>

      {/* RESULTS */}

      {report && currentStyle && ResultIcon && (
        <section className="relative space-y-5">
          {/* COMPLETE URL */}

          <SectionCard isDark={isDark}>
            <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
              <div className="flex items-center gap-2">
                <Link2 className="text-cyan-500" size={21} />

                <h3 className={`text-lg font-semibold ${headingClass}`}>
                  Complete URL Analyzed
                </h3>
              </div>

              <button
                type="button"
                onClick={copyFullUrl}
                className="inline-flex w-fit items-center gap-2 rounded-xl border border-cyan-500/20 bg-cyan-500/10 px-3 py-2 text-sm font-semibold text-cyan-500 transition hover:bg-cyan-500/20"
              >
                {copied ? <Check size={16} /> : <Copy size={16} />}
                {copied ? "Copied" : "Copy Full URL"}
              </button>
            </div>

            <div
              className={`mt-4 rounded-xl border p-4 ${
                isDark
                  ? "border-white/10 bg-slate-950/40"
                  : "border-slate-200 bg-slate-50"
              }`}
            >
              <p className="break-all text-sm leading-7 text-cyan-500">
                {report.url}
              </p>
            </div>

            {parsedReportUrl && (
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <InfoBox
                  label="Protocol"
                  value={parsedReportUrl.protocol}
                  isDark={isDark}
                />

                <InfoBox
                  label="Domain / Hostname"
                  value={parsedReportUrl.hostname}
                  isDark={isDark}
                />

                <InfoBox
                  label="Port"
                  value={parsedReportUrl.port || "Default"}
                  isDark={isDark}
                />

                <InfoBox
                  label="Path"
                  value={parsedReportUrl.pathname || "/"}
                  isDark={isDark}
                />

                <div className="sm:col-span-2">
                  <InfoBox
                    label="Query Parameters"
                    value={parsedReportUrl.search || "No query parameters"}
                    isDark={isDark}
                  />
                </div>

                {parsedReportUrl.hash && (
                  <div className="sm:col-span-2">
                    <InfoBox
                      label="Fragment"
                      value={parsedReportUrl.hash}
                      isDark={isDark}
                    />
                  </div>
                )}
              </div>
            )}

            <p className={`mt-3 text-xs leading-5 ${mutedClass}`}>
              This is the normalized URL returned by your backend and used
              for the analysis. Query parameters may contain private information.
            </p>
          </SectionCard>

          {/* MAIN RISK RESULT */}

          <article
            className={`rounded-3xl border p-5 backdrop-blur-2xl sm:p-7 ${currentStyle.background}`}
          >
            <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex min-w-0 items-start gap-4">
                <div className="rounded-2xl border border-current/10 bg-white/5 p-3">
                  <ResultIcon
                    size={35}
                    className={currentStyle.color}
                  />
                </div>

                <div className="min-w-0">
                  <p
                    className={`text-xs font-bold tracking-[0.15em] ${currentStyle.color}`}
                  >
                    {currentStyle.title}
                  </p>

                  <h2
                    className={`mt-2 break-all text-xl font-bold ${headingClass}`}
                  >
                    {report.domain}
                  </h2>

                  <p
                    className={`mt-2 text-sm leading-6 ${
                      isDark ? "text-slate-300" : "text-slate-600"
                    }`}
                  >
                    {report.recommendation}
                  </p>
                </div>
              </div>

              <div className="shrink-0 sm:text-right">
                <p className={`text-sm ${mutedClass}`}>
                  Risk score
                </p>

                <p className={`text-5xl font-bold ${currentStyle.color}`}>
                  {report.risk_score}
                  <span className={`text-lg ${mutedClass}`}>/100</span>
                </p>

                <p className={`mt-1 text-sm font-semibold ${currentStyle.color}`}>
                  {report.risk_level}
                </p>
              </div>
            </div>

            {/* RISK PROGRESS */}

            <div
              className={`mt-6 h-2 overflow-hidden rounded-full ${
                isDark ? "bg-slate-950/50" : "bg-slate-200"
              }`}
            >
              <div
                className={`h-full rounded-full transition-all duration-700 ${currentStyle.bar}`}
                style={{
                  width: `${Math.max(
                    0,
                    Math.min(100, Number(report.risk_score) || 0)
                  )}%`,
                }}
              />
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-3 text-xs">
              <span
                className={`rounded-lg border px-3 py-2 ${
                  isDark
                    ? "border-white/10 bg-slate-950/30 text-slate-300"
                    : "border-slate-200 bg-white/70 text-slate-600"
                }`}
              >
                Decision: <strong>{report.decision}</strong>
              </span>

              <span
                className={`rounded-lg border px-3 py-2 ${
                  isDark
                    ? "border-white/10 bg-slate-950/30 text-slate-300"
                    : "border-slate-200 bg-white/70 text-slate-600"
                }`}
              >
                Check ID: {report.check_id}
              </span>
            </div>
          </article>

          {/* SECURITY INDICATORS */}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <IndicatorCard
              icon={LockKeyhole}
              title="HTTPS"
              value={report.https_enabled ? "Enabled" : "Not enabled"}
              description="Encryption status only"
              isDark={isDark}
              color="text-cyan-500"
            />

            <IndicatorCard
              icon={ShieldCheck}
              title="SSL/TLS"
              value={
                report.ssl_valid === true
                  ? "Valid"
                  : report.ssl_valid === false
                    ? "Invalid"
                    : "Not checked"
              }
              description={report.ssl_status}
              isDark={isDark}
              color="text-blue-500"
            />

            <IndicatorCard
              icon={Bug}
              title="Malware"
              value={
                report.malware?.malware_detected
                  ? "Indicator detected"
                  : "No list match"
              }
              description={
                report.malware?.reason ?? "No details returned"
              }
              isDark={isDark}
              color={
                report.malware?.malware_detected
                  ? "text-red-500"
                  : "text-emerald-500"
              }
            />

            <IndicatorCard
              icon={Fingerprint}
              title="Phishing"
              value={
                report.phishing?.phishing_detected
                  ? "Suspicious indicators"
                  : "No rule triggered"
              }
              description="Local heuristic analysis"
              isDark={isDark}
              color={
                report.phishing?.phishing_detected
                  ? "text-amber-500"
                  : "text-emerald-500"
              }
            />
          </div>

          {/* DNS INFORMATION */}

          {report.dns_status && (
            <SectionCard isDark={isDark}>
              <div className="flex items-center gap-3">
                <div className="rounded-xl bg-cyan-500/10 p-2.5 text-cyan-500">
                  <Server size={22} />
                </div>

                <div>
                  <h3 className={`font-semibold ${headingClass}`}>
                    DNS Resolution
                  </h3>

                  <p className={`text-xs ${mutedClass}`}>
                    Domain resolution information
                  </p>
                </div>
              </div>

              <div className="mt-4">
                <InfoBox
                  label="DNS Status"
                  value={report.dns_status}
                  isDark={isDark}
                />
              </div>

              {report.resolved_ips && report.resolved_ips.length > 0 && (
                <div className="mt-4">
                  <p className={`mb-2 text-xs ${mutedClass}`}>
                    Resolved IP addresses
                  </p>

                  <div className="flex flex-wrap gap-2">
                    {report.resolved_ips.map((ip) => (
                      <span
                        key={ip}
                        className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-3 py-2 text-xs font-medium text-cyan-500"
                      >
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </SectionCard>
          )}

          {/* CLOUDFLARE */}

          <SectionCard isDark={isDark}>
            <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
              <div className="flex items-center gap-3">
                <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-3 text-cyan-500">
                  <Cloud size={24} />
                </div>

                <div>
                  <h3 className={`text-lg font-semibold ${headingClass}`}>
                    Cloudflare Security Intelligence
                  </h3>

                  <p className={`mt-1 text-sm ${mutedClass}`}>
                    External URL scanning and domain intelligence
                  </p>
                </div>
              </div>

              <span
                className={`w-fit rounded-full border px-3 py-1.5 text-xs font-semibold ${
                  report.cloudflare?.enabled
                    ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-500"
                    : isDark
                      ? "border-white/10 bg-white/5 text-slate-400"
                      : "border-slate-200 bg-slate-100 text-slate-500"
                }`}
              >
                {report.cloudflare?.enabled
                  ? "Integration enabled"
                  : "Unavailable"}
              </span>
            </div>

            <div className="mt-5 grid gap-4 sm:grid-cols-2">
              {/* URL SCANNER */}

              <div className={`rounded-2xl border p-4 ${innerCardClass}`}>
                <div className="flex items-center gap-2">
                  <Search size={18} className="text-cyan-500" />

                  <h4 className={`text-sm font-semibold ${headingClass}`}>
                    Cloudflare URL Scanner
                  </h4>
                </div>

                <p className="mt-3 text-sm font-semibold text-cyan-500">
                  {report.cloudflare?.url_scan?.status ?? "not configured"}
                </p>

                {report.cloudflare?.url_scan?.scan_id && (
                  <>
                    <p className={`mt-2 break-all text-xs ${mutedClass}`}>
                      Scan ID: {report.cloudflare.url_scan.scan_id}
                    </p>

                    <button
                      type="button"
                      onClick={fetchCloudflareScanReport}
                      disabled={cloudflareScanLoading}
                      className="mt-4 inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-2.5 text-xs font-semibold text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {cloudflareScanLoading && (
                        <LoaderCircle size={15} className="animate-spin" />
                      )}

                      {cloudflareScanLoading
                        ? "Retrieving..."
                        : "Retrieve Scan Report"}
                    </button>
                  </>
                )}

                {report.cloudflare?.url_scan?.message && (
                  <p className={`mt-3 text-xs leading-5 ${mutedClass}`}>
                    {report.cloudflare.url_scan.message}
                  </p>
                )}

                {cloudflareScanError && (
                  <p
                    role="status"
                    className="mt-3 text-xs leading-5 text-amber-500"
                  >
                    {cloudflareScanError}
                  </p>
                )}
              </div>

              {/* DOMAIN INTELLIGENCE */}

              <div className={`rounded-2xl border p-4 ${innerCardClass}`}>
                <div className="flex items-center gap-2">
                  <Activity size={18} className="text-cyan-500" />

                  <h4 className={`text-sm font-semibold ${headingClass}`}>
                    Domain Intelligence
                  </h4>
                </div>

                <p className="mt-3 text-sm font-semibold text-cyan-500">
                  {report.cloudflare?.domain_intelligence?.status ??
                    "not configured"}
                </p>

                <p className={`mt-2 text-xs leading-5 ${mutedClass}`}>
                  {report.cloudflare?.domain_intelligence?.message ??
                    "No Cloudflare domain intelligence response was returned."}
                </p>
              </div>
            </div>

            {/* DOMAIN INTELLIGENCE DETAILS */}

            {report.cloudflare?.domain_intelligence?.intelligence != null && (
              <div className="mt-5">
                <h4 className={`mb-2 text-sm font-semibold ${headingClass}`}>
                  Domain Intelligence Details
                </h4>

                <pre
                  className={`max-h-72 overflow-auto rounded-xl border p-4 text-xs leading-5 ${
                    isDark
                      ? "border-white/10 bg-slate-950/60 text-cyan-300"
                      : "border-slate-200 bg-slate-50 text-cyan-700"
                  }`}
                >
                  {JSON.stringify(
                    report.cloudflare.domain_intelligence.intelligence,
                    null,
                    2
                  )}
                </pre>
              </div>
            )}

            {/* CLOUDFLARE SCAN REPORT */}

            {cloudflareScanReport != null && (
              <div className="mt-5">
                <h4 className={`mb-2 text-sm font-semibold ${headingClass}`}>
                  Cloudflare URL Scan Report
                </h4>

                <pre
                  className={`max-h-96 overflow-auto rounded-xl border p-4 text-xs leading-5 ${
                    isDark
                      ? "border-white/10 bg-slate-950/60 text-emerald-300"
                      : "border-slate-200 bg-slate-50 text-emerald-700"
                  }`}
                >
                  {JSON.stringify(cloudflareScanReport, null, 2)}
                </pre>
              </div>
            )}
          </SectionCard>

          {/* DETECTION DETAILS */}

          <SectionCard isDark={isDark}>
            <div className="flex items-center gap-3">
              <div className="rounded-xl bg-cyan-500/10 p-2.5 text-cyan-500">
                <Fingerprint size={22} />
              </div>

              <div>
                <h3 className={`text-lg font-semibold ${headingClass}`}>
                  Detection Details
                </h3>

                <p className={`mt-1 text-xs ${mutedClass}`}>
                  Findings and analysis information returned by the backend.
                </p>
              </div>
            </div>

            {/* ADULT CONTENT */}

            {report.adult_content_detected && (
              <p className="mt-5 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-500">
                Adult-content indicators were detected by configured rules.
              </p>
            )}

            {/* AGE RESTRICTION */}

            {report.age_restricted && (
              <p className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/10 p-3 text-sm text-amber-500">
                This website has an age restriction.
                {report.required_age !== null &&
                  ` Required age: ${report.required_age} or older.`}
              </p>
            )}

            {/* REASONS */}

            <div className="mt-5 space-y-3">
              {!report.reasons || report.reasons.length === 0 ? (
                <div
                  className={`rounded-xl border p-4 text-sm leading-6 ${innerCardClass} ${mutedClass}`}
                >
                  No risk indicators were returned by the configured rules.
                  This does not guarantee the website is safe.
                </div>
              ) : (
                report.reasons.map((reason, index) => (
                  <div
                    key={`${index}-${reason}`}
                    className={`flex items-start gap-3 rounded-xl border p-3 text-sm ${
                      isDark
                        ? "border-white/[0.06] bg-white/[0.025]"
                        : "border-slate-100 bg-slate-50/70"
                    }`}
                  >
                    <ShieldAlert
                      size={18}
                      className="mt-0.5 shrink-0 text-amber-500"
                    />

                    <p
                      className={
                        isDark ? "text-slate-300" : "text-slate-600"
                      }
                    >
                      {reason}
                    </p>
                  </div>
                ))
              )}
            </div>

            {/* ADDITIONAL INFORMATION */}

            <div className={`mt-6 grid gap-3 border-t pt-5 sm:grid-cols-2 ${dividerClass}`}>
              <InfoBox
                label="Domain reputation"
                value={report.domain_reputation}
                isDark={isDark}
              />

              <InfoBox
                label="Age policy"
                value={
                  report.age_decision === "NOT_ESTABLISHED"
                    ? "Not established"
                    : report.age_decision
                }
                isDark={isDark}
              />

              <InfoBox
                label="Analysis method"
                value={report.analysis_method}
                isDark={isDark}
              />

              <InfoBox
                label="Analyzed domain"
                value={report.domain}
                isDark={isDark}
              />

              <InfoBox
                label="User age"
                value={`${report.user_age} years`}
                isDark={isDark}
              />

              <InfoBox
                label="Required age"
                value={
                  report.required_age !== null
                    ? `${report.required_age} years`
                    : "Not specified"
                }
                isDark={isDark}
              />
            </div>

            {/* ALLOW / BLOCK / WARN ACTIONS */}

            {report.decision === "ALLOW" && (
              <a
                href={report.url}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-6 inline-flex items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm font-semibold text-emerald-500 transition hover:bg-emerald-500/15"
              >
                Open website
                <ExternalLink size={16} />
              </a>
            )}

            {report.decision === "BLOCK" && (
              <p className="mt-5 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm leading-6 text-red-500">
                Opening this link is disabled in this result because the
                security policy returned BLOCK.
              </p>
            )}

            {report.decision === "WARN" && (
              <p className="mt-5 rounded-xl border border-amber-500/20 bg-amber-500/10 p-3 text-sm leading-6 text-amber-500">
                Exercise caution. The analysis returned a warning.
              </p>
            )}
          </SectionCard>
        </section>
      )}

      {/* FOOTER */}

      <div
        className={`relative flex items-start gap-2 border-t pt-4 text-xs leading-6 ${dividerClass} ${mutedClass}`}
      >
        <Info size={15} className="mt-1 shrink-0" />

        <p>
          Security results are based on the configured detection rules and
          external integrations. HTTPS provides encryption but does not
          guarantee that a website is trustworthy. A failed scan does not
          establish that a website is safe.
        </p>
      </div>
    </main>
  );
}
