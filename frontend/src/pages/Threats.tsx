
import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Info,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from "lucide-react";

import api from "../services/api";

/* ================= TYPES ================= */

type SecurityEvent = {
  id: number;
  url: string;
  domain: string;
  event_type: string;
  risk_score: number;
  risk_level: string;
  decision: string;
  reasons: string[] | null;
  created_at: string | null;
};

type EventsResponse = {
  items: SecurityEvent[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

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

/* ================= HELPERS ================= */

function normalizeDecision(decision: string | undefined): string {
  const value = (decision || "").toUpperCase();

  if (["ALLOW", "ALLOWED", "SAFE"].includes(value)) return "ALLOW";
  if (["BLOCK", "BLOCKED"].includes(value)) return "BLOCK";
  if (["WARN", "WARNING"].includes(value)) return "WARN";

  return "UNKNOWN";
}

function safeReasons(
  reasons: string[] | null | undefined
): string[] {
  if (!Array.isArray(reasons)) return [];

  return reasons.filter(
    (reason) => typeof reason === "string" && reason.trim()
  );
}

function decisionLabel(decision: string): string {
  switch (decision) {
    case "ALLOW":
      return "Allowed";
    case "WARN":
      return "Caution advised";
    case "BLOCK":
      return "Blocked";
    default:
      return "Unknown decision";
  }
}

function decisionDescription(decision: string): string {
  switch (decision) {
    case "ALLOW":
      return "No blocking indicators were found by the configured checks. This does not guarantee the website is safe.";
    case "WARN":
      return "The security checks recommend caution. Review the reasons before continuing.";
    case "BLOCK":
      return "The security checks or a domain policy blocked this URL. Do not continue unless it has been reviewed.";
    default:
      return "The stored decision is missing or unrecognized. Review this event.";
  }
}

/* ================= COLOR HELPERS ================= */

function severityStyle(
  level: string | undefined,
  isDark: boolean
): string {
  const value = (level || "").toUpperCase();

  switch (value) {
    case "CRITICAL":
      return isDark
        ? "border-red-400/25 bg-red-400/10 text-red-300"
        : "border-red-200 bg-red-50 text-red-700";

    case "HIGH":
      return isDark
        ? "border-orange-400/25 bg-orange-400/10 text-orange-300"
        : "border-orange-200 bg-orange-50 text-orange-700";

    case "MEDIUM":
      return isDark
        ? "border-amber-400/25 bg-amber-400/10 text-amber-300"
        : "border-amber-200 bg-amber-50 text-amber-700";

    case "LOW":
      return isDark
        ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-300"
        : "border-emerald-200 bg-emerald-50 text-emerald-700";

    default:
      return isDark
        ? "border-white/10 bg-white/5 text-slate-300"
        : "border-slate-200 bg-slate-100 text-slate-600";
  }
}

function decisionStyle(
  decision: string,
  isDark: boolean
): string {
  switch (decision) {
    case "ALLOW":
      return isDark
        ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-300"
        : "border-emerald-200 bg-emerald-50 text-emerald-700";

    case "WARN":
      return isDark
        ? "border-amber-400/25 bg-amber-400/10 text-amber-300"
        : "border-amber-200 bg-amber-50 text-amber-700";

    case "BLOCK":
      return isDark
        ? "border-red-400/25 bg-red-400/10 text-red-300"
        : "border-red-200 bg-red-50 text-red-700";

    default:
      return isDark
        ? "border-white/10 bg-white/5 text-slate-300"
        : "border-slate-200 bg-slate-100 text-slate-600";
  }
}

/* ================= DECISION ICON ================= */

function DecisionIcon({
  decision,
  isDark,
}: {
  decision: string;
  isDark: boolean;
}) {
  if (decision === "ALLOW") {
    return (
      <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3 text-emerald-500">
        <ShieldCheck size={23} />
      </div>
    );
  }

  if (decision === "BLOCK") {
    return (
      <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-red-500">
        <ShieldX size={23} />
      </div>
    );
  }

  if (decision === "WARN") {
    return (
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-3 text-amber-500">
        <ShieldAlert size={23} />
      </div>
    );
  }

  return (
    <div
      className={`rounded-xl border p-3 ${
        isDark
          ? "border-white/10 bg-white/5 text-slate-400"
          : "border-slate-200 bg-slate-100 text-slate-500"
      }`}
    >
      <AlertTriangle size={23} />
    </div>
  );
}

/* ================= STAT CARD ================= */

function StatCard({
  title,
  value,
  description,
  color,
  isDark,
}: {
  title: string;
  value: string | number;
  description: string;
  color: string;
  isDark: boolean;
}) {
  return (
    <div
      className={`rounded-2xl border p-5 backdrop-blur-2xl transition-all duration-300 hover:-translate-y-1 ${
        isDark
          ? "border-white/[0.08] bg-white/[0.045] shadow-lg shadow-black/10"
          : "border-white/80 bg-white/75 shadow-lg shadow-slate-200/40"
      }`}
    >
      <p className={`text-sm font-medium ${color}`}>
        {title}
      </p>

      <p
        className={`mt-3 text-3xl font-bold tracking-tight ${
          isDark ? "text-white" : "text-slate-900"
        }`}
      >
        {value}
      </p>

      <p
        className={`mt-2 text-xs ${
          isDark ? "text-slate-500" : "text-slate-400"
        }`}
      >
        {description}
      </p>
    </div>
  );
}

/* ================= THREATS PAGE ================= */

export default function Threats() {
  const isDark = useThemeMode();

  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [refreshKey, setRefreshKey] = useState(0);

  /* ================= THEME STYLES ================= */

  const headingClass = isDark ? "text-white" : "text-slate-900";

  const mutedClass = isDark ? "text-slate-400" : "text-slate-500";

  const cardClass = isDark
    ? "border border-white/[0.08] bg-white/[0.045] shadow-[0_15px_45px_rgba(0,0,0,0.18)]"
    : "border border-white/80 bg-white/75 shadow-[0_15px_45px_rgba(31,41,55,0.06)]";

  const inputClass = isDark
    ? "border-white/10 bg-slate-950/40 text-white placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10"
    : "border-slate-200 bg-white/80 text-slate-900 placeholder:text-slate-400 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/10";

  /* ================= LOAD THREATS ================= */

  const loadThreats = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<EventsResponse | SecurityEvent[]>(
        "/api/events",
        {
          params: {
            page: 1,
            page_size: 100,
            search: search.trim() || undefined,
            risk_level: severity || undefined,
          },
        }
      );

      const payload = response.data;

      const allEvents = Array.isArray(payload)
        ? payload
        : Array.isArray(payload?.items)
          ? payload.items
          : [];

      // Display events requiring attention.
      const threats = allEvents.filter((event) => {
        const decision = normalizeDecision(event.decision);
        const level = (event.risk_level || "").toUpperCase();

        return (
          decision === "WARN" ||
          decision === "BLOCK" ||
          level === "HIGH" ||
          level === "CRITICAL"
        );
      });

      setEvents(threats);
      setTotal(threats.length);
    } catch {
      setEvents([]);
      setTotal(0);

      setError(
        "Could not load threat events. Check the backend, API route, and login session."
      );
    } finally {
      setLoading(false);
    }
  }, [search, severity]);

  useEffect(() => {
    void loadThreats();
  }, [loadThreats, refreshKey]);

  /* ================= STATISTICS ================= */

  const criticalCount = events.filter(
    (event) => (event.risk_level || "").toUpperCase() === "CRITICAL"
  ).length;

  const highCount = events.filter(
    (event) => (event.risk_level || "").toUpperCase() === "HIGH"
  ).length;

  const warningCount = events.filter(
    (event) => normalizeDecision(event.decision) === "WARN"
  ).length;

  const blockedCount = events.filter(
    (event) => normalizeDecision(event.decision) === "BLOCK"
  ).length;

  /* ================= UI ================= */

  return (
    <div
      className={`relative mx-auto w-full max-w-7xl space-y-6 overflow-hidden p-4 transition-colors duration-300 sm:p-6 ${
        isDark ? "text-slate-100" : "text-slate-800"
      }`}
    >
      {/* Background effects */}

      <div className="pointer-events-none absolute -left-32 top-10 h-72 w-72 rounded-full bg-cyan-500/[0.06] blur-[100px]" />

      <div className="pointer-events-none absolute -right-32 top-96 h-72 w-72 rounded-full bg-blue-500/[0.06] blur-[100px]" />

      {/* HEADER */}

      <div className="relative flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <p className="text-xs font-bold tracking-[0.2em] text-cyan-500">
            THREAT INTELLIGENCE
          </p>

          <h1 className={`mt-2 text-2xl font-bold tracking-tight sm:text-3xl ${headingClass}`}>
            Security Findings
          </h1>

          <p className={`mt-2 max-w-2xl text-sm leading-6 ${mutedClass}`}>
            Review warnings and blocked URLs recorded by your security checks.
            Icons and colors reflect the saved security decision.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setRefreshKey((key) => key + 1)}
          disabled={loading}
          className={`inline-flex items-center justify-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium transition-all duration-200 disabled:cursor-not-allowed disabled:opacity-50 ${
            isDark
              ? "border-white/10 bg-white/[0.04] text-slate-300 hover:bg-white/[0.09]"
              : "border-slate-200 bg-white/80 text-slate-600 hover:bg-slate-100"
          }`}
        >
          <RefreshCw
            size={16}
            className={loading ? "animate-spin" : ""}
          />
          Refresh
        </button>
      </div>

      {/* STATISTICS */}

      <div className="relative grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          title="Findings loaded"
          value={total}
          description="Events requiring attention"
          color="text-cyan-500"
          isDark={isDark}
        />

        <StatCard
          title="Critical risks"
          value={criticalCount}
          description="Highest severity findings"
          color="text-red-500"
          isDark={isDark}
        />

        <StatCard
          title="High risks"
          value={highCount}
          description="High severity findings"
          color="text-orange-500"
          isDark={isDark}
        />

        <StatCard
          title="Warnings / blocked"
          value={`${warningCount} / ${blockedCount}`}
          description="Caution and blocked decisions"
          color="text-amber-500"
          isDark={isDark}
        />
      </div>

      {/* SEARCH AND FILTER */}

      <div
        className={`relative flex flex-col gap-3 rounded-2xl p-4 backdrop-blur-2xl sm:flex-row ${cardClass}`}
      >
        <div className="relative flex-1">
          <Search
            size={18}
            className={`absolute left-3.5 top-1/2 -translate-y-1/2 ${mutedClass}`}
          />

          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search domain or URL..."
            aria-label="Search domain or URL"
            className={`w-full rounded-xl border py-3 pl-10 pr-4 text-sm outline-none transition-all ${inputClass}`}
          />
        </div>

        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          aria-label="Filter by risk level"
          className={`rounded-xl border px-4 py-3 text-sm outline-none transition-all ${inputClass}`}
        >
          <option value="">All risk levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      {/* ERROR MESSAGE */}

      {error && (
        <div
          role="alert"
          className="relative flex flex-col gap-3 rounded-2xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-500 sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex items-start gap-2">
            <AlertTriangle size={18} className="mt-0.5 shrink-0" />
            <p>{error}</p>
          </div>

          <button
            type="button"
            onClick={() => setRefreshKey((key) => key + 1)}
            className="w-fit font-semibold underline underline-offset-4 hover:opacity-80"
          >
            Try again
          </button>
        </div>
      )}

      {/* LOADING */}

      {loading ? (
        <div
          className={`relative flex min-h-56 flex-col items-center justify-center rounded-2xl border backdrop-blur-2xl ${cardClass}`}
        >
          <RefreshCw size={27} className="animate-spin text-cyan-500" />

          <p className={`mt-4 text-sm ${mutedClass}`}>
            Loading security findings...
          </p>
        </div>
      ) : events.length === 0 ? (
        /* EMPTY STATE */

        <div
          className={`relative rounded-2xl border p-10 text-center backdrop-blur-2xl ${cardClass}`}
        >
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border border-emerald-500/20 bg-emerald-500/10">
            <CheckCircle2
              size={35}
              className="text-emerald-500"
              aria-hidden="true"
            />
          </div>

          <h2 className={`mt-4 text-lg font-semibold ${headingClass}`}>
            No matching warnings or blocked URLs
          </h2>

          <p className={`mx-auto mt-2 max-w-lg text-sm leading-6 ${mutedClass}`}>
            No matching events requiring attention were found in the loaded
            results. This does not certify that every website is safe.
          </p>

          <button
            type="button"
            onClick={() => {
              setSearch("");
              setSeverity("");
              setRefreshKey((key) => key + 1);
            }}
            className="mt-5 inline-flex items-center gap-2 text-sm font-semibold text-cyan-500 hover:text-blue-500"
          >
            <RefreshCw size={15} />
            Clear filters
          </button>
        </div>
      ) : (
        /* SECURITY EVENTS */

        <div className="relative space-y-4">
          {events.map((event) => {
            const decision = normalizeDecision(event.decision);
            const reasons = safeReasons(event.reasons);

            const domain = event.domain || event.url || "Unknown domain";

            const decisionBoxClass =
              decision === "ALLOW"
                ? isDark
                  ? "border-emerald-400/20 bg-emerald-400/[0.05]"
                  : "border-emerald-200 bg-emerald-50/70"
                : decision === "BLOCK"
                  ? isDark
                    ? "border-red-400/20 bg-red-400/[0.05]"
                    : "border-red-200 bg-red-50/70"
                  : decision === "WARN"
                    ? isDark
                      ? "border-amber-400/20 bg-amber-400/[0.05]"
                      : "border-amber-200 bg-amber-50/70"
                    : isDark
                      ? "border-white/10 bg-white/[0.03]"
                      : "border-slate-200 bg-slate-50";

            const decisionTextClass =
              decision === "ALLOW"
                ? "text-emerald-500"
                : decision === "BLOCK"
                  ? "text-red-500"
                  : decision === "WARN"
                    ? "text-amber-500"
                    : mutedClass;

            return (
              <article
                key={event.id}
                className={`group rounded-2xl border p-5 backdrop-blur-2xl transition-all duration-300 hover:-translate-y-0.5 ${
                  isDark
                    ? "border-white/[0.08] bg-white/[0.045] hover:border-cyan-400/20 hover:bg-white/[0.065]"
                    : "border-white/80 bg-white/75 hover:border-cyan-300 hover:bg-white/95"
                }`}
              >
                {/* Event heading */}

                <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
                  <div className="flex min-w-0 items-start gap-3">
                    <DecisionIcon
                      decision={decision}
                      isDark={isDark}
                    />

                    <div className="min-w-0 flex-1">
                      <h2 className={`break-all font-semibold ${headingClass}`}>
                        {domain}
                      </h2>

                      <p className={`mt-1 break-all text-xs ${mutedClass}`}>
                        {event.url}
                      </p>

                      <p className={`mt-2 text-xs ${mutedClass}`}>
                        {(event.event_type || "SECURITY_EVENT").replaceAll(
                          "_",
                          " "
                        )}

                        {event.created_at
                          ? ` · ${new Date(event.created_at).toLocaleString()}`
                          : ""}
                      </p>
                    </div>
                  </div>

                  {/* Badges */}

                  <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                    <span
                      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold ${severityStyle(
                        event.risk_level,
                        isDark
                      )}`}
                    >
                      {event.risk_level || "UNKNOWN"}
                    </span>

                    <span
                      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold ${
                        isDark
                          ? "border-white/10 bg-white/[0.04] text-slate-300"
                          : "border-slate-200 bg-slate-100 text-slate-600"
                      }`}
                    >
                      Score: {event.risk_score ?? 0}/100
                    </span>

                    <span
                      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold ${decisionStyle(
                        decision,
                        isDark
                      )}`}
                    >
                      {decision}
                    </span>
                  </div>
                </div>

                {/* Decision information */}

                <div className={`mt-5 rounded-xl border p-4 ${decisionBoxClass}`}>
                  <div className="flex items-start gap-3">
                    {decision === "ALLOW" ? (
                      <CheckCircle2
                        size={19}
                        className="mt-0.5 shrink-0 text-emerald-500"
                      />
                    ) : decision === "BLOCK" ? (
                      <ShieldX
                        size={19}
                        className="mt-0.5 shrink-0 text-red-500"
                      />
                    ) : decision === "WARN" ? (
                      <ShieldAlert
                        size={19}
                        className="mt-0.5 shrink-0 text-amber-500"
                      />
                    ) : (
                      <Info
                        size={19}
                        className={`mt-0.5 shrink-0 ${mutedClass}`}
                      />
                    )}

                    <div>
                      <p className={`text-sm font-semibold ${decisionTextClass}`}>
                        {decisionLabel(decision)}
                      </p>

                      <p className={`mt-1 text-sm leading-6 ${mutedClass}`}>
                        {decisionDescription(decision)}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Detection details */}

                <div
                  className={`mt-5 border-t pt-4 ${
                    isDark ? "border-white/[0.08]" : "border-slate-200"
                  }`}
                >
                  <h3 className={`text-sm font-semibold ${headingClass}`}>
                    Detection details
                  </h3>

                  {reasons.length > 0 ? (
                    <ul className="mt-3 space-y-2">
                      {reasons.map((reason, index) => (
                        <li
                          key={`${event.id}-${index}`}
                          className={`flex items-start gap-2 text-sm leading-6 ${mutedClass}`}
                        >
                          <span className={`mt-0.5 ${
                            decision === "BLOCK"
                              ? "text-red-500"
                              : decision === "WARN"
                                ? "text-amber-500"
                                : "text-cyan-500"
                          }`}>
                            •
                          </span>

                          <span className="break-words">{reason}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className={`mt-2 text-sm ${mutedClass}`}>
                      No detailed reasons were stored for this event.
                    </p>
                  )}
                </div>

                {/* Research link */}

                <div
                  className={`mt-4 flex justify-end border-t pt-4 ${
                    isDark ? "border-white/[0.06]" : "border-slate-100"
                  }`}
                >
                  <a
                    href={`https://www.google.com/search?q=${encodeURIComponent(
                      domain
                    )}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold text-cyan-500 transition hover:bg-cyan-500/10 hover:text-blue-500"
                  >
                    Research domain
                    <ExternalLink size={14} />
                  </a>
                </div>
              </article>
            );
          })}
        </div>
      )}

      {/* FOOTER NOTE */}

      <div
        className={`relative border-t pt-4 text-xs leading-6 ${
          isDark
            ? "border-white/[0.07] text-slate-500"
            : "border-slate-200 text-slate-400"
        }`}
      >
        Results are based on recorded events and configured local checks. HTTPS
        provides encryption but does not guarantee that a website is trustworthy.
        This page is not a live global threat-intelligence feed.
      </div>
    </div>
  );
}
