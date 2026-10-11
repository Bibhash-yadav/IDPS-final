
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

function normalizeDecision(decision: string | undefined): string {
  const value = (decision || "").toUpperCase();

  if (["ALLOW", "ALLOWED", "SAFE"].includes(value)) return "ALLOW";
  if (["BLOCK", "BLOCKED"].includes(value)) return "BLOCK";
  if (["WARN", "WARNING"].includes(value)) return "WARN";

  return "UNKNOWN";
}

function severityStyle(level: string | undefined): string {
  switch ((level || "").toUpperCase()) {
    case "CRITICAL":
      return "border-red-500/40 bg-red-500/10 text-red-300";
    case "HIGH":
      return "border-orange-500/40 bg-orange-500/10 text-orange-300";
    case "MEDIUM":
      return "border-amber-500/40 bg-amber-500/10 text-amber-300";
    case "LOW":
      return "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
    default:
      return "border-slate-600 bg-slate-800/60 text-slate-300";
  }
}

function decisionStyle(decision: string): string {
  switch (decision) {
    case "ALLOW":
      return "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
    case "WARN":
      return "border-amber-500/40 bg-amber-500/10 text-amber-300";
    case "BLOCK":
      return "border-red-500/40 bg-red-500/10 text-red-300";
    default:
      return "border-slate-600 bg-slate-800/60 text-slate-300";
  }
}

function DecisionIcon({ decision }: { decision: string }) {
  if (decision === "ALLOW") {
    return (
      <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3 text-emerald-400">
        <ShieldCheck size={24} aria-hidden="true" />
      </div>
    );
  }

  if (decision === "BLOCK") {
    return (
      <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-red-400">
        <ShieldX size={24} aria-hidden="true" />
      </div>
    );
  }

  if (decision === "WARN") {
    return (
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-3 text-amber-400">
        <ShieldAlert size={24} aria-hidden="true" />
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-600 bg-slate-800/60 p-3 text-slate-400">
      <AlertTriangle size={24} aria-hidden="true" />
    </div>
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

function safeReasons(reasons: string[] | null | undefined): string[] {
  if (!Array.isArray(reasons)) return [];
  return reasons.filter((reason) => typeof reason === "string" && reason.trim());
}

export default function Threats() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

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
        },
      );

      // Support both paginated responses and plain event arrays.
      const payload = response.data;
      const allEvents = Array.isArray(payload)
        ? payload
        : Array.isArray(payload?.items)
          ? payload.items
          : [];

      // This page displays events requiring attention.
      // A LOW-risk WARN remains a warning until the backend decision changes.
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
        "Could not load threat events. Check the backend, API route, and login session.",
      );
    } finally {
      setLoading(false);
    }
  }, [search, severity]);

  useEffect(() => {
    void loadThreats();
  }, [loadThreats, refreshKey]);

  const criticalCount = events.filter(
    (event) => (event.risk_level || "").toUpperCase() === "CRITICAL",
  ).length;

  const highCount = events.filter(
    (event) => (event.risk_level || "").toUpperCase() === "HIGH",
  ).length;

  const warningCount = events.filter(
    (event) => normalizeDecision(event.decision) === "WARN",
  ).length;

  const blockedCount = events.filter(
    (event) => normalizeDecision(event.decision) === "BLOCK",
  ).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-cyan-300">
            THREAT INTELLIGENCE
          </p>
          <h1 className="mt-1 text-3xl font-bold text-white">
            Security Findings
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            Review warnings and blocked URLs recorded by your security checks.
            Icons and colors reflect the saved security decision.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setRefreshKey((key) => key + 1)}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-2.5 text-sm text-slate-200 transition hover:bg-slate-800 disabled:opacity-50"
        >
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">Findings loaded</p>
          <p className="mt-2 text-3xl font-bold text-white">{total}</p>
        </div>

        <div className="rounded-2xl border border-red-500/20 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">Critical risks</p>
          <p className="mt-2 text-3xl font-bold text-red-300">
            {criticalCount}
          </p>
        </div>

        <div className="rounded-2xl border border-orange-500/20 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">High risks</p>
          <p className="mt-2 text-3xl font-bold text-orange-300">
            {highCount}
          </p>
        </div>

        <div className="rounded-2xl border border-amber-500/20 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">Warnings / blocked</p>
          <p className="mt-2 text-3xl font-bold text-amber-300">
            {warningCount} / {blockedCount}
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-3 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:flex-row">
        <div className="relative flex-1">
          <Search
            size={18}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
          />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search domain or URL..."
            aria-label="Search domain or URL"
            className="w-full rounded-xl border border-slate-700 bg-slate-950 py-3 pl-10 pr-4 text-sm text-white outline-none focus:border-cyan-500"
          />
        </div>

        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          aria-label="Filter by risk level"
          className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-cyan-500"
        >
          <option value="">All risk levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      {error && (
        <div
          role="alert"
          className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
        >
          {error}
          <button
            type="button"
            onClick={() => setRefreshKey((key) => key + 1)}
            className="ml-2 underline underline-offset-4 hover:text-red-200"
          >
            Try again
          </button>
        </div>
      )}

      {loading ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-10 text-center text-slate-400">
          Loading security findings...
        </div>
      ) : events.length === 0 ? (
        <div className="rounded-2xl border border-emerald-500/20 bg-slate-900/70 p-10 text-center">
          <CheckCircle2
            size={38}
            className="mx-auto text-emerald-400"
            aria-hidden="true"
          />
          <h2 className="mt-3 font-semibold text-white">
            No matching warnings or blocked URLs
          </h2>
          <p className="mt-2 text-sm text-slate-400">
            No matching events requiring attention were found in the loaded
            results. This does not certify that every website is safe.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {events.map((event) => {
            const decision = normalizeDecision(event.decision);
            const reasons = safeReasons(event.reasons);
            const domain = event.domain || event.url || "Unknown domain";

            return (
              <article
                key={event.id}
                className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5"
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="flex min-w-0 gap-3">
                    <DecisionIcon decision={decision} />

                    <div className="min-w-0">
                      <h2 className="break-all font-semibold text-white">
                        {domain}
                      </h2>

                      <p className="mt-1 break-all text-xs text-slate-400">
                        {event.url}
                      </p>

                      <p className="mt-2 text-xs text-slate-500">
                        {(event.event_type || "SECURITY_EVENT").replaceAll(
                          "_",
                          " ",
                        )}
                        {event.created_at
                          ? ` · ${new Date(event.created_at).toLocaleString()}`
                          : ""}
                      </p>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold ${severityStyle(event.risk_level)}`}
                    >
                      {event.risk_level || "UNKNOWN"}
                    </span>

                    <span className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300">
                      Score: {event.risk_score ?? 0}/100
                    </span>

                    <span
                      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold ${decisionStyle(decision)}`}
                    >
                      {decision}
                    </span>
                  </div>
                </div>

                <div
                  className={`mt-5 rounded-xl border p-3 ${
                    decision === "ALLOW"
                      ? "border-emerald-500/20 bg-emerald-500/5"
                      : decision === "BLOCK"
                        ? "border-red-500/20 bg-red-500/5"
                        : decision === "WARN"
                          ? "border-amber-500/20 bg-amber-500/5"
                          : "border-slate-700 bg-slate-800/30"
                  }`}
                >
                  <div className="flex items-start gap-2">
                    {decision === "ALLOW" ? (
                      <CheckCircle2
                        size={18}
                        className="mt-0.5 shrink-0 text-emerald-400"
                      />
                    ) : decision === "BLOCK" ? (
                      <ShieldX
                        size={18}
                        className="mt-0.5 shrink-0 text-red-400"
                      />
                    ) : decision === "WARN" ? (
                      <ShieldAlert
                        size={18}
                        className="mt-0.5 shrink-0 text-amber-400"
                      />
                    ) : (
                      <Info
                        size={18}
                        className="mt-0.5 shrink-0 text-slate-400"
                      />
                    )}

                    <div>
                      <p
                        className={`text-sm font-semibold ${
                          decision === "ALLOW"
                            ? "text-emerald-300"
                            : decision === "BLOCK"
                              ? "text-red-300"
                              : decision === "WARN"
                                ? "text-amber-300"
                                : "text-slate-300"
                        }`}
                      >
                        {decisionLabel(decision)}
                      </p>
                      <p className="mt-1 text-sm text-slate-400">
                        {decisionDescription(decision)}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="mt-5 border-t border-slate-800 pt-4">
                  <h3 className="text-sm font-medium text-slate-200">
                    Detection details
                  </h3>

                  {reasons.length > 0 ? (
                    <ul className="mt-3 space-y-2">
                      {reasons.map((reason, index) => (
                        <li
                          key={`${event.id}-${index}`}
                          className="flex gap-2 text-sm text-slate-400"
                        >
                          <span
                            className={
                              decision === "ALLOW"
                                ? "text-emerald-400"
                                : decision === "BLOCK"
                                  ? "text-red-400"
                                  : "text-amber-400"
                            }
                          >
                            •
                          </span>
                          <span>{reason}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="mt-2 text-sm text-slate-500">
                      No detailed reasons were stored for this event.
                    </p>
                  )}
                </div>

                <div className="mt-4 flex justify-end">
                  <a
                    href={`https://www.google.com/search?q=${encodeURIComponent(domain)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-xs text-cyan-300 hover:text-cyan-200"
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

      <p className="text-xs text-slate-500">
        Results are based on recorded events and configured local checks. HTTPS
        provides encryption but does not guarantee that a website is trustworthy.
        This page is not a live global threat-intelligence feed.
      </p>
    </div>
  );
}
