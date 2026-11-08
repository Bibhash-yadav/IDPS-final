import { useCallback, useEffect, useState } from "react";
import {
  Bell,
  AlertTriangle,
  ShieldAlert,
  RefreshCw,
  Search,
  ExternalLink,
  ShieldCheck,
  Clock3,
  Activity,
  Info,
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
  reasons: string[];
  created_at: string | null;
};

type EventsResponse = {
  items: SecurityEvent[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

function useThemeMode() {
  const [isDark, setIsDark] = useState(() => {
    if (typeof document === "undefined") return true;
    return document.documentElement.dataset.theme !== "light";
  });

  useEffect(() => {
    const root = document.documentElement;
    const updateTheme = () => setIsDark(root.dataset.theme !== "light");
    updateTheme();

    const observer = new MutationObserver(updateTheme);
    observer.observe(root, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });

    return () => observer.disconnect();
  }, []);

  return isDark;
}

function getAlertStyle(level: string, isDark: boolean) {
  const normalized = (level || "").toUpperCase();

  switch (normalized) {
    case "CRITICAL":
      return "border-rose-500/30 bg-rose-500/10 text-rose-500";
    case "HIGH":
      return "border-orange-500/30 bg-orange-500/10 text-orange-500";
    case "MEDIUM":
      return "border-amber-500/30 bg-amber-500/10 text-amber-500";
    case "LOW":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-500";
    default:
      return isDark
        ? "border-white/10 bg-slate-800/60 text-slate-300"
        : "border-slate-200 bg-slate-100/80 text-slate-600";
  }
}

function isBlocked(decision: string) {
  return ["BLOCK", "BLOCKED"].includes((decision || "").toUpperCase());
}

function formatDate(value: string | null) {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Time unavailable"
    : date.toLocaleString();
}

export default function Alerts() {
  const isDark = useThemeMode();

  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [decision, setDecision] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [total, setTotal] = useState(0);

  const surface = isDark
    ? "border-white/[0.08] bg-slate-900/55 shadow-black/20"
    : "border-white/80 bg-white/65 shadow-slate-200/50";
  const innerSurface = isDark
    ? "border-white/[0.07] bg-slate-950/35"
    : "border-slate-200/70 bg-white/55";
  const heading = isDark ? "text-white" : "text-slate-900";
  const body = isDark ? "text-slate-400" : "text-slate-500";
  const subtle = isDark ? "text-slate-500" : "text-slate-400";
  const fieldStyle = isDark
    ? "border-white/10 bg-slate-950/60 text-slate-100 placeholder:text-slate-500"
    : "border-slate-200 bg-white/75 text-slate-800 placeholder:text-slate-400";

  const loadAlerts = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<EventsResponse>("/api/events", {
        params: {
          page: 1,
          page_size: 100,
          search: search.trim() || undefined,
          risk_level: severity || undefined,
          decision: decision || undefined,
        },
      });

      const alertEvents = (response.data.items || []).filter((event) =>
        ["WARN", "WARNING", "BLOCK", "BLOCKED"].includes(
          (event.decision || "").toUpperCase(),
        ),
      );

      setEvents(alertEvents);
      setTotal(alertEvents.length);
    } catch {
      setError("Could not load alerts. Check the backend and your login session.");
      setEvents([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [search, severity, decision]);

  useEffect(() => {
    void loadAlerts();
  }, [loadAlerts]);

  const criticalCount = events.filter(
    (event) => (event.risk_level || "").toUpperCase() === "CRITICAL",
  ).length;

  const blockedCount = events.filter((event) =>
    isBlocked(event.decision),
  ).length;

  const warningCount = events.filter((event) =>
    ["WARN", "WARNING"].includes((event.decision || "").toUpperCase()),
  ).length;

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 pb-5">
      {/* Page heading */}
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-amber-500">
            <Activity size={15} />
            Security operations
          </div>
          <h1 className={`mt-2 flex items-center gap-3 text-3xl font-bold tracking-tight sm:text-4xl ${heading}`}>
            <Bell size={29} className="text-cyan-500" />
            Alerts
          </h1>
          <p className={`mt-2 max-w-2xl text-sm leading-6 ${body}`}>
            Review warnings and blocked events detected by your IDPS checks.
          </p>
        </div>

        <button
          type="button"
          onClick={() => void loadAlerts()}
          disabled={loading}
          className={`inline-flex items-center gap-2 rounded-2xl border px-4 py-2.5 text-sm font-medium shadow-sm backdrop-blur-xl transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-50 ${surface} ${heading}`}
        >
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
          Refresh alerts
        </button>
      </header>

      {/* Summary cards */}
      <section className="grid gap-4 sm:grid-cols-3">
        <div className={`rounded-2xl border p-5 shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className={`flex items-center gap-2 text-sm ${body}`}>
            <Bell size={16} className="text-cyan-500" />
            Matching alerts
          </div>
          <p className={`mt-3 text-3xl font-bold tabular-nums ${heading}`}>{total}</p>
          <p className={`mt-1 text-xs ${subtle}`}>Based on the current filters</p>
        </div>

        <div className={`rounded-2xl border p-5 shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className="flex items-center gap-2 text-sm text-rose-500">
            <ShieldAlert size={17} />
            Blocked
          </div>
          <p className={`mt-3 text-3xl font-bold tabular-nums ${heading}`}>{blockedCount}</p>
          <p className={`mt-1 text-xs ${subtle}`}>URLs marked for blocking</p>
        </div>

        <div className={`rounded-2xl border p-5 shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className="flex items-center gap-2 text-sm text-amber-500">
            <AlertTriangle size={17} />
            Warnings
          </div>
          <p className={`mt-3 text-3xl font-bold tabular-nums ${heading}`}>{warningCount}</p>
          <p className={`mt-1 text-xs ${subtle}`}>
            Critical-risk alerts: <span className={`font-semibold ${heading}`}>{criticalCount}</span>
          </p>
        </div>
      </section>

      {/* Filters */}
      <section className={`flex flex-col gap-3 rounded-2xl border p-4 shadow-lg backdrop-blur-2xl lg:flex-row ${surface}`}>
        <div className="relative min-w-0 flex-1">
          <Search
            size={18}
            className={`absolute left-3 top-1/2 -translate-y-1/2 ${subtle}`}
          />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search URL or domain..."
            aria-label="Search alerts by URL or domain"
            className={`w-full rounded-xl border py-3 pl-10 pr-4 text-sm outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-500/10 ${fieldStyle}`}
          />
        </div>

        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          aria-label="Filter by risk level"
          className={`rounded-xl border px-4 py-3 text-sm outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-500/10 ${fieldStyle}`}
        >
          <option value="">All risk levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          value={decision}
          onChange={(event) => setDecision(event.target.value)}
          aria-label="Filter by decision"
          className={`rounded-xl border px-4 py-3 text-sm outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-500/10 ${fieldStyle}`}
        >
          <option value="">All decisions</option>
          <option value="WARN">Warnings</option>
          <option value="BLOCK">Blocked</option>
        </select>
      </section>

      {error && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-2xl border border-rose-500/25 bg-rose-500/10 p-4 text-sm text-rose-500"
        >
          <AlertTriangle size={17} className="mt-0.5 shrink-0" />
          {error}
        </div>
      )}

      {/* Alert results */}
      {loading ? (
        <div className={`rounded-2xl border p-12 text-center shadow-lg backdrop-blur-2xl ${surface}`}>
          <RefreshCw size={25} className="mx-auto animate-spin text-cyan-500" />
          <p className={`mt-3 text-sm ${body}`}>Loading alerts...</p>
        </div>
      ) : events.length === 0 ? (
        <div className={`rounded-[26px] border p-10 text-center shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className={`mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border ${innerSurface}`}>
            <ShieldCheck size={28} className="text-emerald-500" />
          </div>
          <h2 className={`mt-4 font-semibold ${heading}`}>No matching alerts</h2>
          <p className={`mx-auto mt-2 max-w-md text-sm leading-6 ${body}`}>
            No warnings or blocked events matched your filters in the loaded results.
          </p>
          <button
            type="button"
            onClick={() => {
              setSearch("");
              setSeverity("");
              setDecision("");
            }}
            className="mt-5 rounded-xl border border-cyan-500/25 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-500 transition hover:bg-cyan-500/15"
          >
            Clear filters
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {events.map((event) => {
            const blocked = isBlocked(event.decision);
            const alertStyle = getAlertStyle(event.risk_level, isDark);
            const reasons = Array.isArray(event.reasons) ? event.reasons : [];

            return (
              <article
                key={event.id}
                className={`group rounded-[24px] border p-5 shadow-lg backdrop-blur-2xl transition duration-200 hover:-translate-y-0.5 hover:shadow-xl sm:p-6 ${surface}`}
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="flex min-w-0 gap-3">
                    <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border ${alertStyle}`}>
                      {blocked ? <ShieldAlert size={22} /> : <AlertTriangle size={22} />}
                    </div>

                    <div className="min-w-0">
                      <h2 className={`break-all font-semibold ${heading}`}>
                        {event.domain || event.url}
                      </h2>
                      <p className={`mt-1 break-all text-xs ${body}`}>{event.url}</p>
                      <p className={`mt-2 flex items-center gap-1.5 text-xs ${subtle}`}>
                        <Clock3 size={13} />
                        {formatDate(event.created_at)}
                      </p>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <span className={`rounded-full border px-3 py-1.5 text-[11px] font-semibold ${alertStyle}`}>
                      {event.risk_level || "UNKNOWN"}
                    </span>
                    <span className={`rounded-full border px-3 py-1.5 text-[11px] font-semibold ${blocked
                      ? "border-rose-500/25 bg-rose-500/10 text-rose-500"
                      : "border-amber-500/25 bg-amber-500/10 text-amber-500"
                    }`}>
                      {event.decision}
                    </span>
                    <span className={`rounded-full border px-3 py-1.5 text-[11px] font-semibold ${innerSurface} ${body}`}>
                      Score: {event.risk_score}/100
                    </span>
                  </div>
                </div>

                {reasons.length > 0 && (
                  <div className={`mt-5 rounded-2xl border p-4 ${innerSurface}`}>
                    <p className={`text-[11px] font-semibold uppercase tracking-[0.15em] ${body}`}>
                      Reasons recorded
                    </p>
                    <ul className="mt-3 space-y-2">
                      {reasons.map((reason, index) => (
                        <li
                          key={`${event.id}-${index}`}
                          className={`flex gap-2 text-sm leading-6 ${body}`}
                        >
                          <span className="text-cyan-500">•</span>
                          <span>{reason}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                  <span className={`text-xs ${subtle}`}>
                    Event type: {event.event_type || "URL check"}
                  </span>
                  <a
                    href={`https://www.google.com/search?q=${encodeURIComponent(event.domain || event.url)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-2 rounded-xl px-3 py-2 text-xs font-medium text-cyan-500 transition hover:bg-cyan-500/10"
                  >
                    Research domain <ExternalLink size={14} />
                  </a>
                </div>
              </article>
            );
          })}
        </div>
      )}

      <p className={`flex items-start gap-2 text-xs leading-5 ${subtle}`}>
        <Info size={14} className="mt-0.5 shrink-0" />
        Alerts are derived from stored URL-check events. This page does not yet provide real-time push notifications or a live threat-intelligence feed.
      </p>
    </div>
  );
}
