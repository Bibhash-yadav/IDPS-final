
import { useCallback, useEffect, useState } from "react";
import {
  Bell,
  AlertTriangle,
  ShieldAlert,
  RefreshCw,
  Search,
  ExternalLink,
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

function getAlertStyle(level: string) {
  switch (level.toUpperCase()) {
    case "CRITICAL":
      return "border-red-500/30 bg-red-500/10 text-red-300";
    case "HIGH":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    case "MEDIUM":
      return "border-amber-500/30 bg-amber-500/10 text-amber-300";
    default:
      return "border-slate-700 bg-slate-800/60 text-slate-300";
  }
}

export default function Alerts() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [decision, setDecision] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [total, setTotal] = useState(0);

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

      const alertEvents = response.data.items.filter((event) =>
        ["WARN", "WARNING", "BLOCK", "BLOCKED"].includes(
          event.decision.toUpperCase(),
        ),
      );

      setEvents(alertEvents);
      setTotal(alertEvents.length);
    } catch {
      setError("Could not load alerts. Check the backend and your login session.");
    } finally {
      setLoading(false);
    }
  }, [search, severity, decision]);

  useEffect(() => {
    void loadAlerts();
  }, [loadAlerts]);

  const criticalCount = events.filter(
    (event) => event.risk_level.toUpperCase() === "CRITICAL",
  ).length;

  const blockedCount = events.filter((event) =>
    ["BLOCK", "BLOCKED"].includes(event.decision.toUpperCase()),
  ).length;

  const warningCount = events.filter((event) =>
    ["WARN", "WARNING"].includes(event.decision.toUpperCase()),
  ).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-amber-300">
            SECURITY NOTIFICATIONS
          </p>
          <h1 className="mt-1 flex items-center gap-3 text-3xl font-bold text-white">
            <Bell size={28} />
            Alerts
          </h1>
          <p className="mt-2 text-sm text-slate-400">
            Review warnings and blocked events detected by your IDPS checks.
          </p>
        </div>

        <button
          onClick={() => void loadAlerts()}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50"
        >
          <RefreshCw size={16} />
          Refresh alerts
        </button>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">Matching alerts</p>
          <p className="mt-2 text-3xl font-bold text-white">{total}</p>
        </div>

        <div className="rounded-2xl border border-red-500/20 bg-slate-900/70 p-5">
          <div className="flex items-center gap-2 text-red-300">
            <ShieldAlert size={18} />
            <p className="text-sm">Blocked</p>
          </div>
          <p className="mt-2 text-3xl font-bold text-white">{blockedCount}</p>
        </div>

        <div className="rounded-2xl border border-amber-500/20 bg-slate-900/70 p-5">
          <div className="flex items-center gap-2 text-amber-300">
            <AlertTriangle size={18} />
            <p className="text-sm">Warnings</p>
          </div>
          <p className="mt-2 text-3xl font-bold text-white">{warningCount}</p>
          <p className="mt-1 text-xs text-slate-500">
            Critical-risk alerts: {criticalCount}
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-3 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 lg:flex-row">
        <div className="relative flex-1">
          <Search
            size={18}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
          />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search URL or domain..."
            className="w-full rounded-xl border border-slate-700 bg-slate-950 py-3 pl-10 pr-4 text-sm text-white outline-none focus:border-cyan-500"
          />
        </div>

        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-cyan-500"
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
          className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-cyan-500"
        >
          <option value="">All decisions</option>
          <option value="WARN">Warnings</option>
          <option value="BLOCK">Blocked</option>
        </select>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {loading ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-10 text-center text-slate-400">
          Loading alerts...
        </div>
      ) : events.length === 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-10 text-center">
          <Bell size={32} className="mx-auto text-slate-500" />
          <h2 className="mt-3 font-semibold text-white">No matching alerts</h2>
          <p className="mt-2 text-sm text-slate-400">
            No warnings or blocked events matched your filters in the loaded results.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {events.map((event) => (
            <article
              key={event.id}
              className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5"
            >
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="flex min-w-0 gap-3">
                  <div
                    className={`rounded-xl border p-3 ${getAlertStyle(event.risk_level)}`}
                  >
                    {["BLOCK", "BLOCKED"].includes(
                      event.decision.toUpperCase(),
                    ) ? (
                      <ShieldAlert size={22} />
                    ) : (
                      <AlertTriangle size={22} />
                    )}
                  </div>

                  <div className="min-w-0">
                    <h2 className="break-all font-semibold text-white">
                      {event.domain || event.url}
                    </h2>
                    <p className="mt-1 break-all text-xs text-slate-400">
                      {event.url}
                    </p>
                    <p className="mt-2 text-xs text-slate-500">
                      {event.created_at
                        ? new Date(event.created_at).toLocaleString()
                        : "Time unavailable"}
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <span
                    className={`rounded-lg border px-3 py-1.5 text-xs font-semibold ${getAlertStyle(event.risk_level)}`}
                  >
                    {event.risk_level}
                  </span>
                  <span className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300">
                    {event.decision}
                  </span>
                  <span className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300">
                    Score: {event.risk_score}/100
                  </span>
                </div>
              </div>

              {event.reasons.length > 0 && (
                <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Reasons recorded
                  </p>
                  <ul className="mt-2 space-y-1">
                    {event.reasons.map((reason, index) => (
                      <li
                        key={`${event.id}-${index}`}
                        className="text-sm text-slate-300"
                      >
                        • {reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="mt-4 flex justify-end">
                <a
                  href={`https://www.google.com/search?q=${encodeURIComponent(event.domain || event.url)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 text-xs text-cyan-300 hover:text-cyan-200"
                >
                  Research domain <ExternalLink size={14} />
                </a>
              </div>
            </article>
          ))}
        </div>
      )}

      <p className="text-xs text-slate-500">
        Alerts are derived from stored URL-check events. This page does not yet
        provide real-time push notifications or a live threat-intelligence feed.
      </p>
    </div>
  );
}
