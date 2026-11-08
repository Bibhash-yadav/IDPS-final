
import { useCallback, useEffect, useState } from "react";
import {
  Search,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Activity,
  ShieldCheck,
  AlertTriangle,
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
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
};

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

function badgeClass(value: string, isDark: boolean) {
  const key = value.toUpperCase();

  if (["CRITICAL", "HIGH", "BLOCK", "BLOCKED"].includes(key)) {
    return isDark
      ? "bg-red-500/15 text-red-300 border-red-400/25"
      : "bg-red-50 text-red-700 border-red-200";
  }

  if (["MEDIUM", "WARN", "WARNING"].includes(key)) {
    return isDark
      ? "bg-amber-500/15 text-amber-300 border-amber-400/25"
      : "bg-amber-50 text-amber-700 border-amber-200";
  }

  if (["LOW", "ALLOW", "ALLOWED"].includes(key)) {
    return isDark
      ? "bg-emerald-500/15 text-emerald-300 border-emerald-400/25"
      : "bg-emerald-50 text-emerald-700 border-emerald-200";
  }

  return isDark
    ? "bg-slate-500/15 text-slate-300 border-slate-400/20"
    : "bg-slate-100 text-slate-600 border-slate-200";
}

export default function Events() {
  const isDark = useThemeMode();

  const [data, setData] = useState<EventsResponse>({
    items: [],
    page: 1,
    page_size: 10,
    total: 0,
    total_pages: 0,
  });

  const [search, setSearch] = useState("");
  const [riskLevel, setRiskLevel] = useState("");
  const [decision, setDecision] = useState("");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadEvents = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<EventsResponse>("/api/events", {
        params: {
          page,
          page_size: 10,
          search: search.trim() || undefined,
          risk_level: riskLevel || undefined,
          decision: decision || undefined,
        },
      });

      setData(response.data);
    } catch {
      setError(
        "Unable to load security events. Check your login and backend connection."
      );
    } finally {
      setLoading(false);
    }
  }, [page, search, riskLevel, decision]);

  useEffect(() => {
    void loadEvents();
  }, [loadEvents]);

  const changeFilter = (
    setter: (value: string) => void,
    value: string
  ) => {
    setter(value);
    setPage(1);
  };

  const cardClass = isDark
    ? "border border-white/10 bg-white/[0.055] shadow-[0_12px_40px_rgba(0,0,0,0.18)] backdrop-blur-2xl"
    : "border border-white/80 bg-white/75 shadow-[0_12px_40px_rgba(31,41,55,0.07)] backdrop-blur-2xl";

  const primaryText = isDark ? "text-white" : "text-slate-900";
  const secondaryText = isDark ? "text-slate-400" : "text-slate-500";
  const mutedText = isDark ? "text-slate-500" : "text-slate-400";

  const inputClass = isDark
    ? "border-white/10 bg-slate-950/50 text-white placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10"
    : "border-slate-200 bg-white/80 text-slate-800 placeholder:text-slate-400 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/10";

  const buttonClass = isDark
    ? "border-white/10 bg-white/[0.06] text-slate-200 hover:bg-white/10"
    : "border-slate-200 bg-white/80 text-slate-700 hover:bg-slate-100";

  const tableHeaderClass = isDark
    ? "border-white/10 bg-white/[0.035] text-slate-400"
    : "border-slate-200 bg-slate-50/80 text-slate-500";

  const tableRowClass = isDark
    ? "border-white/[0.07] hover:bg-white/[0.035]"
    : "border-slate-100 hover:bg-slate-50/80";

  return (
    <div className="space-y-7 pb-8">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.8)]" />
            <p className="text-xs font-bold tracking-[0.2em] text-cyan-500">
              MONITORING CENTER
            </p>
          </div>

          <h1 className={`text-3xl font-bold tracking-tight ${primaryText}`}>
            Security Events
          </h1>

          <p className={`mt-2 text-sm ${secondaryText}`}>
            Search, filter, and review URL security decisions.
          </p>
        </div>

        <button
          onClick={() => void loadEvents()}
          disabled={loading}
          className={`inline-flex items-center gap-2 rounded-2xl border px-5 py-3 text-sm font-semibold shadow-sm transition-all duration-200 hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-50 ${buttonClass}`}
        >
          <RefreshCw
            size={16}
            className={loading ? "animate-spin" : ""}
          />
          Refresh
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <div className={`rounded-[24px] p-5 transition-all duration-300 hover:-translate-y-1 ${cardClass}`}>
          <div className="flex items-center justify-between">
            <div>
              <p className={`text-sm font-medium ${secondaryText}`}>
                Matching Events
              </p>
              <p className={`mt-3 text-3xl font-bold ${primaryText}`}>
                {data.total}
              </p>
            </div>

            <div className="rounded-2xl bg-cyan-500/10 p-3 text-cyan-500">
              <Activity size={23} />
            </div>
          </div>
          <p className={`mt-3 text-xs ${mutedText}`}>
            Total events matching your filters
          </p>
        </div>

        <div className={`rounded-[24px] p-5 transition-all duration-300 hover:-translate-y-1 ${cardClass}`}>
          <div className="flex items-center justify-between">
            <div>
              <p className={`text-sm font-medium ${secondaryText}`}>
                Current Page
              </p>
              <p className={`mt-3 text-3xl font-bold ${primaryText}`}>
                {data.total_pages ? data.page : 0}
                <span className={`text-lg font-medium ${mutedText}`}>
                  {" "}/ {data.total_pages}
                </span>
              </p>
            </div>

            <div className="rounded-2xl bg-violet-500/10 p-3 text-violet-500">
              <ShieldCheck size={23} />
            </div>
          </div>
          <p className={`mt-3 text-xs ${mutedText}`}>
            Navigate through security records
          </p>
        </div>

        <div className={`rounded-[24px] p-5 transition-all duration-300 hover:-translate-y-1 ${cardClass}`}>
          <div className="flex items-center justify-between">
            <div>
              <p className={`text-sm font-medium ${secondaryText}`}>
                Events Displayed
              </p>
              <p className={`mt-3 text-3xl font-bold ${primaryText}`}>
                {data.items.length}
              </p>
            </div>

            <div className="rounded-2xl bg-amber-500/10 p-3 text-amber-500">
              <AlertTriangle size={23} />
            </div>
          </div>
          <p className={`mt-3 text-xs ${mutedText}`}>
            Records displayed on this page
          </p>
        </div>
      </div>

      {/* Search and filters */}
      <div className={`rounded-[24px] p-4 sm:p-5 ${cardClass}`}>
        <div className="mb-4">
          <h2 className={`text-base font-semibold ${primaryText}`}>
            Search & Filters
          </h2>
          <p className={`mt-1 text-xs ${secondaryText}`}>
            Narrow down security events by URL, risk level, or decision.
          </p>
        </div>

        <div className="flex flex-col gap-3 lg:flex-row">
          <div className="relative flex-1">
            <Search
              size={18}
              className={`absolute left-4 top-1/2 -translate-y-1/2 ${mutedText}`}
            />

            <input
              value={search}
              onChange={(e) => changeFilter(setSearch, e.target.value)}
              placeholder="Search URL, domain, or event type..."
              className={`w-full rounded-2xl border py-3.5 pl-11 pr-4 text-sm outline-none transition-all ${inputClass}`}
            />
          </div>

          <select
            value={riskLevel}
            onChange={(e) =>
              changeFilter(setRiskLevel, e.target.value)
            }
            className={`rounded-2xl border px-4 py-3.5 text-sm outline-none transition-all ${inputClass}`}
          >
            <option value="">All risk levels</option>
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
            <option value="CRITICAL">Critical</option>
          </select>

          <select
            value={decision}
            onChange={(e) =>
              changeFilter(setDecision, e.target.value)
            }
            className={`rounded-2xl border px-4 py-3.5 text-sm outline-none transition-all ${inputClass}`}
          >
            <option value="">All decisions</option>
            <option value="ALLOW">Allow</option>
            <option value="WARN">Warn</option>
            <option value="BLOCK">Block</option>
          </select>
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-500">
          <span>{error}</span>

          <button
            onClick={() => void loadEvents()}
            className="font-semibold underline underline-offset-4"
          >
            Try again
          </button>
        </div>
      )}

      {/* Events table */}
      <div className={`overflow-hidden rounded-[24px] ${cardClass}`}>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-5 py-5">
          <div>
            <h2 className={`text-lg font-semibold ${primaryText}`}>
              Event History
            </h2>
            <p className={`mt-1 text-xs ${secondaryText}`}>
              Detailed URL security activity
            </p>
          </div>

          <span className={`rounded-full border px-3 py-1.5 text-xs font-medium ${
            isDark
              ? "border-cyan-400/20 bg-cyan-400/10 text-cyan-300"
              : "border-cyan-200 bg-cyan-50 text-cyan-700"
          }`}>
            {data.total} Records
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[850px] text-left text-sm">
            <thead className={`border-b text-xs uppercase tracking-wider ${tableHeaderClass}`}>
              <tr>
                <th className="px-5 py-4 font-semibold">URL / Domain</th>
                <th className="px-5 py-4 font-semibold">Event</th>
                <th className="px-5 py-4 font-semibold">Risk</th>
                <th className="px-5 py-4 font-semibold">Decision</th>
                <th className="px-5 py-4 font-semibold">Date</th>
              </tr>
            </thead>

            <tbody>
              {loading ? (
                <tr>
                  <td
                    colSpan={5}
                    className={`px-5 py-16 text-center ${secondaryText}`}
                  >
                    <RefreshCw
                      size={24}
                      className="mx-auto mb-3 animate-spin text-cyan-500"
                    />
                    Loading security events...
                  </td>
                </tr>
              ) : data.items.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-16 text-center">
                    <ShieldAlert
                      className={`mx-auto mb-3 ${mutedText}`}
                      size={34}
                    />
                    <p className={`font-semibold ${primaryText}`}>
                      No events found
                    </p>
                    <p className={`mt-1 text-xs ${secondaryText}`}>
                      Try changing the filters or checking a URL first.
                    </p>
                  </td>
                </tr>
              ) : (
                data.items.map((event) => (
                  <tr
                    key={event.id}
                    className={`border-b transition-colors duration-200 last:border-0 ${tableRowClass}`}
                  >
                    <td className="max-w-sm px-5 py-4">
                      <p
                        className={`truncate font-semibold ${primaryText}`}
                        title={event.url}
                      >
                        {event.domain || event.url}
                      </p>
                      <p
                        className={`mt-1 truncate text-xs ${secondaryText}`}
                        title={event.url}
                      >
                        {event.url}
                      </p>
                    </td>

                    <td className={`px-5 py-4 ${secondaryText}`}>
                      {event.event_type.replaceAll("_", " ")}
                    </td>

                    <td className="px-5 py-4">
                      <span
                        className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${badgeClass(event.risk_level, isDark)}`}
                      >
                        {event.risk_level}
                      </span>
                      <p className={`mt-2 text-xs ${secondaryText}`}>
                        Score: {event.risk_score}
                      </p>
                    </td>

                    <td className="px-5 py-4">
                      <span
                        className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${badgeClass(event.decision, isDark)}`}
                      >
                        {event.decision}
                      </span>
                    </td>

                    <td className={`whitespace-nowrap px-5 py-4 text-xs ${secondaryText}`}>
                      {event.created_at
                        ? new Date(event.created_at).toLocaleString()
                        : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className={`flex flex-wrap items-center justify-between gap-3 border-t px-5 py-4 ${
          isDark ? "border-white/10" : "border-slate-200"
        }`}>
          <p className={`text-xs ${secondaryText}`}>
            Showing {data.items.length} of {data.total} matching events
          </p>

          <div className="flex items-center gap-3">
            <button
              disabled={loading || page <= 1}
              onClick={() => setPage((current) => current - 1)}
              className={`rounded-xl border p-2.5 transition-all disabled:cursor-not-allowed disabled:opacity-30 ${buttonClass}`}
              aria-label="Previous page"
            >
              <ChevronLeft size={18} />
            </button>

            <span className={`min-w-[70px] text-center text-sm font-medium ${primaryText}`}>
              {data.total_pages ? data.page : 0} / {data.total_pages}
            </span>

            <button
              disabled={loading || page >= data.total_pages}
              onClick={() => setPage((current) => current + 1)}
              className={`rounded-xl border p-2.5 transition-all disabled:cursor-not-allowed disabled:opacity-30 ${buttonClass}`}
              aria-label="Next page"
            >
              <ChevronRight size={18} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
