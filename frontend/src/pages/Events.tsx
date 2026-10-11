
import { useCallback, useEffect, useState } from "react";
import { Search, RefreshCw, ChevronLeft, ChevronRight, ShieldAlert } from "lucide-react";
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

const badgeClass = (value: string) => {
  const key = value.toUpperCase();

  if (["CRITICAL", "HIGH", "BLOCK", "BLOCKED"].includes(key)) {
    return "bg-red-500/15 text-red-300 border-red-500/30";
  }

  if (["MEDIUM", "WARN", "WARNING"].includes(key)) {
    return "bg-amber-500/15 text-amber-300 border-amber-500/30";
  }

  if (["LOW", "ALLOW", "ALLOWED"].includes(key)) {
    return "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
  }

  return "bg-slate-500/15 text-slate-300 border-slate-500/30";
};

export default function Events() {
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
      setError("Unable to load security events. Check your login and backend connection.");
    } finally {
      setLoading(false);
    }
  }, [page, search, riskLevel, decision]);

  useEffect(() => {
    void loadEvents();
  }, [loadEvents]);

  const changeFilter = (
    setter: (value: string) => void,
    value: string,
  ) => {
    setter(value);
    setPage(1);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm text-cyan-300">MONITORING CENTER</p>
          <h1 className="mt-1 text-3xl font-bold text-white">
            Security Events
          </h1>
          <p className="mt-2 text-sm text-slate-400">
            Search, filter, and review URL security decisions.
          </p>
        </div>

        <button
          onClick={() => void loadEvents()}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50"
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">Matching events</p>
          <p className="mt-2 text-3xl font-bold text-white">{data.total}</p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">Current page</p>
          <p className="mt-2 text-3xl font-bold text-white">
            {data.total_pages ? data.page : 0}
            <span className="text-lg text-slate-500">
              {" "}/ {data.total_pages}
            </span>
          </p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">Events displayed</p>
          <p className="mt-2 text-3xl font-bold text-white">
            {data.items.length}
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
            onChange={(e) => changeFilter(setSearch, e.target.value)}
            placeholder="Search URL, domain, or event type..."
            className="w-full rounded-xl border border-slate-700 bg-slate-950 py-3 pl-10 pr-4 text-sm text-white outline-none focus:border-cyan-500"
          />
        </div>

        <select
          value={riskLevel}
          onChange={(e) => changeFilter(setRiskLevel, e.target.value)}
          className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-cyan-500"
        >
          <option value="">All risk levels</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>

        <select
          value={decision}
          onChange={(e) => changeFilter(setDecision, e.target.value)}
          className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-cyan-500"
        >
          <option value="">All decisions</option>
          <option value="ALLOW">Allow</option>
          <option value="WARN">Warn</option>
          <option value="BLOCK">Block</option>
        </select>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
          <button
            onClick={() => void loadEvents()}
            className="ml-2 underline"
          >
            Try again
          </button>
        </div>
      )}

      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[850px] text-left text-sm">
            <thead className="border-b border-slate-800 bg-slate-950/60 text-xs uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-5 py-4">URL / Domain</th>
                <th className="px-5 py-4">Event</th>
                <th className="px-5 py-4">Risk</th>
                <th className="px-5 py-4">Decision</th>
                <th className="px-5 py-4">Date</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-slate-800">
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-5 py-12 text-center text-slate-400">
                    Loading security events...
                  </td>
                </tr>
              ) : data.items.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-12 text-center">
                    <ShieldAlert className="mx-auto mb-3 text-slate-500" size={30} />
                    <p className="font-medium text-slate-300">No events found</p>
                    <p className="mt-1 text-xs text-slate-500">
                      Try changing the filters or checking a URL first.
                    </p>
                  </td>
                </tr>
              ) : (
                data.items.map((event) => (
                  <tr key={event.id} className="hover:bg-slate-800/40">
                    <td className="max-w-sm px-5 py-4">
                      <p className="truncate font-medium text-white" title={event.url}>
                        {event.domain || event.url}
                      </p>
                      <p className="mt-1 truncate text-xs text-slate-500" title={event.url}>
                        {event.url}
                      </p>
                    </td>

                    <td className="px-5 py-4 text-slate-300">
                      {event.event_type.replaceAll("_", " ")}
                    </td>

                    <td className="px-5 py-4">
                      <span className={`rounded-lg border px-2.5 py-1 text-xs font-semibold ${badgeClass(event.risk_level)}`}>
                        {event.risk_level}
                      </span>
                      <p className="mt-1 text-xs text-slate-500">
                        Score: {event.risk_score}
                      </p>
                    </td>

                    <td className="px-5 py-4">
                      <span className={`rounded-lg border px-2.5 py-1 text-xs font-semibold ${badgeClass(event.decision)}`}>
                        {event.decision}
                      </span>
                    </td>

                    <td className="whitespace-nowrap px-5 py-4 text-xs text-slate-400">
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

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 px-5 py-4">
          <p className="text-xs text-slate-400">
            Showing {data.items.length} of {data.total} matching events
          </p>

          <div className="flex items-center gap-3">
            <button
              disabled={loading || page <= 1}
              onClick={() => setPage((current) => current - 1)}
              className="rounded-lg border border-slate-700 p-2 text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
              aria-label="Previous page"
            >
              <ChevronLeft size={18} />
            </button>

            <span className="text-sm text-slate-300">
              {data.total_pages ? data.page : 0} / {data.total_pages}
            </span>

            <button
              disabled={loading || page >= data.total_pages}
              onClick={() => setPage((current) => current + 1)}
              className="rounded-lg border border-slate-700 p-2 text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
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
