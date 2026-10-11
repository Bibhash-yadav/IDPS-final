
import { useEffect, useState } from "react";
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
} from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
} from "recharts";
import api from "../services/api";

type SecurityEvent = {
  id: number;
  url: string;
  domain: string;
  event_type: string;
  risk_score: number;
  risk_level: string;
  decision: string;
  created_at: string | null;
};

type EventsResponse = {
  items: SecurityEvent[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

const RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const DECISIONS = ["ALLOW", "WARN", "BLOCK"];

const COLORS: Record<string, string> = {
  LOW: "#34d399",
  MEDIUM: "#fbbf24",
  HIGH: "#fb923c",
  CRITICAL: "#f87171",
  ALLOW: "#34d399",
  WARN: "#fbbf24",
  BLOCK: "#f87171",
};

function formatLabel(value: string) {
  return value.charAt(0) + value.slice(1).toLowerCase();
}

export default function Analytics() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadAnalytics() {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<EventsResponse>("/api/events", {
        params: { page: 1, page_size: 100 },
      });

      setEvents(response.data.items);
      setTotal(response.data.total);
    } catch {
      setError("Unable to load analytics. Check the backend connection and login.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadAnalytics();
  }, []);

  const riskData = RISK_LEVELS.map((level) => ({
    name: formatLabel(level),
    key: level,
    value: events.filter(
      (event) => event.risk_level.toUpperCase() === level,
    ).length,
  }));

  const decisionData = DECISIONS.map((decision) => ({
    name: formatLabel(decision),
    key: decision,
    value: events.filter(
      (event) => event.decision.toUpperCase() === decision,
    ).length,
  }));

  const activityMap = new Map<string, number>();

  for (let offset = 6; offset >= 0; offset--) {
    const date = new Date();
    date.setDate(date.getDate() - offset);
    const key = date.toLocaleDateString("en-CA");
    activityMap.set(key, 0);
  }

  events.forEach((event) => {
    if (!event.created_at) return;

    const date = new Date(event.created_at);
    if (Number.isNaN(date.getTime())) return;

    const key = date.toLocaleDateString("en-CA");

    if (activityMap.has(key)) {
      activityMap.set(key, (activityMap.get(key) ?? 0) + 1);
    }
  });

  const activityData = Array.from(activityMap, ([date, count]) => ({
    date,
    day: new Date(`${date}T12:00:00`).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
    }),
    events: count,
  }));

  const blocked = events.filter((event) =>
    ["BLOCK", "BLOCKED"].includes(event.decision.toUpperCase()),
  ).length;

  const highRisk = events.filter((event) =>
    ["HIGH", "CRITICAL"].includes(event.risk_level.toUpperCase()),
  ).length;

  const averageRisk = events.length
    ? Math.round(
        events.reduce((sum, event) => sum + event.risk_score, 0) /
          events.length,
      )
    : 0;

  if (loading) {
    return (
      <div className="flex min-h-64 items-center justify-center gap-3 text-slate-400">
        <Activity className="animate-pulse" />
        Loading analytics...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-cyan-300">
            SECURITY INTELLIGENCE
          </p>
          <h1 className="mt-1 text-3xl font-bold text-white">Analytics</h1>
          <p className="mt-2 text-sm text-slate-400">
            Visualize risk levels, decisions, and recent security activity.
          </p>
        </div>

        <button
          onClick={() => void loadAnalytics()}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-800"
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">Total matching events</p>
          <p className="mt-2 text-3xl font-bold text-white">{total}</p>
          <p className="mt-2 text-xs text-slate-500">
            Events recorded for your account
          </p>
        </div>

        <div className="rounded-2xl border border-red-500/20 bg-slate-900/70 p-5">
          <div className="flex items-center gap-2 text-red-300">
            <ShieldAlert size={18} />
            <p className="text-sm">Blocked in loaded events</p>
          </div>
          <p className="mt-2 text-3xl font-bold text-white">{blocked}</p>
        </div>

        <div className="rounded-2xl border border-orange-500/20 bg-slate-900/70 p-5">
          <p className="text-sm text-slate-400">High / critical risks</p>
          <p className="mt-2 text-3xl font-bold text-white">{highRisk}</p>
        </div>

        <div className="rounded-2xl border border-emerald-500/20 bg-slate-900/70 p-5">
          <div className="flex items-center gap-2 text-emerald-300">
            <ShieldCheck size={18} />
            <p className="text-sm">Average risk score</p>
          </div>
          <p className="mt-2 text-3xl font-bold text-white">
            {averageRisk}<span className="text-base text-slate-500"> / 100</span>
          </p>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <h2 className="font-semibold text-white">Risk distribution</h2>
          <p className="mt-1 text-xs text-slate-400">
            Events grouped by detected risk level
          </p>

          <div className="mt-5 h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="45%"
                  outerRadius={90}
                  innerRadius={55}
                  paddingAngle={3}
                >
                  {riskData.map((entry) => (
                    <Cell key={entry.key} fill={COLORS[entry.key]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: 12,
                    color: "#f8fafc",
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <h2 className="font-semibold text-white">Security decisions</h2>
          <p className="mt-1 text-xs text-slate-400">
            Allow, warn, and block decisions in the loaded events
          </p>

          <div className="mt-5 h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={decisionData}>
                <CartesianGrid stroke="#263244" strokeDasharray="3 3" />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis allowDecimals={false} stroke="#94a3b8" />
                <Tooltip
                  contentStyle={{
                    background: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: 12,
                    color: "#f8fafc",
                  }}
                />
                <Bar dataKey="value" name="Events" radius={[6, 6, 0, 0]}>
                  {decisionData.map((entry) => (
                    <Cell key={entry.key} fill={COLORS[entry.key]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
        <h2 className="font-semibold text-white">Activity — last 7 days</h2>
        <p className="mt-1 text-xs text-slate-400">
          Recorded events by date, based on the latest 100 loaded records
        </p>

        <div className="mt-5 h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={activityData}>
              <CartesianGrid stroke="#263244" strokeDasharray="3 3" />
              <XAxis dataKey="day" stroke="#94a3b8" />
              <YAxis allowDecimals={false} stroke="#94a3b8" />
              <Tooltip
                contentStyle={{
                  background: "#0f172a",
                  border: "1px solid #334155",
                  borderRadius: 12,
                  color: "#f8fafc",
                }}
              />
              <Bar
                dataKey="events"
                name="Events"
                fill="#22d3ee"
                radius={[6, 6, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <p className="text-xs text-slate-500">
        Charts use up to 100 recent events returned by the API. They are not
        necessarily totals across the entire database. Detection results depend
        on the checks currently implemented in your backend.
      </p>
    </div>
  );
}
