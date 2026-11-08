
import { useEffect, useState } from "react";
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  BarChart3,
  TrendingUp,
  AlertTriangle,
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

function useThemeMode() {
  const [isDark, setIsDark] = useState(() => {
    if (typeof document === "undefined") return true;
    return document.documentElement.dataset.theme !== "light";
  });

  useEffect(() => {
    const root = document.documentElement;

    const updateTheme = () => {
      setIsDark(root.dataset.theme !== "light");
    };

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

function getLocalDateKey(date: Date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");

  return `${year}-${month}-${day}`;
}

function Analytics() {
  const isDark = useThemeMode();

  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const surface = isDark
    ? "border-white/[0.08] bg-slate-900/55 shadow-black/20"
    : "border-white/80 bg-white/65 shadow-slate-200/50";

  const heading = isDark
    ? "text-white"
    : "text-slate-900";

  const body = isDark
    ? "text-slate-400"
    : "text-slate-500";

  const subtle = isDark
    ? "text-slate-500"
    : "text-slate-400";

  const chartText = isDark ? "#94a3b8" : "#64748b";

  const chartGrid = isDark ? "#334155" : "#e2e8f0";

  const tooltipStyle = {
    backgroundColor: isDark ? "#0f172a" : "#ffffff",
    border: `1px solid ${isDark ? "#334155" : "#e2e8f0"}`,
    borderRadius: "14px",
    color: isDark ? "#f8fafc" : "#0f172a",
    boxShadow: "0 10px 30px rgba(0,0,0,0.12)",
  };

  async function loadAnalytics() {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<EventsResponse>("/api/events", {
        params: {
          page: 1,
          page_size: 100,
        },
      });

      setEvents(response.data.items || []);
      setTotal(response.data.total || 0);
    } catch {
      setError(
        "Unable to load analytics. Check the backend connection and login."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadAnalytics();
  }, []);

  // Risk distribution
  const riskData = RISK_LEVELS.map((level) => ({
    name: formatLabel(level),
    key: level,
    value: events.filter(
      (event) =>
        (event.risk_level || "").toUpperCase() === level
    ).length,
  }));

  // Security decisions
  const decisionData = DECISIONS.map((decision) => ({
    name: formatLabel(decision),
    key: decision,
    value: events.filter(
      (event) =>
        (event.decision || "").toUpperCase() === decision
    ).length,
  }));

  // Activity during the last seven days
  const activityMap = new Map<string, number>();

  for (let offset = 6; offset >= 0; offset--) {
    const date = new Date();
    date.setDate(date.getDate() - offset);

    activityMap.set(getLocalDateKey(date), 0);
  }

  events.forEach((event) => {
    if (!event.created_at) return;

    const date = new Date(event.created_at);

    if (Number.isNaN(date.getTime())) return;

    const key = getLocalDateKey(date);

    if (activityMap.has(key)) {
      activityMap.set(
        key,
        (activityMap.get(key) ?? 0) + 1
      );
    }
  });

  const activityData = Array.from(
    activityMap,
    ([date, count]) => ({
      date,
      day: new Date(`${date}T12:00:00`).toLocaleDateString(
        undefined,
        {
          month: "short",
          day: "numeric",
        }
      ),
      events: count,
    })
  );

  // Summary statistics
  const blocked = events.filter((event) =>
    ["BLOCK", "BLOCKED"].includes(
      (event.decision || "").toUpperCase()
    )
  ).length;

  const highRisk = events.filter((event) =>
    ["HIGH", "CRITICAL"].includes(
      (event.risk_level || "").toUpperCase()
    )
  ).length;

  const averageRisk = events.length
    ? Math.round(
        events.reduce(
          (sum, event) =>
            sum + (Number(event.risk_score) || 0),
          0
        ) / events.length
      )
    : 0;

  const allowed = events.filter((event) =>
    ["ALLOW", "ALLOWED"].includes(
      (event.decision || "").toUpperCase()
    )
  ).length;

  const warned = events.filter((event) =>
    ["WARN", "WARNING"].includes(
      (event.decision || "").toUpperCase()
    )
  ).length;

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 pb-5">

      {/* Page heading */}
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-500">
            <Activity size={15} />
            Security intelligence
          </div>

          <h1 className={`mt-2 text-3xl font-bold tracking-tight sm:text-4xl ${heading}`}>
            Analytics
          </h1>

          <p className={`mt-2 text-sm leading-6 ${body}`}>
            Visualize risk levels, security decisions and recent activity.
          </p>
        </div>

        <button
          type="button"
          onClick={() => void loadAnalytics()}
          disabled={loading}
          className={`inline-flex items-center gap-2 rounded-2xl border px-4 py-2.5 text-sm font-medium shadow-sm backdrop-blur-xl transition hover:-translate-y-0.5 disabled:opacity-50 ${surface} ${heading}`}
        >
          <RefreshCw
            size={16}
            className={loading ? "animate-spin" : ""}
          />
          Refresh
        </button>
      </header>

      {/* Error message */}
      {error && (
        <div className="flex items-start gap-2 rounded-2xl border border-red-500/25 bg-red-500/10 p-4 text-sm text-red-500">
          <AlertTriangle size={17} className="mt-0.5 shrink-0" />
          {error}
        </div>
      )}

      {/* Summary cards */}
      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">

        <div className={`rounded-2xl border p-5 shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className={`flex items-center gap-2 text-sm ${body}`}>
            <BarChart3 size={17} className="text-cyan-500" />
            Total matching events
          </div>

          <p className={`mt-3 text-3xl font-bold tabular-nums ${heading}`}>
            {total}
          </p>

          <p className={`mt-2 text-xs ${subtle}`}>
            Events recorded for your account
          </p>
        </div>

        <div className={`rounded-2xl border p-5 shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className="flex items-center gap-2 text-sm text-rose-500">
            <ShieldAlert size={18} />
            Blocked events
          </div>

          <p className={`mt-3 text-3xl font-bold tabular-nums ${heading}`}>
            {blocked}
          </p>

          <p className={`mt-2 text-xs ${subtle}`}>
            URLs marked for blocking
          </p>
        </div>

        <div className={`rounded-2xl border p-5 shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className="flex items-center gap-2 text-sm text-orange-500">
            <AlertTriangle size={18} />
            High / critical risks
          </div>

          <p className={`mt-3 text-3xl font-bold tabular-nums ${heading}`}>
            {highRisk}
          </p>

          <p className={`mt-2 text-xs ${subtle}`}>
            Events with elevated risk
          </p>
        </div>

        <div className={`rounded-2xl border p-5 shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className="flex items-center gap-2 text-sm text-emerald-500">
            <ShieldCheck size={18} />
            Average risk score
          </div>

          <p className={`mt-3 text-3xl font-bold tabular-nums ${heading}`}>
            {averageRisk}
            <span className={`text-base font-normal ${subtle}`}>
              {" "}/ 100
            </span>
          </p>

          <p className={`mt-2 text-xs ${subtle}`}>
            Average score of loaded events
          </p>
        </div>

      </section>

      {/* Decision summary */}
      <section className={`rounded-2xl border p-5 shadow-lg backdrop-blur-2xl ${surface}`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className={`font-semibold ${heading}`}>
              Security overview
            </h2>

            <p className={`mt-1 text-xs ${body}`}>
              Distribution of decisions in the loaded records
            </p>
          </div>

          <TrendingUp size={20} className="text-cyan-500" />
        </div>

        <div className="mt-5 grid grid-cols-3 gap-3">
          <div className={`rounded-xl border p-3 ${isDark ? "border-emerald-500/20 bg-emerald-500/5" : "border-emerald-500/20 bg-emerald-50/70"}`}>
            <p className="text-xs text-emerald-500">Allowed</p>
            <p className={`mt-2 text-2xl font-bold ${heading}`}>
              {allowed}
            </p>
          </div>

          <div className={`rounded-xl border p-3 ${isDark ? "border-amber-500/20 bg-amber-500/5" : "border-amber-500/20 bg-amber-50/70"}`}>
            <p className="text-xs text-amber-500">Warnings</p>
            <p className={`mt-2 text-2xl font-bold ${heading}`}>
              {warned}
            </p>
          </div>

          <div className={`rounded-xl border p-3 ${isDark ? "border-rose-500/20 bg-rose-500/5" : "border-rose-500/20 bg-rose-50/70"}`}>
            <p className="text-xs text-rose-500">Blocked</p>
            <p className={`mt-2 text-2xl font-bold ${heading}`}>
              {blocked}
            </p>
          </div>
        </div>
      </section>

      {/* Charts */}
      <div className="grid gap-6 xl:grid-cols-2">

        {/* Risk distribution */}
        <section className={`rounded-[24px] border p-5 shadow-lg backdrop-blur-2xl sm:p-6 ${surface}`}>
          <h2 className={`font-semibold ${heading}`}>
            Risk distribution
          </h2>

          <p className={`mt-1 text-xs ${body}`}>
            Events grouped by detected risk level
          </p>

          <div className="mt-5 h-72">
            {loading ? (
              <div className={`flex h-full items-center justify-center gap-2 text-sm ${body}`}>
                <RefreshCw size={17} className="animate-spin text-cyan-500" />
                Loading chart...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="45%"
                    outerRadius={95}
                    innerRadius={58}
                    paddingAngle={3}
                    stroke="none"
                  >
                    {riskData.map((entry) => (
                      <Cell
                        key={entry.key}
                        fill={COLORS[entry.key]}
                      />
                    ))}
                  </Pie>

                  <Tooltip
                    contentStyle={tooltipStyle}
                    itemStyle={{
                      color: isDark ? "#f8fafc" : "#334155",
                    }}
                  />

                  <Legend
                    formatter={(value) => (
                      <span style={{ color: chartText, fontSize: 12 }}>
                        {value}
                      </span>
                    )}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </section>

        {/* Security decisions */}
        <section className={`rounded-[24px] border p-5 shadow-lg backdrop-blur-2xl sm:p-6 ${surface}`}>
          <h2 className={`font-semibold ${heading}`}>
            Security decisions
          </h2>

          <p className={`mt-1 text-xs ${body}`}>
            Allow, warn and block decisions in loaded events
          </p>

          <div className="mt-5 h-72">
            {loading ? (
              <div className={`flex h-full items-center justify-center gap-2 text-sm ${body}`}>
                <RefreshCw size={17} className="animate-spin text-cyan-500" />
                Loading chart...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={decisionData}
                  margin={{
                    top: 10,
                    right: 10,
                    left: -15,
                    bottom: 5,
                  }}
                >
                  <CartesianGrid
                    stroke={chartGrid}
                    strokeDasharray="3 3"
                    vertical={false}
                  />

                  <XAxis
                    dataKey="name"
                    stroke={chartText}
                    tick={{ fontSize: 12 }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <YAxis
                    allowDecimals={false}
                    stroke={chartText}
                    tick={{ fontSize: 12 }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <Tooltip
                    contentStyle={tooltipStyle}
                  />

                  <Bar
                    dataKey="value"
                    name="Events"
                    radius={[8, 8, 0, 0]}
                    maxBarSize={65}
                  >
                    {decisionData.map((entry) => (
                      <Cell
                        key={entry.key}
                        fill={COLORS[entry.key]}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </section>

      </div>

      {/* Activity chart */}
      <section className={`rounded-[24px] border p-5 shadow-lg backdrop-blur-2xl sm:p-6 ${surface}`}>
        <h2 className={`font-semibold ${heading}`}>
          Activity — last 7 days
        </h2>

        <p className={`mt-1 text-xs ${body}`}>
          Recorded events by date, based on the latest 100 loaded records
        </p>

        <div className="mt-5 h-72">
          {loading ? (
            <div className={`flex h-full items-center justify-center gap-2 text-sm ${body}`}>
              <RefreshCw size={17} className="animate-spin text-cyan-500" />
              Loading activity...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={activityData}
                margin={{
                  top: 10,
                  right: 10,
                  left: -15,
                  bottom: 5,
                }}
              >
                <CartesianGrid
                  stroke={chartGrid}
                  strokeDasharray="3 3"
                  vertical={false}
                />

                <XAxis
                  dataKey="day"
                  stroke={chartText}
                  tick={{ fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />

                <YAxis
                  allowDecimals={false}
                  stroke={chartText}
                  tick={{ fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />

                <Tooltip
                  contentStyle={tooltipStyle}
                />

                <Bar
                  dataKey="events"
                  name="Events"
                  fill="#06b6d4"
                  radius={[8, 8, 0, 0]}
                  maxBarSize={55}
                />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </section>

      {/* Footer note */}
      <p className={`text-xs leading-5 ${subtle}`}>
        Charts use up to 100 recent events returned by the API. They are not
        necessarily totals across the entire database. Detection results
        depend on the checks currently implemented in your backend.
      </p>

    </div>
  );
}

export default Analytics;
