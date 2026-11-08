
import { useEffect, useState } from "react";
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  Ban,
  Bug,
  Fish,
  Globe,
  ArrowUpRight,
  Clock,
  Shield,
  RefreshCw,
} from "lucide-react";

import api from "../services/api";

interface Stats {
  total_urls_checked: number;
  safe_websites: number;
  warnings: number;
  blocked_websites: number;
  malware_detected: number;
  phishing_detected: number;
  security_events_last_7_days: number;
  protection_status: string;
}

interface SecurityEvent {
  id: number;
  domain: string;
  event_type: string;
  risk_score: number;
  decision: string;
  created_at: string | null;
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  // Read theme selected in DashboardLayout
  const [isDark, setIsDark] = useState(() => {
    return (
      document.documentElement.dataset.theme !== "light"
    );
  });

  // Keep dashboard synchronized with global theme
  useEffect(() => {
    const observer = new MutationObserver(() => {
      setIsDark(
        document.documentElement.dataset.theme !== "light"
      );
    });

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });

    return () => observer.disconnect();
  }, []);

  // Load dashboard data
  useEffect(() => {
    let active = true;

    async function loadDashboard() {
      try {
        setError("");

        const [statsResponse, eventsResponse] = await Promise.all([
          api.get<Stats>("/api/dashboard/stats"),
          api.get<SecurityEvent[]>("/api/dashboard/events"),
        ]);

        if (active) {
          setStats(statsResponse.data);
          setEvents(eventsResponse.data);
        }
      } catch {
        if (active) {
          setError(
            "Unable to load dashboard data. Check your connection."
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    void loadDashboard();

    return () => {
      active = false;
    };
  }, []);

  // Theme styles
  const theme = {
    heading: isDark ? "text-white" : "text-slate-900",
    text: isDark ? "text-slate-400" : "text-slate-600",
    muted: isDark ? "text-slate-500" : "text-slate-500",

    card: isDark
      ? "border-white/[0.09] bg-slate-900/55 shadow-black/10"
      : "border-white/80 bg-white/65 shadow-slate-300/30",

    innerCard: isDark
      ? "border-white/[0.07] bg-white/[0.035]"
      : "border-slate-200/70 bg-white/55",

    divider: isDark
      ? "border-white/[0.08]"
      : "border-slate-200/80",

    tableHeader: isDark
      ? "bg-white/[0.025] text-slate-400"
      : "bg-slate-100/60 text-slate-600",

    rowHover: isDark
      ? "hover:bg-white/[0.035]"
      : "hover:bg-blue-50/60",
  };

  const cards = [
    {
      label: "URLs Checked",
      value: stats?.total_urls_checked ?? 0,
      icon: Activity,
      color: "text-cyan-500",
      iconBg: "bg-cyan-500/10",
      description: "Total scanned websites",
    },
    {
      label: "Safe Websites",
      value: stats?.safe_websites ?? 0,
      icon: ShieldCheck,
      color: "text-emerald-500",
      iconBg: "bg-emerald-500/10",
      description: "Verified safe websites",
    },
    {
      label: "Warnings",
      value: stats?.warnings ?? 0,
      icon: ShieldAlert,
      color: "text-amber-500",
      iconBg: "bg-amber-500/10",
      description: "Potential security risks",
    },
    {
      label: "Blocked",
      value: stats?.blocked_websites ?? 0,
      icon: Ban,
      color: "text-rose-500",
      iconBg: "bg-rose-500/10",
      description: "Blocked dangerous websites",
    },
  ];

  function getDecisionStyle(decision: string) {
    const value = decision.toLowerCase();

    if (
      value.includes("block") ||
      value.includes("malicious") ||
      value.includes("danger")
    ) {
      return isDark
        ? "border-rose-400/20 bg-rose-400/10 text-rose-300"
        : "border-rose-200 bg-rose-50 text-rose-700";
    }

    if (
      value.includes("warn") ||
      value.includes("suspicious")
    ) {
      return isDark
        ? "border-amber-400/20 bg-amber-400/10 text-amber-300"
        : "border-amber-200 bg-amber-50 text-amber-700";
    }

    if (
      value.includes("safe") ||
      value.includes("allow")
    ) {
      return isDark
        ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
        : "border-emerald-200 bg-emerald-50 text-emerald-700";
    }

    return isDark
      ? "border-white/10 bg-white/5 text-slate-300"
      : "border-slate-200 bg-slate-100 text-slate-600";
  }

  function formatDate(date: string | null) {
    if (!date) return "—";

    const parsed = new Date(date);

    if (Number.isNaN(parsed.getTime())) return "—";

    return parsed.toLocaleString();
  }

  return (
    <main className="relative min-h-full space-y-7">

      {/* Dashboard Heading */}
      <section className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">

        <div>
          <div className="mb-2 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-500 shadow-[0_0_10px_rgba(34,211,238,0.7)]" />
            <p className="text-[11px] font-bold tracking-[2px] text-cyan-500">
              SECURITY OPERATIONS CENTER
            </p>
          </div>

          <h1 className={`text-2xl font-bold tracking-tight md:text-3xl ${theme.heading}`}>
            Security Dashboard
          </h1>

          <p className={`mt-2 text-sm ${theme.text}`}>
            Monitor your security activity and threat intelligence.
          </p>
        </div>

        <div className={`flex w-fit items-center gap-2 rounded-2xl border px-4 py-2.5 backdrop-blur-xl ${theme.card}`}>
          <Shield size={16} className="text-emerald-500" />

          <span className={`text-xs font-medium ${theme.text}`}>
            Security monitoring
          </span>
        </div>
      </section>

      {/* Loading */}
      {loading && (
        <div className={`flex items-center gap-3 rounded-2xl border p-5 backdrop-blur-xl ${theme.card}`}>
          <RefreshCw size={18} className="animate-spin text-cyan-500" />
          <p className={`text-sm ${theme.text}`}>
            Loading security statistics...
          </p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div
          role="alert"
          className="rounded-2xl border border-red-400/20 bg-red-500/10 p-4 text-sm text-red-500 backdrop-blur-xl"
        >
          {error}
        </div>
      )}

      {/* Statistics Cards */}
      {stats && (
        <>
          <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

            {cards.map(
              ({
                label,
                value,
                icon: Icon,
                color,
                iconBg,
                description,
              }) => (
                <article
                  key={label}
                  className={`group relative overflow-hidden rounded-[24px] border p-5 shadow-xl backdrop-blur-2xl transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl ${theme.card}`}
                >
                  {/* Decorative glow */}
                  <div className={`pointer-events-none absolute -right-10 -top-10 h-32 w-32 rounded-full blur-[55px] ${iconBg}`} />

                  <div className="relative flex items-center justify-between">
                    <p className={`text-sm font-medium ${theme.text}`}>
                      {label}
                    </p>

                    <div className={`flex h-11 w-11 items-center justify-center rounded-2xl ${iconBg}`}>
                      <Icon size={21} className={color} />
                    </div>
                  </div>

                  <div className="relative mt-5">
                    <h2 className={`text-3xl font-bold tracking-tight ${theme.heading}`}>
                      {value.toLocaleString()}
                    </h2>

                    <p className={`mt-2 text-xs ${theme.muted}`}>
                      {description}
                    </p>
                  </div>

                  <div className={`mt-5 h-1 overflow-hidden rounded-full ${isDark ? "bg-white/5" : "bg-slate-200"}`}>
                    <div className={`h-full w-1/3 rounded-full ${color.replace("text-", "bg-")} opacity-60`} />
                  </div>
                </article>
              )
            )}
          </section>

          {/* Threat Intelligence Overview */}
          <section>
            <div className="mb-4">
              <h2 className={`text-lg font-semibold ${theme.heading}`}>
                Threat Intelligence
              </h2>

              <p className={`mt-1 text-xs ${theme.text}`}>
                Detection statistics and protection status.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">

              {/* Malware */}
              <article className={`rounded-[24px] border p-5 backdrop-blur-2xl transition hover:-translate-y-1 ${theme.card}`}>
                <div className="flex items-center justify-between">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-rose-500/10">
                    <Bug size={20} className="text-rose-500" />
                  </div>
                  <ArrowUpRight size={17} className={theme.muted} />
                </div>

                <p className={`mt-4 text-sm ${theme.text}`}>
                  Malware Detections
                </p>

                <h3 className={`mt-2 text-2xl font-bold ${theme.heading}`}>
                  {stats.malware_detected.toLocaleString()}
                </h3>
              </article>

              {/* Phishing */}
              <article className={`rounded-[24px] border p-5 backdrop-blur-2xl transition hover:-translate-y-1 ${theme.card}`}>
                <div className="flex items-center justify-between">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500/10">
                    <Fish size={20} className="text-amber-500" />
                  </div>
                  <ArrowUpRight size={17} className={theme.muted} />
                </div>

                <p className={`mt-4 text-sm ${theme.text}`}>
                  Phishing Detections
                </p>

                <h3 className={`mt-2 text-2xl font-bold ${theme.heading}`}>
                  {stats.phishing_detected.toLocaleString()}
                </h3>
              </article>

              {/* Security Events */}
              <article className={`rounded-[24px] border p-5 backdrop-blur-2xl transition hover:-translate-y-1 ${theme.card}`}>
                <div className="flex items-center justify-between">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-500/10">
                    <Globe size={20} className="text-blue-500" />
                  </div>
                  <ArrowUpRight size={17} className={theme.muted} />
                </div>

                <p className={`mt-4 text-sm ${theme.text}`}>
                  Events · Last 7 Days
                </p>

                <h3 className={`mt-2 text-2xl font-bold ${theme.heading}`}>
                  {stats.security_events_last_7_days.toLocaleString()}
                </h3>
              </article>

              {/* Protection */}
              <article className={`rounded-[24px] border p-5 backdrop-blur-2xl transition hover:-translate-y-1 ${theme.card}`}>
                <div className="flex items-center justify-between">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/10">
                    <ShieldCheck size={20} className="text-emerald-500" />
                  </div>
                  <span className="h-2 w-2 rounded-full bg-emerald-500" />
                </div>

                <p className={`mt-4 text-sm ${theme.text}`}>
                  Protection Status
                </p>

                <h3 className="mt-2 truncate text-xl font-bold text-emerald-500">
                  {stats.protection_status}
                </h3>
              </article>
            </div>
          </section>

          {/* Recent Security Events */}
          <section className={`overflow-hidden rounded-[26px] border shadow-xl backdrop-blur-2xl ${theme.card}`}>

            <div className={`flex flex-col justify-between gap-3 border-b p-5 sm:flex-row sm:items-center ${theme.divider}`}>
              <div>
                <div className="flex items-center gap-2">
                  <Activity size={19} className="text-cyan-500" />

                  <h2 className={`text-lg font-semibold ${theme.heading}`}>
                    Recent Security Events
                  </h2>
                </div>

                <p className={`mt-1 text-xs ${theme.text}`}>
                  Latest URL checks saved to your account.
                </p>
              </div>

              <div className={`flex w-fit items-center gap-2 rounded-full border px-3 py-1.5 ${theme.innerCard}`}>
                <Clock size={13} className={theme.text} />
                <span className={`text-[11px] ${theme.text}`}>
                  Latest activity
                </span>
              </div>
            </div>

            {events.length === 0 ? (
              <div className="flex flex-col items-center justify-center px-5 py-14 text-center">
                <div className={`mb-4 flex h-14 w-14 items-center justify-center rounded-2xl ${theme.innerCard}`}>
                  <ShieldCheck size={26} className="text-cyan-500" />
                </div>

                <h3 className={`font-semibold ${theme.heading}`}>
                  No Security Events Yet
                </h3>

                <p className={`mt-2 max-w-sm text-sm ${theme.text}`}>
                  Check a URL to start monitoring security events and threat activity.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[750px] text-left text-sm">

                  <thead className={theme.tableHeader}>
                    <tr>
                      <th className="px-5 py-4 font-semibold">Domain</th>
                      <th className="px-5 py-4 font-semibold">Event Type</th>
                      <th className="px-5 py-4 font-semibold">Risk Score</th>
                      <th className="px-5 py-4 font-semibold">Decision</th>
                      <th className="px-5 py-4 font-semibold">Date</th>
                    </tr>
                  </thead>

                  <tbody>
                    {events.map((event) => (
                      <tr
                        key={event.id}
                        className={`border-t transition-colors ${theme.divider} ${theme.rowHover}`}
                      >
                        <td className={`px-5 py-4 font-medium ${theme.heading}`}>
                          <div className="flex items-center gap-2">
                            <Globe size={15} className="shrink-0 text-cyan-500" />
                            {event.domain}
                          </div>
                        </td>

                        <td className={`px-5 py-4 ${theme.text}`}>
                          {event.event_type}
                        </td>

                        <td className="px-5 py-4">
                          <div className="flex items-center gap-2">
                            <span className={`font-semibold ${
                              event.risk_score >= 70
                                ? "text-rose-500"
                                : event.risk_score >= 40
                                  ? "text-amber-500"
                                  : "text-emerald-500"
                            }`}>
                              {event.risk_score}/100
                            </span>
                          </div>
                        </td>

                        <td className="px-5 py-4">
                          <span className={`inline-flex rounded-full border px-3 py-1 text-[11px] font-semibold ${getDecisionStyle(event.decision)}`}>
                            {event.decision}
                          </span>
                        </td>

                        <td className={`px-5 py-4 text-xs ${theme.text}`}>
                          {formatDate(event.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>

                </table>
              </div>
            )}
          </section>
        </>
      )}
    </main>
  );
}
