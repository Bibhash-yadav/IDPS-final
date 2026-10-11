
import { useEffect, useState } from "react";
import { Activity, ShieldCheck, ShieldAlert, Ban } from "lucide-react";
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

  useEffect(() => {
    let active = true;

    async function loadDashboard() {
      try {
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
          setError("Unable to load dashboard data. Check your connection.");
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

  const cards = [
    { label: "URLs Checked", value: stats?.total_urls_checked ?? 0, icon: Activity },
    { label: "Safe Websites", value: stats?.safe_websites ?? 0, icon: ShieldCheck },
    { label: "Warnings", value: stats?.warnings ?? 0, icon: ShieldAlert },
    { label: "Blocked", value: stats?.blocked_websites ?? 0, icon: Ban },
  ];

  return (
    <main className="min-h-screen bg-[#080d18] p-5 text-slate-100 md:p-8">
      <header className="mb-8">
        <p className="text-sm text-cyan-400">SECURITY OPERATIONS CENTER</p>
        <h1 className="mt-2 text-3xl font-bold">Security Dashboard</h1>
        <p className="mt-2 text-sm text-slate-400">
          Your security activity, based on saved database events.
        </p>
      </header>

      {loading && <p className="text-slate-400">Loading statistics...</p>}

      {error && (
        <p role="alert" className="mb-5 rounded-lg bg-red-500/10 p-4 text-red-300">
          {error}
        </p>
      )}

      {stats && (
        <>
          <section className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {cards.map(({ label, value, icon: Icon }) => (
              <article
                key={label}
                className="rounded-xl border border-slate-800 bg-[#101827] p-5"
              >
                <div className="flex items-center justify-between">
                  <p className="text-sm text-slate-400">{label}</p>
                  <Icon size={20} className="text-cyan-400" />
                </div>
                <p className="mt-4 text-3xl font-bold">{value.toLocaleString()}</p>
              </article>
            ))}
          </section>

          <section className="mb-8 grid grid-cols-1 gap-4 md:grid-cols-3">
            <article className="rounded-xl border border-slate-800 bg-[#101827] p-5">
              <p className="text-sm text-slate-400">Malware detections</p>
              <p className="mt-2 text-2xl font-bold">{stats.malware_detected}</p>
            </article>
            <article className="rounded-xl border border-slate-800 bg-[#101827] p-5">
              <p className="text-sm text-slate-400">Phishing detections</p>
              <p className="mt-2 text-2xl font-bold">{stats.phishing_detected}</p>
            </article>
            <article className="rounded-xl border border-slate-800 bg-[#101827] p-5">
              <p className="text-sm text-slate-400">Protection status</p>
              <p className="mt-2 font-semibold text-emerald-400">
                {stats.protection_status}
              </p>
            </article>
          </section>

          <section className="overflow-hidden rounded-xl border border-slate-800 bg-[#101827]">
            <div className="border-b border-slate-800 p-5">
              <h2 className="text-lg font-semibold">Recent Security Events</h2>
              <p className="mt-1 text-sm text-slate-400">
                Latest URL checks saved to your account.
              </p>
            </div>

            {events.length === 0 ? (
              <p className="p-6 text-sm text-slate-400">
                No security events yet. Check a URL to begin.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-slate-400">
                    <tr>
                      <th className="p-4">Domain</th>
                      <th className="p-4">Event</th>
                      <th className="p-4">Risk</th>
                      <th className="p-4">Decision</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((event) => (
                      <tr key={event.id} className="border-t border-slate-800">
                        <td className="p-4">{event.domain}</td>
                        <td className="p-4">{event.event_type}</td>
                        <td className="p-4">{event.risk_score}/100</td>
                        <td className="p-4">{event.decision}</td>
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
