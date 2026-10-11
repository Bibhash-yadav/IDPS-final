
import { useEffect, useState } from "react";
import {
  UserRound,
  Mail,
  ShieldCheck,
  CalendarDays,
  RefreshCw,
  Info,
} from "lucide-react";
import api from "../services/api";

type ProfileData = {
  id: number | string;
  name: string;
  email: string;
  role?: string;
  created_at?: string | null;
};

export default function Profile() {
  const [profile, setProfile] = useState<ProfileData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadProfile() {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<ProfileData>("/api/auth/me");
      setProfile(response.data);
    } catch {
      setError(
        "Unable to load your profile. Please check your login session and backend connection.",
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadProfile();
  }, []);

  if (loading) {
    return (
      <div className="flex min-h-64 items-center justify-center gap-3 text-slate-400">
        <RefreshCw size={20} className="animate-spin" />
        Loading your profile...
      </div>
    );
  }

  if (error || !profile) {
    return (
      <div className="space-y-4">
        <h1 className="text-3xl font-bold text-white">My Profile</h1>
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error || "Profile information is unavailable."}
        </div>
        <button
          onClick={() => void loadProfile()}
          className="inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-400"
        >
          <RefreshCw size={16} />
          Retry
        </button>
      </div>
    );
  }

  const initial = profile.name?.trim().charAt(0).toUpperCase() || "U";

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-cyan-300">
            ACCOUNT INFORMATION
          </p>
          <h1 className="mt-1 text-3xl font-bold text-white">My Profile</h1>
          <p className="mt-2 text-sm text-slate-400">
            View your registered account information.
          </p>
        </div>

        <button
          onClick={() => void loadProfile()}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-800"
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70">
        <div className="h-28 bg-gradient-to-r from-cyan-900/70 via-blue-900/50 to-slate-900" />

        <div className="px-6 pb-6">
          <div className="-mt-10 flex flex-wrap items-end gap-4">
            <div className="flex h-20 w-20 items-center justify-center rounded-2xl border-4 border-slate-900 bg-cyan-500 text-3xl font-bold text-slate-950">
              {initial}
            </div>

            <div className="pb-1">
              <h2 className="text-2xl font-bold text-white">
                {profile.name}
              </h2>
              <p className="mt-1 text-sm text-slate-400">{profile.email}</p>
            </div>

            <span className="mb-1 ml-auto rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-300">
              Authenticated
            </span>
          </div>

          <div className="mt-8 grid gap-4 sm:grid-cols-2">
            <ProfileCard
              icon={<UserRound size={20} />}
              label="Full name"
              value={profile.name}
            />

            <ProfileCard
              icon={<Mail size={20} />}
              label="Registered email"
              value={profile.email}
            />

            <ProfileCard
              icon={<ShieldCheck size={20} />}
              label="Account role"
              value={profile.role || "USER"}
            />

            <ProfileCard
              icon={<CalendarDays size={20} />}
              label="Account created"
              value={
                profile.created_at
                  ? new Date(profile.created_at).toLocaleDateString()
                  : "Not provided by API"
              }
            />
          </div>
        </div>
      </section>

      <div className="flex gap-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
        <Info size={20} className="mt-0.5 shrink-0 text-cyan-300" />
        <p className="text-sm leading-6 text-slate-300">
          Your profile is read directly from the authenticated backend.
          Editing account details and changing your password are not
          implemented on this page yet.
        </p>
      </div>
    </div>
  );
}

function ProfileCard({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
      <div className="flex items-center gap-2 text-cyan-300">
        {icon}
        <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
          {label}
        </span>
      </div>
      <p className="mt-3 break-all font-medium text-white">{value}</p>
    </div>
  );
}
