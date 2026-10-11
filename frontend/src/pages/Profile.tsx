
import { useCallback, useEffect, useState } from "react";
import {
  UserRound,
  Mail,
  ShieldCheck,
  CalendarDays,
  RefreshCw,
  Info,
  Cake,
  Clock,
  CheckCircle2,
  AlertCircle,
} from "lucide-react";
import api from "../services/api";

type ProfileData = {
  id: number | string;
  name: string;
  email: string;
  role?: string | null;
  date_of_birth?: string | null;
  age?: number | null;
  created_at?: string | null;
};

function calculateAge(dateOfBirth?: string | null): number | null {
  if (!dateOfBirth) return null;

  const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(dateOfBirth);
  if (!match) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);

  const dob = new Date(year, month - 1, day);

  if (
    dob.getFullYear() !== year ||
    dob.getMonth() !== month - 1 ||
    dob.getDate() !== day
  ) {
    return null;
  }

  const today = new Date();
  if (dob > today) return null;

  let age = today.getFullYear() - year;

  if (
    today.getMonth() < month - 1 ||
    (today.getMonth() === month - 1 && today.getDate() < day)
  ) {
    age--;
  }

  return age;
}

function formatDate(value?: string | null): string {
  if (!value) return "Not provided";

  // Handle date-only values without timezone shifting.
  const dateOnly = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);

  const date = dateOnly
    ? new Date(
        Number(dateOnly[1]),
        Number(dateOnly[2]) - 1,
        Number(dateOnly[3]),
      )
    : new Date(value);

  if (Number.isNaN(date.getTime())) return "Not provided";

  return date.toLocaleDateString(undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
  });
}

export default function Profile() {
  const [profile, setProfile] = useState<ProfileData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadProfile = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<ProfileData>("/api/auth/me");

      if (!response.data || !response.data.email) {
        throw new Error("Invalid profile response");
      }

      setProfile(response.data);
    } catch {
      setProfile(null);
      setError(
        "Unable to load your profile. Please check your login session and backend connection.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadProfile();
  }, [loadProfile]);

  if (loading) {
    return (
      <div className="flex min-h-64 items-center justify-center gap-3 text-slate-400">
        <RefreshCw
          size={20}
          className="animate-spin text-cyan-400"
        />
        <span>Loading your profile...</span>
      </div>
    );
  }

  if (error || !profile) {
    return (
      <div className="mx-auto w-full max-w-5xl space-y-5">
        <div>
          <p className="text-sm font-medium tracking-wider text-cyan-300">
            ACCOUNT INFORMATION
          </p>
          <h1 className="mt-1 text-3xl font-bold text-white">
            My Profile
          </h1>
        </div>

        <div className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm leading-6 text-red-300">
          <AlertCircle size={20} className="mt-0.5 shrink-0" />
          <p>{error || "Profile information is unavailable."}</p>
        </div>

        <button
          type="button"
          onClick={() => void loadProfile()}
          className="inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
        >
          <RefreshCw size={16} />
          Retry
        </button>
      </div>
    );
  }

  const initial = profile.name?.trim().charAt(0).toUpperCase() || "U";
  const role = profile.role || "USER";
  const registeredAge = calculateAge(profile.date_of_birth);

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6">
      {/* Page heading */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <p className="text-sm font-medium tracking-wider text-cyan-300">
            ACCOUNT INFORMATION
          </p>

          <h1 className="mt-1 text-3xl font-bold text-white">
            My Profile
          </h1>

          <p className="mt-2 text-sm leading-6 text-slate-400">
            View your registered information and account details.
          </p>
        </div>

        <button
          type="button"
          onClick={() => void loadProfile()}
          disabled={loading}
          className="inline-flex shrink-0 items-center justify-center gap-2 self-start rounded-xl border border-slate-700 px-4 py-2.5 text-sm text-slate-200 transition hover:border-cyan-500/50 hover:bg-slate-800 disabled:opacity-50 sm:self-center"
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* Main profile card */}
      <section className="min-w-0 overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-xl shadow-black/10">
        {/* Decorative banner: contains no overlapping profile text */}
        <div className="relative h-28 overflow-hidden bg-gradient-to-r from-cyan-950 via-blue-900/70 to-slate-900 sm:h-32">
          <div className="absolute -right-8 -top-16 h-48 w-48 rounded-full border border-cyan-400/10" />
          <div className="absolute -right-1 -top-9 h-32 w-32 rounded-full border border-cyan-400/10" />

          <div className="absolute left-5 top-5 inline-flex items-center gap-2 rounded-full border border-cyan-300/10 bg-slate-950/20 px-3 py-2 text-xs font-semibold tracking-wider text-cyan-200 sm:left-6 sm:top-6">
            <ShieldCheck size={16} />
            IDPS SHIELD ACCOUNT
          </div>
        </div>

        <div className="px-4 pb-5 sm:px-6 sm:pb-6">
          {/* Profile identity: normal document flow prevents overlap */}
          <div className="flex min-w-0 flex-col gap-5 pt-6 sm:flex-row sm:items-center sm:gap-5 sm:pt-7">
            <div className="flex h-20 w-20 shrink-0 items-center justify-center rounded-2xl border border-cyan-300/20 bg-cyan-400 text-3xl font-bold text-slate-950 shadow-lg shadow-cyan-950/30">
              {initial}
            </div>

            <div className="min-w-0 flex-1">
              <h2 className="break-words text-2xl font-bold text-white">
                {profile.name || "User"}
              </h2>

              <p className="mt-1 break-all text-sm text-slate-400">
                {profile.email}
              </p>

              <div className="mt-3 flex flex-wrap gap-2">
                <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-950/60 px-3 py-1 text-xs font-medium text-slate-300">
                  <ShieldCheck size={14} className="text-cyan-300" />
                  {role}
                </span>

                <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-300">
                  <CheckCircle2 size={14} />
                  Authenticated
                </span>
              </div>
            </div>
          </div>

          {/* Account details grid */}
          <div className="mt-7 grid grid-cols-1 gap-4 md:grid-cols-2 lg:gap-5">
            <ProfileCard
              icon={<UserRound size={20} />}
              label="Full name"
              value={profile.name || "Not provided"}
            />

            <ProfileCard
              icon={<Mail size={20} />}
              label="Registered email"
              value={profile.email || "Not provided"}
            />

            <ProfileCard
              icon={<ShieldCheck size={20} />}
              label="Account role"
              value={role}
            />

            <ProfileCard
              icon={<CalendarDays size={20} />}
              label="Account created"
              value={formatDate(profile.created_at)}
            />

            <ProfileCard
              icon={<Cake size={20} />}
              label="Date of birth"
              value={formatDate(profile.date_of_birth)}
            />

            <ProfileCard
              icon={<Clock size={20} />}
              label="Registered age"
              value={
                registeredAge !== null
                  ? `${registeredAge} years old`
                  : "Date of birth not registered"
              }
              highlight
            />
          </div>
        </div>
      </section>

      {/* Age-based protection information */}
      <section className="flex min-w-0 items-start gap-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 sm:p-5">
        <Info
          size={20}
          className="mt-0.5 shrink-0 text-cyan-300"
        />

        <div className="min-w-0">
          <h3 className="font-semibold text-cyan-200">
            Age-based website protection
          </h3>

          <p className="mt-2 break-words text-sm leading-6 text-slate-300">
            IDPS Shield uses your registered date of birth to calculate
            your age for age-based website policy checks. Your age is
            calculated automatically and is not selected manually on
            the website checking page.
          </p>

          {!profile.date_of_birth && (
            <p className="mt-2 break-words text-sm leading-6 text-amber-300">
              Your date of birth has not been returned by the backend.
              Verify your registration details and database record before
              using age-based website checks.
            </p>
          )}
        </div>
      </section>

      {/* Privacy information */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 sm:p-5">
        <div className="flex items-center gap-2 text-slate-300">
          <ShieldCheck size={18} className="shrink-0 text-cyan-300" />
          <h3 className="text-sm font-semibold">Account privacy</h3>
        </div>

        <p className="mt-2 text-sm leading-6 text-slate-400">
          This page displays account information returned by your
          authenticated backend. Editing account details and changing
          your password are not currently available here.
        </p>
      </section>
    </div>
  );
}

function ProfileCard({
  icon,
  label,
  value,
  highlight = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  highlight?: boolean;
}) {
  return (
    <div
      className={`min-w-0 rounded-xl border p-4 transition sm:p-5 ${
        highlight
          ? "border-cyan-500/25 bg-cyan-500/5"
          : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
      }`}
    >
      <div className="flex min-w-0 items-center gap-2">
        <span className="shrink-0 text-cyan-300">{icon}</span>

        <span className="min-w-0 break-words text-xs font-medium uppercase tracking-wider text-slate-400">
          {label}
        </span>
      </div>

      <p className="mt-3 break-words text-base font-semibold leading-6 text-white">
        {value}
      </p>
    </div>
  );
}
