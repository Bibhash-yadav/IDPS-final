
import { useCallback, useEffect, useState, type ReactNode } from "react";
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
  Shield,
  User,
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

  const dateOnly = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);

  const date = dateOnly
    ? new Date(
        Number(dateOnly[1]),
        Number(dateOnly[2]) - 1,
        Number(dateOnly[3])
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
  const isDark = useThemeMode();

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
        "Unable to load your profile. Please check your login session and backend connection."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadProfile();
  }, [loadProfile]);

  const headingClass = isDark ? "text-white" : "text-slate-900";
  const secondaryClass = isDark ? "text-slate-400" : "text-slate-500";
  const mutedClass = isDark ? "text-slate-500" : "text-slate-400";

  const glassClass = isDark
    ? "border border-white/10 bg-white/[0.055] shadow-[0_12px_40px_rgba(0,0,0,0.18)]"
    : "border border-white/80 bg-white/75 shadow-[0_12px_40px_rgba(31,41,55,0.07)]";

  const buttonClass = isDark
    ? "border-white/10 bg-white/[0.06] text-slate-200 hover:bg-white/10"
    : "border-slate-200 bg-white/80 text-slate-700 hover:bg-slate-100";

  const initial =
    profile?.name?.trim().charAt(0).toUpperCase() || "U";

  const role = profile?.role || "USER";
  const registeredAge = calculateAge(profile?.date_of_birth);

  // Loading state
  if (loading) {
    return (
      <div className="flex min-h-64 items-center justify-center gap-3">
        <RefreshCw size={20} className="animate-spin text-cyan-500" />
        <span className={`text-sm font-medium ${secondaryClass}`}>
          Loading your profile...
        </span>
      </div>
    );
  }

  // Error state
  if (error || !profile) {
    return (
      <div className="mx-auto w-full max-w-5xl space-y-6">
        <div>
          <p className="text-xs font-bold tracking-[0.2em] text-cyan-500">
            ACCOUNT INFORMATION
          </p>
          <h1 className={`mt-2 text-3xl font-bold ${headingClass}`}>
            My Profile
          </h1>
        </div>

        <div className={`rounded-2xl p-5 ${glassClass}`}>
          <div className="flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm leading-6 text-red-500">
            <AlertCircle size={20} className="mt-0.5 shrink-0" />
            <p>{error || "Profile information is unavailable."}</p>
          </div>

          <button
            type="button"
            onClick={() => void loadProfile()}
            className="mt-5 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition hover:-translate-y-0.5"
          >
            <RefreshCw size={16} />
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 pb-8">
      {/* Page heading */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs font-bold tracking-[0.2em] text-cyan-500">
            ACCOUNT INFORMATION
          </p>

          <h1 className={`mt-2 text-3xl font-bold tracking-tight ${headingClass}`}>
            My Profile
          </h1>

          <p className={`mt-2 text-sm ${secondaryClass}`}>
            View your registered information and account details.
          </p>
        </div>

        <button
          type="button"
          onClick={() => void loadProfile()}
          disabled={loading}
          className={`inline-flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-semibold transition hover:-translate-y-0.5 disabled:opacity-50 ${buttonClass}`}
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* Main profile card */}
      <section className={`overflow-hidden rounded-[26px] backdrop-blur-2xl ${glassClass}`}>
        {/* Banner */}
        <div className="relative h-32 overflow-hidden bg-gradient-to-r from-cyan-600 via-blue-700 to-indigo-800 sm:h-36">
          <div className="absolute -right-12 -top-20 h-64 w-64 rounded-full border border-white/10" />
          <div className="absolute -right-3 -top-12 h-48 w-48 rounded-full border border-white/10" />
          <div className="absolute right-24 top-10 h-24 w-24 rounded-full border border-white/10" />

          <div className="absolute left-5 top-5 inline-flex items-center gap-2 rounded-full border border-white/20 bg-black/10 px-3 py-2 text-[10px] font-bold tracking-[0.15em] text-white backdrop-blur-xl sm:left-7">
            <ShieldCheck size={15} />
            IDPS SHIELD ACCOUNT
          </div>

          <div className="absolute bottom-5 right-6 hidden items-center gap-2 text-xs font-medium text-white/70 sm:flex">
            <Shield size={15} />
            Secure Account
          </div>
        </div>

        {/* Identity */}
        <div className="px-5 pb-6 sm:px-7">
          <div className="flex min-w-0 flex-col gap-4 pt-6 sm:flex-row sm:items-center sm:gap-5">
            <div className="flex h-20 w-20 shrink-0 items-center justify-center rounded-[22px] border-4 border-white/20 bg-gradient-to-br from-cyan-400 to-blue-500 text-3xl font-bold text-white shadow-xl shadow-cyan-500/20">
              {initial}
            </div>

            <div className="min-w-0 flex-1">
              <h2 className={`break-words text-2xl font-bold ${headingClass}`}>
                {profile.name || "User"}
              </h2>

              <p className={`mt-1 break-all text-sm ${secondaryClass}`}>
                {profile.email}
              </p>

              <div className="mt-3 flex flex-wrap gap-2">
                <span
                  className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-semibold ${
                    isDark
                      ? "border-cyan-400/20 bg-cyan-400/10 text-cyan-300"
                      : "border-cyan-200 bg-cyan-50 text-cyan-700"
                  }`}
                >
                  <ShieldCheck size={14} />
                  {role}
                </span>

                <span
                  className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-semibold ${
                    isDark
                      ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
                      : "border-emerald-200 bg-emerald-50 text-emerald-700"
                  }`}
                >
                  <CheckCircle2 size={14} />
                  Authenticated
                </span>
              </div>
            </div>
          </div>

          {/* Account details */}
          <div className="mt-7">
            <div className="mb-4 flex items-center gap-2">
              <User size={17} className="text-cyan-500" />
              <h3 className={`text-sm font-bold ${headingClass}`}>
                Personal Information
              </h3>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <ProfileCard
                isDark={isDark}
                icon={<UserRound size={19} />}
                label="Full name"
                value={profile.name || "Not provided"}
              />

              <ProfileCard
                isDark={isDark}
                icon={<Mail size={19} />}
                label="Registered email"
                value={profile.email || "Not provided"}
              />

              <ProfileCard
                isDark={isDark}
                icon={<ShieldCheck size={19} />}
                label="Account role"
                value={role}
              />

              <ProfileCard
                isDark={isDark}
                icon={<CalendarDays size={19} />}
                label="Account created"
                value={formatDate(profile.created_at)}
              />

              <ProfileCard
                isDark={isDark}
                icon={<Cake size={19} />}
                label="Date of birth"
                value={formatDate(profile.date_of_birth)}
              />

              <ProfileCard
                isDark={isDark}
                icon={<Clock size={19} />}
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
        </div>
      </section>

      {/* Age-based protection */}
      <section
        className={`flex items-start gap-4 rounded-[22px] p-5 backdrop-blur-2xl ${glassClass}`}
      >
        <div className="shrink-0 rounded-xl bg-cyan-500/10 p-2.5 text-cyan-500">
          <Info size={21} />
        </div>

        <div className="min-w-0">
          <h3 className={`font-semibold ${headingClass}`}>
            Age-based website protection
          </h3>

          <p className={`mt-2 text-sm leading-6 ${secondaryClass}`}>
            IDPS Shield uses your registered date of birth to calculate
            your age for age-based website policy checks. Your age is
            calculated automatically and is not selected manually on
            the website checking page.
          </p>

          {!profile.date_of_birth && (
            <p className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/10 p-3 text-sm leading-6 text-amber-600">
              Your date of birth has not been returned by the backend.
              Verify your registration details and database record before
              using age-based website checks.
            </p>
          )}
        </div>
      </section>

      {/* Privacy information */}
      <section className={`rounded-[22px] p-5 backdrop-blur-2xl ${glassClass}`}>
        <div className="flex items-center gap-2">
          <ShieldCheck size={19} className="text-cyan-500" />
          <h3 className={`text-sm font-semibold ${headingClass}`}>
            Account privacy
          </h3>
        </div>

        <p className={`mt-2 text-sm leading-6 ${secondaryClass}`}>
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
  isDark,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  highlight?: boolean;
  isDark: boolean;
}) {
  const cardClass = highlight
    ? isDark
      ? "border-cyan-400/20 bg-cyan-400/[0.07]"
      : "border-cyan-200 bg-cyan-50/70"
    : isDark
      ? "border-white/[0.08] bg-slate-950/30 hover:bg-white/[0.06]"
      : "border-slate-200/80 bg-white/60 hover:bg-white";

  return (
    <div
      className={`min-w-0 rounded-[20px] border p-4 transition-all duration-200 hover:-translate-y-0.5 ${cardClass}`}
    >
      <div className="flex min-w-0 items-center gap-2.5">
        <span className="shrink-0 text-cyan-500">{icon}</span>

        <span
          className={`min-w-0 break-words text-[10px] font-bold uppercase tracking-[0.12em] ${
            isDark ? "text-slate-400" : "text-slate-500"
          }`}
        >
          {label}
        </span>
      </div>

      <p
        className={`mt-3 break-words text-sm font-semibold leading-6 ${
          isDark ? "text-white" : "text-slate-800"
        }`}
      >
        {value}
      </p>
    </div>
  );
}
