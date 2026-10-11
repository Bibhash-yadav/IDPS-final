
import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ShieldCheck,
  Eye,
  EyeOff,
  User,
  Mail,
  LockKeyhole,
  CalendarDays,
  CheckCircle2,
  LoaderCircle,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";

function getTodayDate(): string {
  const today = new Date();

  const year = today.getFullYear();
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const day = String(today.getDate()).padStart(2, "0");

  return `${year}-${month}-${day}`;
}

/**
 * Calculate age from YYYY-MM-DD without timezone conversion.
 */
function calculateAge(dateOfBirth: string): number | null {
  if (!dateOfBirth) return null;

  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateOfBirth);

  if (!match) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);

  const dob = new Date(year, month - 1, day);

  // Reject invalid dates such as 2000-02-31.
  if (
    dob.getFullYear() !== year ||
    dob.getMonth() !== month - 1 ||
    dob.getDate() !== day
  ) {
    return null;
  }

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  if (dob > today || year < 1900) {
    return null;
  }

  let age = today.getFullYear() - year;

  const birthdayNotReached =
    today.getMonth() < month - 1 ||
    (today.getMonth() === month - 1 && today.getDate() < day);

  if (birthdayNotReached) {
    age--;
  }

  return age >= 0 && age <= 120 ? age : null;
}

type RegistrationApiError = {
  response?: {
    status?: number;
    data?: {
      detail?: string | { msg?: string; message?: string }[];
      message?: string;
    };
  };
  message?: string;
};

function getRegistrationError(error: unknown): string {
  const apiError = error as RegistrationApiError;
  const detail = apiError.response?.data?.detail;

  if (typeof detail === "string" && detail.trim()) {
    return detail;
  }

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => item.msg || item.message || "")
      .filter(Boolean);

    if (messages.length) {
      return messages.join(" ");
    }
  }

  if (apiError.response?.data?.message) {
    return apiError.response.data.message;
  }

  if (apiError.response?.status === 409) {
    return "An account with this email already exists. Please sign in.";
  }

  if (apiError.response?.status === 422) {
    return "Some registration details are invalid. Please check your entries.";
  }

  if (!apiError.response) {
    return (
      "Cannot connect to the backend. Check that your FastAPI server " +
      "is running and your API URL is configured correctly."
    );
  }

  return apiError.message || "Registration failed. Please try again.";
}

export default function Register() {
  const { register, user, loading } = useAuth();
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [dateOfBirth, setDateOfBirth] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const calculatedAge = calculateAge(dateOfBirth);

  useEffect(() => {
    if (!loading && user) {
      navigate("/dashboard", { replace: true });
    }
  }, [loading, user, navigate]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (busy) return;

    setError("");

    const normalizedName = name.trim();
    const normalizedEmail = email.trim().toLowerCase();

    if (
      !normalizedName ||
      !normalizedEmail ||
      !dateOfBirth ||
      !password ||
      !confirmPassword
    ) {
      setError("Please complete all fields.");
      return;
    }

    if (normalizedName.length < 2) {
      setError("Name must contain at least 2 characters.");
      return;
    }

    if (normalizedName.length > 100) {
      setError("Name cannot exceed 100 characters.");
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      setError("Please enter a valid email address.");
      return;
    }

    if (calculatedAge === null) {
      setError("Please enter a valid date of birth.");
      return;
    }

    if (password.length < 8) {
      setError("Password must contain at least 8 characters.");
      return;
    }

    if (!/[A-Z]/.test(password)) {
      setError("Password must contain at least one uppercase letter.");
      return;
    }

    if (!/[a-z]/.test(password)) {
      setError("Password must contain at least one lowercase letter.");
      return;
    }

    if (!/[0-9]/.test(password)) {
      setError("Password must contain at least one number.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setBusy(true);

    try {
      // The DOB is sent as YYYY-MM-DD and must be persisted by the backend.
      await register({
        name: normalizedName,
        email: normalizedEmail,
        password,
        date_of_birth: dateOfBirth,
      });

      navigate("/dashboard", { replace: true });
    } catch (registrationError: unknown) {
      setError(getRegistrationError(registrationError));
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#080d18] text-cyan-400">
        <LoaderCircle size={22} className="mr-3 animate-spin" />
        Checking your session...
      </main>
    );
  }

  if (user) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#080d18] text-cyan-400">
        Opening dashboard...
      </main>
    );
  }

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#080d18] px-4 py-10">
      <div className="pointer-events-none absolute -left-32 -top-32 h-80 w-80 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-32 -right-32 h-80 w-80 rounded-full bg-blue-500/10 blur-3xl" />

      <section className="relative w-full max-w-md rounded-2xl border border-slate-800 bg-[#101827]/95 p-7 shadow-2xl sm:p-8">
        <div className="mb-7 flex items-center gap-3">
          <div className="rounded-xl bg-cyan-400/10 p-3 text-cyan-400">
            <ShieldCheck size={30} />
          </div>

          <div>
            <h1 className="text-xl font-bold text-white">IDPS Shield</h1>
            <p className="text-sm text-slate-400">
              Intelligent Cyber Defense Platform
            </p>
          </div>
        </div>

        <h2 className="text-2xl font-bold text-white">
          Create your account
        </h2>

        <p className="mt-2 text-sm leading-6 text-slate-400">
          Register to monitor URLs and manage your security dashboard.
        </p>

        <form onSubmit={handleSubmit} className="mt-7 space-y-5">
          <div>
            <label
              htmlFor="register-name"
              className="mb-2 block text-sm font-medium text-slate-300"
            >
              Full name
            </label>

            <div className="flex items-center rounded-lg border border-slate-700 bg-[#080d18] focus-within:border-cyan-400">
              <User size={18} className="ml-3 shrink-0 text-slate-500" />

              <input
                id="register-name"
                type="text"
                autoComplete="name"
                required
                minLength={2}
                maxLength={100}
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Enter your full name"
                disabled={busy}
                className="min-w-0 flex-1 bg-transparent px-3 py-3 text-white outline-none placeholder:text-slate-600 disabled:opacity-60"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="register-email"
              className="mb-2 block text-sm font-medium text-slate-300"
            >
              Email address
            </label>

            <div className="flex items-center rounded-lg border border-slate-700 bg-[#080d18] focus-within:border-cyan-400">
              <Mail size={18} className="ml-3 shrink-0 text-slate-500" />

              <input
                id="register-email"
                type="email"
                autoComplete="email"
                required
                maxLength={254}
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                disabled={busy}
                className="min-w-0 flex-1 bg-transparent px-3 py-3 text-white outline-none placeholder:text-slate-600 disabled:opacity-60"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="register-dob"
              className="mb-2 block text-sm font-medium text-slate-300"
            >
              Date of birth
            </label>

            <div className="flex items-center rounded-lg border border-slate-700 bg-[#080d18] focus-within:border-cyan-400">
              <CalendarDays
                size={18}
                className="ml-3 shrink-0 text-slate-500"
              />

              <input
                id="register-dob"
                type="date"
                autoComplete="bday"
                required
                min="1900-01-01"
                max={getTodayDate()}
                value={dateOfBirth}
                onChange={(event) => setDateOfBirth(event.target.value)}
                disabled={busy}
                className="min-w-0 flex-1 bg-transparent px-3 py-3 text-white outline-none [color-scheme:dark] disabled:opacity-60"
              />
            </div>

            {dateOfBirth && calculatedAge !== null && (
              <div className="mt-3 rounded-lg border border-cyan-400/20 bg-cyan-400/5 p-3">
                <p className="text-sm text-slate-300">
                  Calculated age:{" "}
                  <span className="font-semibold text-cyan-400">
                    {calculatedAge} years
                  </span>
                </p>

                <p className="mt-1 text-xs text-slate-400">
                  {calculatedAge < 18
                    ? "Under-18 protection policies can be applied to this account."
                    : "Age-based protection policies will use this registered date of birth."}
                </p>
              </div>
            )}
          </div>

          <div>
            <label
              htmlFor="register-password"
              className="mb-2 block text-sm font-medium text-slate-300"
            >
              Password
            </label>

            <div className="flex items-center rounded-lg border border-slate-700 bg-[#080d18] focus-within:border-cyan-400">
              <LockKeyhole
                size={18}
                className="ml-3 shrink-0 text-slate-500"
              />

              <input
                id="register-password"
                type={showPassword ? "text" : "password"}
                autoComplete="new-password"
                required
                minLength={8}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Create a strong password"
                disabled={busy}
                className="min-w-0 flex-1 bg-transparent px-3 py-3 text-white outline-none placeholder:text-slate-600 disabled:opacity-60"
              />

              <button
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                aria-label={showPassword ? "Hide password" : "Show password"}
                className="px-3 text-slate-400 hover:text-cyan-400"
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>

            <p className="mt-2 text-xs leading-5 text-slate-500">
              Use at least 8 characters, including uppercase, lowercase, and a
              number.
            </p>
          </div>

          <div>
            <label
              htmlFor="confirm-password"
              className="mb-2 block text-sm font-medium text-slate-300"
            >
              Confirm password
            </label>

            <div className="flex items-center rounded-lg border border-slate-700 bg-[#080d18] focus-within:border-cyan-400">
              <LockKeyhole
                size={18}
                className="ml-3 shrink-0 text-slate-500"
              />

              <input
                id="confirm-password"
                type={showConfirmPassword ? "text" : "password"}
                autoComplete="new-password"
                required
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                placeholder="Re-enter your password"
                disabled={busy}
                className="min-w-0 flex-1 bg-transparent px-3 py-3 text-white outline-none placeholder:text-slate-600 disabled:opacity-60"
              />

              <button
                type="button"
                onClick={() =>
                  setShowConfirmPassword((value) => !value)
                }
                aria-label={
                  showConfirmPassword
                    ? "Hide confirmation password"
                    : "Show confirmation password"
                }
                className="px-3 text-slate-400 hover:text-cyan-400"
              >
                {showConfirmPassword ? (
                  <EyeOff size={18} />
                ) : (
                  <Eye size={18} />
                )}
              </button>
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm leading-5 text-red-400"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-500 px-4 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? (
              <>
                <LoaderCircle size={18} className="animate-spin" />
                Creating account...
              </>
            ) : (
              <>
                <CheckCircle2 size={18} />
                Create Account
              </>
            )}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-slate-400">
          Already have an account?{" "}
          <Link
            to="/login"
            className="font-medium text-cyan-400 hover:underline"
          >
            Sign in
          </Link>
        </p>

        <p className="mt-6 text-center text-xs leading-5 text-slate-600">
          Your date of birth is used to calculate your age and apply
          age-appropriate protection policies.
        </p>
      </section>
    </main>
  );
}
