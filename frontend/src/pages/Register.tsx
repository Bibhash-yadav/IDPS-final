
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ShieldCheck,
  Eye,
  EyeOff,
  User,
  Mail,
  LockKeyhole,
  CheckCircle2,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function Register() {
  const { register, user, loading } = useAuth();
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Redirect already authenticated users.
  if (!loading && user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#080d18] text-cyan-400">
        <p>Account already signed in. Opening dashboard...</p>
        {navigate("/dashboard", { replace: true }) && null}
      </div>
    );
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    const normalizedName = name.trim();
    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedName || !normalizedEmail || !password || !confirmPassword) {
      setError("Please complete all fields.");
      return;
    }

    if (normalizedName.length < 2) {
      setError("Name must contain at least 2 characters.");
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
      await register({
        name: normalizedName,
        email: normalizedEmail,
        password,
      });

      // AuthContext.register saves the token and user.
      navigate("/dashboard", { replace: true });
    } catch (err: unknown) {
      let message = "Registration failed. Please try again.";

      if (typeof err === "object" && err !== null && "response" in err) {
        const response = (
          err as {
            response?: {
              data?: {
                detail?: string | { msg?: string }[];
                message?: string;
              };
            };
          }
        ).response;

        const detail = response?.data?.detail;

        if (typeof detail === "string") {
          message = detail;
        } else if (Array.isArray(detail)) {
          message = detail
            .map((item) => item.msg)
            .filter(Boolean)
            .join(" ");
        } else {
          message = response?.data?.message || message;
        }
      }

      setError(message);
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#080d18] text-cyan-400">
        Checking your session...
      </main>
    );
  }

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#080d18] px-4 py-10">
      {/* Background decoration */}
      <div className="pointer-events-none absolute -left-32 -top-32 h-80 w-80 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-32 -right-32 h-80 w-80 rounded-full bg-blue-500/10 blur-3xl" />

      <section className="relative w-full max-w-md rounded-2xl border border-slate-800 bg-[#101827]/95 p-7 shadow-2xl sm:p-8">
        {/* Brand */}
        <div className="mb-7 flex items-center gap-3">
          <div className="rounded-xl bg-cyan-400/10 p-3 text-cyan-400">
            <ShieldCheck size={30} />
          </div>

          <div>
            <h1 className="text-xl font-bold text-white">
              IDPS Shield
            </h1>
            <p className="text-sm text-slate-400">
              Intelligent Cyber Defense Platform
            </p>
          </div>
        </div>

        <h2 className="text-2xl font-bold text-white">
          Create your account
        </h2>

        <p className="mt-2 text-sm leading-6 text-slate-400">
          Join IDPS Shield to monitor URLs and manage your security dashboard.
        </p>

        <form onSubmit={handleSubmit} className="mt-7 space-y-5">
          {/* Full name */}
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
                className="min-w-0 flex-1 bg-transparent px-3 py-3 text-white outline-none placeholder:text-slate-600"
              />
            </div>
          </div>

          {/* Email */}
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
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                className="min-w-0 flex-1 bg-transparent px-3 py-3 text-white outline-none placeholder:text-slate-600"
              />
            </div>
          </div>

          {/* Password */}
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
                className="min-w-0 flex-1 bg-transparent px-3 py-3 text-white outline-none placeholder:text-slate-600"
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
              Use at least 8 characters, including uppercase, lowercase,
              and a number.
            </p>
          </div>

          {/* Confirm password */}
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
                className="min-w-0 flex-1 bg-transparent px-3 py-3 text-white outline-none placeholder:text-slate-600"
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

          {/* Error */}
          {error && (
            <div
              role="alert"
              className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm leading-5 text-red-400"
            >
              {error}
            </div>
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={busy}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-500 px-4 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950/30 border-t-slate-950" />
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

        {/* Login link */}
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
          IDPS Shield helps you assess potential online threats. No security
          system can guarantee that every website is safe.
        </p>
      </section>
    </main>
  );
}
