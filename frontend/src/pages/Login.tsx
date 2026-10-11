
import { useState, type FormEvent } from "react";
import {
  Navigate,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { login, user, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const from = location.state?.from;
  const destination =
    typeof from === "string"
      ? from
      : from?.pathname || "/dashboard";

  if (loading) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#080d18] text-cyan-400">
        Checking your session...
      </main>
    );
  }

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  function openRegister() {
    setError("");
    navigate("/register");
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedEmail || !password) {
      setError("Please enter your email address and password.");
      return;
    }

    setBusy(true);

    try {
      await login({
        email: normalizedEmail,
        password,
      });

      navigate(destination, { replace: true });
    } catch (err: unknown) {
      let message = "Login failed. Check your credentials.";

      if (typeof err === "object" && err !== null && "response" in err) {
        const response = (
          err as {
            response?: {
              data?: {
                detail?: string;
                message?: string;
              };
            };
          }
        ).response;

        message =
          response?.data?.detail ||
          response?.data?.message ||
          message;
      }

      setError(message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#080d18] px-4 py-10">
      <section className="w-full max-w-md rounded-2xl border border-slate-800 bg-[#101827] p-8 shadow-2xl">
        <div className="mb-7 flex items-center gap-3">
          <div className="rounded-xl bg-cyan-400/10 p-3 text-cyan-400">
            <ShieldCheck size={28} />
          </div>

          <div>
            <h1 className="text-xl font-bold text-white">
              IDPS Shield
            </h1>
            <p className="text-sm text-slate-400">
              Cyber Defense Platform
            </p>
          </div>
        </div>

        <h2 className="text-2xl font-semibold text-white">
          Welcome back
        </h2>

        <p className="mt-2 text-sm text-slate-400">
          Sign in to access your security dashboard.
        </p>

        <form onSubmit={handleSubmit} className="mt-7 space-y-5">
          <div>
            <label
              htmlFor="login-email"
              className="mb-2 block text-sm text-slate-300"
            >
              Email address
            </label>

            <input
              id="login-email"
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-[#080d18] px-4 py-3 text-white outline-none focus:border-cyan-400"
              placeholder="you@example.com"
            />
          </div>

          <div>
            <label
              htmlFor="login-password"
              className="mb-2 block text-sm text-slate-300"
            >
              Password
            </label>

            <div className="flex rounded-lg border border-slate-700 bg-[#080d18] focus-within:border-cyan-400">
              <input
                id="login-password"
                type={showPassword ? "text" : "password"}
                required
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="min-w-0 flex-1 bg-transparent px-4 py-3 text-white outline-none"
                placeholder="Enter your password"
              />

              <button
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                aria-label={
                  showPassword ? "Hide password" : "Show password"
                }
                className="px-3 text-sm text-cyan-400"
              >
                {showPassword ? "Hide" : "Show"}
              </button>
            </div>
          </div>

          {error && (
            <p
              role="alert"
              className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-400"
            >
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-lg bg-cyan-500 px-4 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <div className="mt-6 text-center text-sm text-slate-400">
          New to IDPS Shield?{" "}
          <button
            type="button"
            onClick={openRegister}
            className="font-medium text-cyan-400 hover:underline"
          >
            Create Account
          </button>
        </div>
      </section>
    </main>
  );
}
