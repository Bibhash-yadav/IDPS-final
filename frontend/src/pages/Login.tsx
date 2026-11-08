
import { useState, useEffect, type FormEvent } from "react";

import {
  Navigate,
  useLocation,
  useNavigate,
} from "react-router-dom";

import {
  ShieldCheck,
  Eye,
  EyeOff,
  LockKeyhole,
  Mail,
  Shield,
  ArrowLeft,
  Smartphone,
  RefreshCw,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";

import type {
  TwoFactorChallengeResponse,
} from "../types/auth";


// =====================================================
// THEME DETECTION
// =====================================================

function useThemeMode() {
  const [isDark, setIsDark] = useState(
    () => document.documentElement.dataset.theme !== "light"
  );

  useEffect(() => {
    const updateTheme = () => {
      setIsDark(
        document.documentElement.dataset.theme !== "light"
      );
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


// =====================================================
// ERROR HELPER
// =====================================================

function getErrorMessage(err: unknown): string {
  let message = "Something went wrong. Please try again.";

  if (
    typeof err === "object" &&
    err !== null &&
    "response" in err
  ) {
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

  return message;
}


// =====================================================
// LOGIN COMPONENT
// =====================================================

export default function Login() {
  const {
    login,
    verifyTwoFactor,
    resendEmailOtp,
    user,
    loading,
  } = useAuth();

  const navigate = useNavigate();
  const location = useLocation();

  const isDark = useThemeMode();


  // ===================================================
  // LOGIN STATE
  // ===================================================

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);


  // ===================================================
  // TWO-FACTOR STATE
  // ===================================================

  const [challenge, setChallenge] =
    useState<TwoFactorChallengeResponse | null>(null);

  const [verificationCode, setVerificationCode] =
    useState("");

  const [resending, setResending] = useState(false);


  // ===================================================
  // REDIRECT
  // ===================================================

  const from = location.state?.from;

  const destination =
    typeof from === "string"
      ? from
      : from?.pathname || "/dashboard";


  // ===================================================
  // LOADING SCREEN
  // ===================================================

  if (loading) {
    return (
      <main
        className={`flex h-dvh items-center justify-center overflow-hidden ${
          isDark
            ? "bg-[#080d18] text-cyan-400"
            : "bg-slate-50 text-cyan-600"
        }`}
      >
        <div className="flex items-center gap-3 text-sm font-medium">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-current border-t-transparent" />
          Checking your session...
        </div>
      </main>
    );
  }


  // ===================================================
  // ALREADY AUTHENTICATED
  // ===================================================

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }


  // ===================================================
  // THEME CLASSES
  // ===================================================

  const panelClass = isDark
    ? "border border-white/10 bg-white/[0.055] shadow-[0_20px_70px_rgba(0,0,0,0.4)]"
    : "border border-white/80 bg-white/80 shadow-[0_20px_70px_rgba(31,41,55,0.10)]";

  const headingClass = isDark
    ? "text-white"
    : "text-slate-900";

  const mutedClass = isDark
    ? "text-slate-400"
    : "text-slate-500";

  const inputClass = isDark
    ? "border-white/10 bg-slate-950/50 text-white placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10"
    : "border-slate-200 bg-white/80 text-slate-900 placeholder:text-slate-400 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/10";


  // ===================================================
  // NAVIGATION
  // ===================================================

  function openRegister() {
    setError("");
    navigate("/register");
  }


  function backToLogin() {
    setChallenge(null);
    setVerificationCode("");
    setError("");
    setNotice("");
  }


  // ===================================================
  // NORMAL LOGIN
  // ===================================================

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();

    setError("");
    setNotice("");

    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedEmail || !password) {
      setError(
        "Please enter your email address and password."
      );

      return;
    }

    setBusy(true);

    try {
      const result = await login({
        email: normalizedEmail,
        password,
      });

      if ("requires_two_factor" in result) {
        setChallenge(result);

        setVerificationCode("");

        if (
          result.available_methods.includes("email")
        ) {
          setNotice(
            "A verification code has been sent to your registered email."
          );
        } else {
          setNotice(
            "Open your authenticator app and enter the current six-digit code."
          );
        }

        return;
      }

      // Normal login without 2FA.
      navigate(destination, {
        replace: true,
      });

    } catch (err: unknown) {
      setError(getErrorMessage(err));

    } finally {
      setBusy(false);
    }
  }


  // ===================================================
  // VERIFY 2FA
  // ===================================================

  async function handleVerify(
    event: FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();

    setError("");
    setNotice("");

    if (!challenge) {
      setError("Your verification session has expired.");
      return;
    }

    if (!/^\d{6}$/.test(verificationCode)) {
      setError("Enter a valid six-digit verification code.");
      return;
    }

    setBusy(true);

    try {
      await verifyTwoFactor(
        challenge.challenge_token,
        verificationCode
      );

      // AuthContext now contains the final access token.
      navigate(destination, {
        replace: true,
      });

    } catch (err: unknown) {
      setError(getErrorMessage(err));
      setVerificationCode("");

    } finally {
      setBusy(false);
    }
  }


  // ===================================================
  // RESEND EMAIL OTP
  // ===================================================

  async function handleResendOtp() {
    if (!challenge) return;

    setError("");
    setNotice("");

    setResending(true);

    try {
      const result = await resendEmailOtp(
        challenge.challenge_token
      );

      setNotice(result.message);

      setVerificationCode("");

    } catch (err: unknown) {
      setError(getErrorMessage(err));

    } finally {
      setResending(false);
    }
  }


  // ===================================================
  // 2FA METHOD
  // ===================================================

  const isEmailMethod =
    challenge?.available_methods.includes("email") ?? false;

  const isTotpMethod =
    challenge?.available_methods.includes("totp") ?? false;


  // ===================================================
  // RENDER
  // ===================================================

  return (
    <main
      className={`relative flex min-h-dvh w-full items-center justify-center overflow-x-hidden px-4 py-6 transition-colors duration-300 ${
        isDark ? "bg-[#080d18]" : "bg-[#f3f7fc]"
      }`}
    >

      {/* BACKGROUND DECORATION */}

      <div className="pointer-events-none absolute inset-0 overflow-hidden">

        <div
          className={`absolute -left-32 -top-32 h-72 w-72 rounded-full blur-[100px] ${
            isDark
              ? "bg-cyan-500/10"
              : "bg-cyan-400/20"
          }`}
        />

        <div
          className={`absolute -bottom-32 -right-32 h-72 w-72 rounded-full blur-[100px] ${
            isDark
              ? "bg-blue-600/10"
              : "bg-blue-400/20"
          }`}
        />

        <div
          className={`absolute left-1/2 top-1/2 h-80 w-80 -translate-x-1/2 -translate-y-1/2 rounded-full blur-[120px] ${
            isDark
              ? "bg-indigo-500/[0.06]"
              : "bg-indigo-400/[0.10]"
          }`}
        />

      </div>


      {/* AUTHENTICATION CARD */}

      <section
        className={`relative z-10 my-auto w-full max-w-[420px] rounded-[26px] px-6 py-6 backdrop-blur-3xl sm:px-8 sm:py-7 ${panelClass}`}
      >

        {/* BRAND */}

        <div className="mb-6 flex items-center gap-3">

          <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-2.5 text-cyan-500 shadow-lg shadow-cyan-500/10">
            <ShieldCheck size={25} />
          </div>

          <div>
            <h1
              className={`text-lg font-bold tracking-tight ${headingClass}`}
            >
              IDPS Shield
            </h1>

            <p className={`text-xs ${mutedClass}`}>
              Intelligent Cyber Defense System
            </p>
          </div>

        </div>


        {/* =========================================
            NORMAL LOGIN SCREEN
        ========================================= */}

        {!challenge && (
          <>

            <div className="mb-5">

              <div
                className={`mb-2 inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[10px] font-semibold ${
                  isDark
                    ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
                    : "border-emerald-200 bg-emerald-50 text-emerald-700"
                }`}
              >
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                SECURE AUTHENTICATION
              </div>

              <h2
                className={`text-2xl font-bold tracking-tight ${headingClass}`}
              >
                Welcome back
              </h2>

              <p className={`mt-1 text-xs ${mutedClass}`}>
                Sign in to access your security dashboard.
              </p>

            </div>


            {/* LOGIN FORM */}

            <form
              onSubmit={handleSubmit}
              className="space-y-4"
            >

              {/* EMAIL */}

              <div>

                <label
                  htmlFor="login-email"
                  className={`mb-1.5 block text-xs font-semibold ${headingClass}`}
                >
                  Email address
                </label>

                <div className="relative">

                  <Mail
                    size={17}
                    className={`absolute left-3.5 top-1/2 -translate-y-1/2 ${mutedClass}`}
                  />

                  <input
                    id="login-email"
                    type="email"
                    required
                    autoComplete="email"
                    value={email}
                    onChange={(event) =>
                      setEmail(event.target.value)
                    }
                    placeholder="you@example.com"
                    className={`w-full rounded-xl border py-3 pl-10 pr-3 text-sm outline-none transition-all ${inputClass}`}
                  />

                </div>

              </div>


              {/* PASSWORD */}

              <div>

                <label
                  htmlFor="login-password"
                  className={`mb-1.5 block text-xs font-semibold ${headingClass}`}
                >
                  Password
                </label>

                <div
                  className={`flex rounded-xl border transition-all focus-within:border-cyan-400/60 focus-within:ring-2 focus-within:ring-cyan-400/10 ${
                    isDark
                      ? "border-white/10 bg-slate-950/50"
                      : "border-slate-200 bg-white/80"
                  }`}
                >

                  <LockKeyhole
                    size={17}
                    className={`ml-3.5 shrink-0 self-center ${mutedClass}`}
                  />

                  <input
                    id="login-password"
                    type={showPassword ? "text" : "password"}
                    required
                    autoComplete="current-password"
                    value={password}
                    onChange={(event) =>
                      setPassword(event.target.value)
                    }
                    placeholder="Enter your password"
                    className={`min-w-0 flex-1 bg-transparent px-3 py-3 text-sm outline-none ${
                      isDark
                        ? "text-white placeholder:text-slate-500"
                        : "text-slate-900 placeholder:text-slate-400"
                    }`}
                  />

                  <button
                    type="button"
                    onClick={() =>
                      setShowPassword((value) => !value)
                    }
                    aria-label={
                      showPassword
                        ? "Hide password"
                        : "Show password"
                    }
                    className={`mr-2 rounded-lg p-2 transition ${
                      isDark
                        ? "text-slate-400 hover:bg-white/10 hover:text-cyan-300"
                        : "text-slate-500 hover:bg-slate-100 hover:text-cyan-600"
                    }`}
                  >
                    {showPassword ? (
                      <EyeOff size={17} />
                    ) : (
                      <Eye size={17} />
                    )}
                  </button>

                </div>

              </div>


              {/* ERROR */}

              {error && (
                <div
                  role="alert"
                  className="rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-500"
                >
                  {error}
                </div>
              )}


              {/* SUBMIT */}

              <button
                type="submit"
                disabled={busy}
                className="group flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xl hover:shadow-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:translate-y-0"
              >

                {busy ? (
                  <>
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                    Signing in...
                  </>
                ) : (
                  <>
                    Sign in

                    <ShieldCheck
                      size={17}
                      className="transition-transform group-hover:scale-110"
                    />
                  </>
                )}

              </button>

            </form>


            {/* REGISTER */}

            <div className={`mt-5 text-center text-xs ${mutedClass}`}>
              New to IDPS Shield?{" "}

              <button
                type="button"
                onClick={openRegister}
                className="font-semibold text-cyan-500 transition hover:text-blue-500 hover:underline"
              >
                Create Account
              </button>
            </div>

          </>
        )}


        {/* =========================================
            TWO-FACTOR VERIFICATION SCREEN
        ========================================= */}

        {challenge && (
          <>

            <button
              type="button"
              onClick={backToLogin}
              className={`mb-5 flex items-center gap-2 text-xs font-medium transition hover:text-cyan-500 ${mutedClass}`}
            >
              <ArrowLeft size={15} />
              Back to login
            </button>


            <div className="mb-5">

              <div className="mb-3 inline-flex rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-3 text-cyan-500">
                {isTotpMethod ? (
                  <Smartphone size={25} />
                ) : (
                  <Mail size={25} />
                )}
              </div>

              <h2
                className={`text-2xl font-bold tracking-tight ${headingClass}`}
              >
                Two-factor verification
              </h2>

              <p className={`mt-2 text-xs leading-5 ${mutedClass}`}>
                {isTotpMethod
                  ? "Open Google Authenticator or another compatible authenticator app and enter the current six-digit code."
                  : "Enter the six-digit verification code sent to your registered email address."}
              </p>

            </div>


            {/* METHOD INDICATOR */}

            <div
              className={`mb-4 flex items-center gap-3 rounded-xl border p-3 ${
                isDark
                  ? "border-white/10 bg-white/[0.035]"
                  : "border-slate-200 bg-slate-50"
              }`}
            >

              <ShieldCheck
                size={19}
                className="text-cyan-500"
              />

              <div>
                <p
                  className={`text-xs font-semibold ${headingClass}`}
                >
                  {isTotpMethod
                    ? "Google Authenticator"
                    : "Email OTP"}
                </p>

                <p className={`text-[10px] ${mutedClass}`}>
                  {isTotpMethod
                    ? "Authenticator verification"
                    : "Email verification"}
                </p>
              </div>

            </div>


            {/* VERIFICATION FORM */}

            <form
              onSubmit={handleVerify}
              className="space-y-4"
            >

              <div>

                <label
                  htmlFor="verification-code"
                  className={`mb-1.5 block text-xs font-semibold ${headingClass}`}
                >
                  Six-digit verification code
                </label>

                <input
                  id="verification-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  required
                  value={verificationCode}
                  onChange={(event) => {
                    const value = event.target.value
                      .replace(/\D/g, "")
                      .slice(0, 6);

                    setVerificationCode(value);
                  }}
                  placeholder="000000"
                  className={`w-full rounded-xl border px-4 py-4 text-center text-2xl font-bold tracking-[0.5em] outline-none transition-all ${inputClass}`}
                />

                <p className={`mt-2 text-[10px] ${mutedClass}`}>
                  Enter all six digits to continue.
                </p>

              </div>


              {/* NOTICE */}

              {notice && (
                <div
                  role="status"
                  className={`rounded-xl border p-3 text-xs ${
                    isDark
                      ? "border-cyan-400/20 bg-cyan-400/10 text-cyan-300"
                      : "border-cyan-200 bg-cyan-50 text-cyan-700"
                  }`}
                >
                  {notice}
                </div>
              )}


              {/* ERROR */}

              {error && (
                <div
                  role="alert"
                  className="rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-500"
                >
                  {error}
                </div>
              )}


              {/* VERIFY BUTTON */}

              <button
                type="submit"
                disabled={busy || verificationCode.length !== 6}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition-all hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:translate-y-0"
              >

                {busy ? (
                  <>
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                    Verifying...
                  </>
                ) : (
                  <>
                    Verify and continue
                    <ShieldCheck size={17} />
                  </>
                )}

              </button>

            </form>


            {/* RESEND EMAIL OTP */}

            {isEmailMethod && (
              <button
                type="button"
                onClick={handleResendOtp}
                disabled={resending || busy}
                className="mt-4 flex w-full items-center justify-center gap-2 rounded-xl border border-cyan-500/20 px-4 py-3 text-xs font-semibold text-cyan-500 transition hover:bg-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50"
              >

                {resending ? (
                  <>
                    <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
                    Sending code...
                  </>
                ) : (
                  <>
                    <RefreshCw size={14} />
                    Resend verification code
                  </>
                )}

              </button>
            )}

          </>
        )}


        {/* FOOTER */}

        <div
          className={`mt-6 flex items-center justify-center gap-2 border-t pt-4 text-[10px] ${
            isDark
              ? "border-white/10 text-slate-500"
              : "border-slate-200 text-slate-400"
          }`}
        >
          <Shield size={12} />
          Protected by IDPS Security
        </div>

      </section>

    </main>
  );
}
