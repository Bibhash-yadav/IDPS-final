
import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { QRCodeSVG } from "qrcode.react";
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
  Shield,
  AlertCircle,
  Smartphone,
  ArrowLeft,
  ArrowRight,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";

/* ================= THEME ================= */

function useThemeMode() {
  const [isDark, setIsDark] = useState(
    () => document.documentElement.dataset.theme !== "light"
  );

  useEffect(() => {
    const updateTheme = () => {
      setIsDark(document.documentElement.dataset.theme !== "light");
    };

    const observer = new MutationObserver(updateTheme);

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });

    updateTheme();

    return () => observer.disconnect();
  }, []);

  return isDark;
}

/* ================= DATE HELPERS ================= */

function getTodayDate() {
  const today = new Date();

  return [
    today.getFullYear(),
    String(today.getMonth() + 1).padStart(2, "0"),
    String(today.getDate()).padStart(2, "0"),
  ].join("-");
}

function calculateAge(dateOfBirth: string): number | null {
  if (!dateOfBirth) return null;

  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateOfBirth);

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
  today.setHours(0, 0, 0, 0);

  if (dob > today || year < 1900) return null;

  let age = today.getFullYear() - year;

  if (
    today.getMonth() < month - 1 ||
    (today.getMonth() === month - 1 &&
      today.getDate() < day)
  ) {
    age--;
  }

  return age >= 0 && age <= 120 ? age : null;
}

/* ================= ERROR HANDLING ================= */

type RegistrationErrorLike = {
  response?: {
    data?: {
      detail?: unknown;
      message?: unknown;
    };
  };
  message?: string;
};

function getRegistrationError(error: unknown): string {
  const apiError = (
    typeof error === "object" && error !== null
      ? error
      : {}
  ) as RegistrationErrorLike;

  const detail = apiError.response?.data?.detail;

  if (typeof detail === "string") return detail;

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item: unknown) => {
        if (typeof item !== "object" || item === null) return "";

        const entry = item as { msg?: unknown; message?: unknown };
        if (typeof entry.msg === "string") return entry.msg;
        if (typeof entry.message === "string") return entry.message;
        return "";
      })
      .filter((message: string) => message.length > 0);

    if (messages.length > 0) return messages.join(" ");
  }

  const responseMessage = apiError.response?.data?.message;

  if (typeof responseMessage === "string") return responseMessage;
  if (typeof apiError.message === "string") return apiError.message;

  return "Something went wrong. Please try again.";
}

/* ================= COMPONENT ================= */

export default function Register() {
  const {
    register,
    user,
    loading,
    verifyRegistrationEmail,
    resendRegistrationEmail,
    selectRegistrationMethod,
    setupRegistrationTotp,
    setupRegistrationEmail,
    completeRegistration,
  } = useAuth();

  const navigate = useNavigate();
  const isDark = useThemeMode();

  // Registration stages:
  // details -> email -> method -> setup -> complete
  const [stage, setStage] = useState("details");

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [dateOfBirth, setDateOfBirth] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [emailCode, setEmailCode] = useState("");
  const [twoFactorCode, setTwoFactorCode] = useState("");

  type TwoFactorMethod = "email" | "totp";
  const [method, setMethod] = useState<TwoFactorMethod>("totp");

  const [registrationToken, setRegistrationToken] = useState("");
  const [enrollmentToken, setEnrollmentToken] = useState("");

  const [provisioningUri, setProvisioningUri] = useState("");
  const [totpSecret, setTotpSecret] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [busy, setBusy] = useState(false);

  const calculatedAge = calculateAge(dateOfBirth);

  useEffect(() => {
    if (!loading && user) {
      navigate("/dashboard", { replace: true });
    }
  }, [loading, user, navigate]);

  /* ================= STYLES ================= */

  const headingClass = isDark
    ? "text-white"
    : "text-slate-900";

  const mutedClass = isDark
    ? "text-slate-400"
    : "text-slate-500";

  const panelClass = isDark
    ? "border border-white/10 bg-white/[0.055] shadow-[0_25px_80px_rgba(0,0,0,0.4)]"
    : "border border-white/80 bg-white/80 shadow-[0_25px_80px_rgba(31,41,55,0.10)]";

  const inputClass = isDark
    ? "border-white/10 bg-slate-950/50 text-white placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10"
    : "border-slate-200 bg-white/80 text-slate-900 placeholder:text-slate-400 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/10";

  const labelClass = `mb-1.5 block text-xs font-semibold ${headingClass}`;

  const passwordContainerClass = isDark
    ? "border-white/10 bg-slate-950/50"
    : "border-slate-200 bg-white/80";

  const passwordTextClass = isDark
    ? "text-white placeholder:text-slate-500"
    : "text-slate-900 placeholder:text-slate-400";

  const eyeButtonClass = isDark
    ? "text-slate-400 hover:bg-white/10 hover:text-cyan-300"
    : "text-slate-500 hover:bg-slate-100 hover:text-cyan-600";

  const secondaryButtonClass = isDark
    ? "border border-white/10 bg-white/5 text-slate-200 hover:bg-white/10"
    : "border border-slate-200 bg-white text-slate-700 hover:bg-slate-50";

  /* ================= HELPERS ================= */

  function clearMessages() {
    setError("");
    setSuccess("");
  }

  async function runAction(action: () => Promise<void>): Promise<void> {
    if (busy) return;

    setBusy(true);
    clearMessages();

    try {
      await action();
    } catch (err: unknown) {
      setError(getRegistrationError(err));
    } finally {
      setBusy(false);
    }
  }

  /* ================= STEP 1: ACCOUNT DETAILS ================= */

  async function handleRegister(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (busy) return;

    clearMessages();

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

    if (normalizedName.length < 2 || normalizedName.length > 100) {
      setError("Name must contain between 2 and 100 characters.");
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
      setError("Password needs an uppercase letter.");
      return;
    }

    if (!/[a-z]/.test(password)) {
      setError("Password needs a lowercase letter.");
      return;
    }

    if (!/\d/.test(password)) {
      setError("Password needs a number.");
      return;
    }

    if (!/[^A-Za-z0-9]/.test(password)) {
      setError("Password needs a special character.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    await runAction(async () => {
      const result = await register({
        name: normalizedName,
        email: normalizedEmail,
        password,
        date_of_birth: dateOfBirth,
      });

      if (!result.registration_token) {
        throw new Error(
          "The server did not return a registration token."
        );
      }

      setRegistrationToken(result.registration_token);
      setEmail(normalizedEmail);
      setStage("email");

      setSuccess(
        "Registration started. Check your email for the six-digit verification code."
      );
    });
  }

  /* ================= STEP 2: VERIFY EMAIL ================= */

  async function handleEmailVerification(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!/^\d{6}$/.test(emailCode)) {
      setError("Enter the six-digit email verification code.");
      return;
    }

    await runAction(async () => {
      const result = await verifyRegistrationEmail(
        registrationToken,
        emailCode
      );

      if (!result.enrollment_token) {
        throw new Error(
          "The server did not return an enrollment token."
        );
      }

      setEnrollmentToken(result.enrollment_token);
      setStage("method");

      setSuccess(
        "Email verified successfully. Now choose your 2FA method."
      );
    });
  }

  async function handleResendEmail() {
    await runAction(async () => {
      const result = await resendRegistrationEmail(
        registrationToken
      );

      setSuccess(result.message);
      setEmailCode("");
    });
  }

  /* ================= STEP 3: SELECT 2FA ================= */

  async function handleMethodSelection() {
    await runAction(async () => {
      await selectRegistrationMethod(
        enrollmentToken,
        method
      );

      if (method === "totp") {
        const result = await setupRegistrationTotp(
          enrollmentToken
        );

        setProvisioningUri(result.provisioning_uri);
        setTotpSecret(result.secret);
      } else {
        await setupRegistrationEmail(enrollmentToken);
        setProvisioningUri("");
        setTotpSecret("");
      }

      setTwoFactorCode("");
      setStage("setup");
    });
  }

  /* ================= STEP 4: COMPLETE ================= */

  async function handleComplete(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!/^\d{6}$/.test(twoFactorCode)) {
      setError("Enter a valid six-digit verification code.");
      return;
    }

    await runAction(async () => {
      await completeRegistration(
        enrollmentToken,
        twoFactorCode
      );

      setStage("complete");
      setSuccess("Your account has been created successfully.");

      navigate("/dashboard", { replace: true });
    });
  }

  /* ================= LOADING ================= */

  if (loading) {
    return (
      <main
        className={`flex min-h-dvh items-center justify-center ${
          isDark
            ? "bg-[#080d18] text-cyan-400"
            : "bg-slate-50 text-cyan-600"
        }`}
      >
        <LoaderCircle size={22} className="mr-3 animate-spin" />
        Checking your session...
      </main>
    );
  }

  if (user) {
    return (
      <main
        className={`flex min-h-dvh items-center justify-center ${
          isDark
            ? "bg-[#080d18] text-cyan-400"
            : "bg-slate-50 text-cyan-600"
        }`}
      >
        <LoaderCircle size={22} className="mr-3 animate-spin" />
        Opening dashboard...
      </main>
    );
  }

  /* ================= PROGRESS ================= */

  const stages = [
    "Account",
    "Email",
    "2FA",
    "Complete",
  ];

  const stageIndex =
    stage === "details" ? 0 :
    stage === "email" ? 1 :
    stage === "method" || stage === "setup" ? 2 : 3;

  /* ================= UI ================= */

  return (
    <main
      className={`relative flex min-h-dvh items-center justify-center overflow-x-hidden px-4 py-6 transition-colors duration-300 sm:py-8 ${
        isDark ? "bg-[#080d18]" : "bg-[#f3f7fc]"
      }`}
    >
      {/* Background effects */}

      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div
          className={`absolute -left-32 -top-32 h-80 w-80 rounded-full blur-[100px] ${
            isDark ? "bg-cyan-500/10" : "bg-cyan-400/20"
          }`}
        />

        <div
          className={`absolute -bottom-32 -right-32 h-80 w-80 rounded-full blur-[100px] ${
            isDark ? "bg-blue-600/10" : "bg-blue-400/20"
          }`}
        />

        <div
          className={`absolute left-1/2 top-1/2 h-96 w-96 -translate-x-1/2 -translate-y-1/2 rounded-full blur-[130px] ${
            isDark ? "bg-indigo-500/[0.06]" : "bg-indigo-400/[0.10]"
          }`}
        />
      </div>

      <section
        className={`relative z-10 my-auto w-full max-w-[500px] rounded-[28px] p-5 backdrop-blur-3xl sm:p-7 ${panelClass}`}
      >
        {/* Brand */}

        <div className="mb-5 flex items-center gap-3">
          <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-2.5 text-cyan-500 shadow-lg shadow-cyan-500/10">
            <ShieldCheck size={26} />
          </div>

          <div>
            <h1 className={`text-lg font-bold tracking-tight ${headingClass}`}>
              IDPS Shield
            </h1>

            <p className={`text-xs ${mutedClass}`}>
              Intelligent Cyber Defense System
            </p>
          </div>
        </div>

        {/* Heading */}

        <div className="mb-5">
          <div
            className={`mb-2 inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[10px] font-semibold ${
              isDark
                ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
                : "border-emerald-200 bg-emerald-50 text-emerald-700"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            SECURE REGISTRATION
          </div>

          <h2 className={`text-2xl font-bold tracking-tight ${headingClass}`}>
            {stage === "details" && "Create your account"}
            {stage === "email" && "Verify your email"}
            {stage === "method" && "Secure your account"}
            {stage === "setup" && "Set up two-factor authentication"}
          </h2>

          <p className={`mt-1 text-xs leading-5 ${mutedClass}`}>
            {stage === "details" &&
              "Enter your details to create your IDPS Shield account."}
            {stage === "email" &&
              `Enter the verification code sent to ${email}.`}
            {stage === "method" &&
              "Choose how you want to protect your account."}
            {stage === "setup" &&
              "Verify your second authentication factor to complete registration."}
          </p>
        </div>

        {/* Progress */}

        <div className="mb-6 grid grid-cols-4 gap-2">
          {stages.map((item, index) => (
            <div key={item}>
              <div
                className={`mb-2 h-1.5 rounded-full ${
                  index <= stageIndex
                    ? "bg-gradient-to-r from-cyan-500 to-blue-500"
                    : isDark
                      ? "bg-white/10"
                      : "bg-slate-200"
                }`}
              />
              <p
                className={`text-center text-[10px] ${
                  index <= stageIndex
                    ? "font-semibold text-cyan-500"
                    : mutedClass
                }`}
              >
                {item}
              </p>
            </div>
          ))}
        </div>

        {/* STEP 1: DETAILS */}

        {stage === "details" && (
          <form
            onSubmit={handleRegister}
            className="flex w-full flex-col gap-4"
          >
            <div>
              <label htmlFor="register-name" className={labelClass}>
                Full name
              </label>

              <div className="relative">
                <User
                  size={17}
                  className={`absolute left-3.5 top-1/2 -translate-y-1/2 ${mutedClass}`}
                />

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
                  className={`w-full rounded-xl border py-3 pl-10 pr-3 text-sm outline-none transition-all ${inputClass}`}
                />
              </div>
            </div>

            <div>
              <label htmlFor="register-email" className={labelClass}>
                Email address
              </label>

              <div className="relative">
                <Mail
                  size={17}
                  className={`absolute left-3.5 top-1/2 -translate-y-1/2 ${mutedClass}`}
                />

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
                  className={`w-full rounded-xl border py-3 pl-10 pr-3 text-sm outline-none transition-all ${inputClass}`}
                />
              </div>
            </div>

            <div>
              <label htmlFor="register-dob" className={labelClass}>
                Date of birth
              </label>

              <div className="relative">
                <CalendarDays
                  size={17}
                  className={`absolute left-3.5 top-1/2 -translate-y-1/2 ${mutedClass}`}
                />

                <input
                  id="register-dob"
                  type="date"
                  required
                  min="1900-01-01"
                  max={getTodayDate()}
                  value={dateOfBirth}
                  onChange={(event) => setDateOfBirth(event.target.value)}
                  disabled={busy}
                  className={`w-full rounded-xl border py-3 pl-10 pr-3 text-sm outline-none transition-all ${inputClass} ${
                    isDark ? "[color-scheme:dark]" : "[color-scheme:light]"
                  }`}
                />
              </div>

              {dateOfBirth && calculatedAge !== null && (
                <p className={`mt-2 text-xs ${mutedClass}`}>
                  Calculated age: {calculatedAge} years
                </p>
              )}
            </div>

            <div>
              <label htmlFor="register-password" className={labelClass}>
                Password
              </label>

              <div
                className={`flex w-full rounded-xl border transition-all focus-within:border-cyan-400/60 focus-within:ring-2 focus-within:ring-cyan-400/10 ${passwordContainerClass}`}
              >
                <LockKeyhole
                  size={17}
                  className={`ml-3.5 shrink-0 self-center ${mutedClass}`}
                />

                <input
                  id="register-password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="new-password"
                  required
                  minLength={8}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Create password"
                  disabled={busy}
                  className={`min-w-0 flex-1 bg-transparent px-3 py-3 text-sm outline-none ${passwordTextClass}`}
                />

                <button
                  type="button"
                  onClick={() => setShowPassword((value) => !value)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className={`mr-2 rounded-lg p-2 transition ${eyeButtonClass}`}
                >
                  {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </div>

              <p className={`mt-1.5 text-[10px] leading-4 ${mutedClass}`}>
                8+ characters, uppercase, lowercase, number and special character.
              </p>
            </div>

            <div>
              <label htmlFor="confirm-password" className={labelClass}>
                Confirm password
              </label>

              <div
                className={`flex w-full rounded-xl border transition-all focus-within:border-cyan-400/60 focus-within:ring-2 focus-within:ring-cyan-400/10 ${passwordContainerClass}`}
              >
                <LockKeyhole
                  size={17}
                  className={`ml-3.5 shrink-0 self-center ${mutedClass}`}
                />

                <input
                  id="confirm-password"
                  type={showConfirmPassword ? "text" : "password"}
                  autoComplete="new-password"
                  required
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  placeholder="Confirm password"
                  disabled={busy}
                  className={`min-w-0 flex-1 bg-transparent px-3 py-3 text-sm outline-none ${passwordTextClass}`}
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
                  className={`mr-2 rounded-lg p-2 transition ${eyeButtonClass}`}
                >
                  {showConfirmPassword ? (
                    <EyeOff size={17} />
                  ) : (
                    <Eye size={17} />
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={busy}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy ? (
                <>
                  <LoaderCircle size={18} className="animate-spin" />
                  Sending verification code...
                </>
              ) : (
                <>
                  <CheckCircle2 size={18} />
                  Continue
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </form>
        )}

        {/* STEP 2: EMAIL VERIFICATION */}

        {stage === "email" && (
          <form
            onSubmit={handleEmailVerification}
            className="flex flex-col gap-4"
          >
            <div
              className={`rounded-xl border p-4 ${
                isDark
                  ? "border-cyan-400/20 bg-cyan-400/[0.06]"
                  : "border-cyan-200 bg-cyan-50"
              }`}
            >
              <Mail className="mb-2 text-cyan-500" size={22} />
              <p className={`text-sm font-semibold ${headingClass}`}>
                Check your inbox
              </p>
              <p className={`mt-1 break-all text-xs ${mutedClass}`}>
                We sent a six-digit code to {email}.
              </p>
            </div>

            <div>
              <label htmlFor="email-otp" className={labelClass}>
                Email verification code
              </label>

              <input
                id="email-otp"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                required
                value={emailCode}
                onChange={(event) =>
                  setEmailCode(
                    event.target.value.replace(/\D/g, "").slice(0, 6)
                  )
                }
                placeholder="000000"
                className={`w-full rounded-xl border px-4 py-4 text-center text-2xl font-bold tracking-[0.5em] outline-none ${inputClass}`}
              />
            </div>

            <button
              type="submit"
              disabled={busy || emailCode.length !== 6}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-3 text-sm font-semibold text-white disabled:opacity-50"
            >
              {busy ? (
                <LoaderCircle size={18} className="animate-spin" />
              ) : (
                <CheckCircle2 size={18} />
              )}
              Verify email
            </button>

            <button
              type="button"
              disabled={busy}
              onClick={handleResendEmail}
              className={`w-full rounded-xl px-4 py-3 text-xs font-semibold transition ${secondaryButtonClass}`}
            >
              Resend verification code
            </button>

            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setStage("details");
                clearMessages();
              }}
              className={`flex items-center justify-center gap-2 text-xs ${mutedClass}`}
            >
              <ArrowLeft size={14} />
              Back to account details
            </button>
          </form>
        )}

        {/* STEP 3: CHOOSE 2FA */}

        {stage === "method" && (
          <div className="flex flex-col gap-4">
            <button
              type="button"
              onClick={() => setMethod("totp")}
              className={`flex items-start gap-3 rounded-xl border p-4 text-left transition ${
                method === "totp"
                  ? "border-cyan-500 bg-cyan-500/10"
                  : secondaryButtonClass
              }`}
            >
              <Smartphone className="mt-0.5 shrink-0 text-cyan-500" size={22} />
              <span>
                <span className={`block text-sm font-semibold ${headingClass}`}>
                  Google Authenticator
                </span>
                <span className={`mt-1 block text-xs ${mutedClass}`}>
                  Use an authenticator app to generate time-based codes.
                </span>
              </span>
              {method === "totp" && (
                <CheckCircle2 className="ml-auto shrink-0 text-cyan-500" size={18} />
              )}
            </button>

            <button
              type="button"
              onClick={() => setMethod("email")}
              className={`flex items-start gap-3 rounded-xl border p-4 text-left transition ${
                method === "email"
                  ? "border-cyan-500 bg-cyan-500/10"
                  : secondaryButtonClass
              }`}
            >
              <Mail className="mt-0.5 shrink-0 text-cyan-500" size={22} />
              <span>
                <span className={`block text-sm font-semibold ${headingClass}`}>
                  Email OTP
                </span>
                <span className={`mt-1 block text-xs ${mutedClass}`}>
                  Receive a new verification code by email when signing in.
                </span>
              </span>
              {method === "email" && (
                <CheckCircle2 className="ml-auto shrink-0 text-cyan-500" size={18} />
              )}
            </button>

            <button
              type="button"
              onClick={handleMethodSelection}
              disabled={busy}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-3 text-sm font-semibold text-white disabled:opacity-50"
            >
              {busy ? (
                <LoaderCircle size={18} className="animate-spin" />
              ) : (
                <ArrowRight size={18} />
              )}
              Continue with selected method
            </button>
          </div>
        )}

        {/* STEP 4: 2FA SETUP */}

        {stage === "setup" && (
          <form onSubmit={handleComplete} className="flex flex-col gap-4">
            {method === "totp" ? (
              <>
                <div
                  className={`rounded-xl border p-4 ${
                    isDark
                      ? "border-cyan-400/20 bg-cyan-400/[0.06]"
                      : "border-cyan-200 bg-cyan-50"
                  }`}
                >
                  <div className="mb-3 flex items-center gap-2">
                    <Smartphone size={19} className="text-cyan-500" />
                    <p className={`text-sm font-semibold ${headingClass}`}>
                      Scan authenticator QR code
                    </p>
                  </div>

                  <div className="mx-auto flex w-fit rounded-xl bg-white p-3">
                    {provisioningUri && (
                      <QRCodeSVG
                        value={provisioningUri}
                        size={190}
                        level="M"
                        includeMargin
                      />
                    )}
                  </div>

                  <p className={`mt-3 text-center text-xs ${mutedClass}`}>
                    Open Google Authenticator, choose Add account, then scan this QR code.
                  </p>
                </div>

                <div>
                  <label className={labelClass}>
                    Manual setup key
                  </label>

                  <div className={`break-all rounded-xl border p-3 font-mono text-xs ${secondaryButtonClass}`}>
                    {totpSecret}
                  </div>
                </div>

                <p className={`text-xs leading-5 ${mutedClass}`}>
                  If you cannot scan the QR code, enter the setup key manually in your authenticator app.
                </p>
              </>
            ) : (
              <div
                className={`rounded-xl border p-4 ${
                  isDark
                    ? "border-cyan-400/20 bg-cyan-400/[0.06]"
                    : "border-cyan-200 bg-cyan-50"
                }`}
              >
                <Mail size={24} className="mb-2 text-cyan-500" />
                <p className={`text-sm font-semibold ${headingClass}`}>
                  Check your email
                </p>
                <p className={`mt-1 text-xs ${mutedClass}`}>
                  A second-factor verification code has been sent to {email}.
                </p>

                <button
                  type="button"
                  onClick={() =>
                    runAction(async () => {
                      const result = await setupRegistrationEmail(
                        enrollmentToken
                      );
                      setSuccess(result.message);
                    })
                  }
                  disabled={busy}
                  className="mt-3 text-xs font-semibold text-cyan-500 hover:underline"
                >
                  Resend 2FA code
                </button>
              </div>
            )}

            <div>
              <label htmlFor="two-factor-code" className={labelClass}>
                {method === "totp"
                  ? "Authenticator code"
                  : "Email verification code"}
              </label>

              <input
                id="two-factor-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                required
                value={twoFactorCode}
                onChange={(event) =>
                  setTwoFactorCode(
                    event.target.value.replace(/\D/g, "").slice(0, 6)
                  )
                }
                placeholder="000000"
                className={`w-full rounded-xl border px-4 py-4 text-center text-2xl font-bold tracking-[0.5em] outline-none ${inputClass}`}
              />
            </div>

            <button
              type="submit"
              disabled={busy || twoFactorCode.length !== 6}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-3 text-sm font-semibold text-white disabled:opacity-50"
            >
              {busy ? (
                <LoaderCircle size={18} className="animate-spin" />
              ) : (
                <ShieldCheck size={18} />
              )}
              Verify and create account
            </button>

            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setStage("method");
                setTwoFactorCode("");
                clearMessages();
              }}
              className={`flex items-center justify-center gap-2 text-xs ${mutedClass}`}
            >
              <ArrowLeft size={14} />
              Change authentication method
            </button>
          </form>
        )}

        {/* ERROR */}

        {error && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-2 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-xs leading-5 text-red-500"
          >
            <AlertCircle size={16} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* SUCCESS */}

        {success && (
          <div
            role="status"
            className="mt-4 flex items-start gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3 text-xs leading-5 text-emerald-500"
          >
            <CheckCircle2 size={16} className="mt-0.5 shrink-0" />
            <span>{success}</span>
          </div>
        )}

        {/* LOGIN LINK */}

        <p className={`mt-5 text-center text-xs ${mutedClass}`}>
          Already have an account?{" "}
          <Link
            to="/login"
            className="font-semibold text-cyan-500 transition hover:text-blue-500 hover:underline"
          >
            Sign in
          </Link>
        </p>

        {/* FOOTER */}

        <div
          className={`mt-5 flex items-center justify-center gap-2 border-t pt-4 text-[10px] ${
            isDark
              ? "border-white/10 text-slate-500"
              : "border-slate-200 text-slate-400"
          }`}
        >
          <Shield size={12} />
          Email verification and two-factor authentication protect your account.
        </div>
      </section>
    </main>
  );
}
