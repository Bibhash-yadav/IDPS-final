
import { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Save,
  Loader2,
  CheckCircle2,
  AlertCircle,
  RotateCcw,
  Chrome,
} from "lucide-react";

import api from "../services/api";
import DownloadExtensionButton from "../components/DownloadExtensionButton";

/* ================= TYPES ================= */

interface ProtectionSettings {
  safe_browsing: boolean;
  strict_mode: boolean;
}

interface ApiError {
  response?: {
    data?: {
      detail?: string;
      message?: string;
    };
  };
}

/* ================= DEFAULT SETTINGS ================= */

const DEFAULT_SETTINGS: ProtectionSettings = {
  safe_browsing: true,
  strict_mode: true,
};

/* ================= THEME HOOK ================= */

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

/* ================= ERROR HANDLER ================= */

function getErrorMessage(error: unknown, fallback: string): string {
  const apiError = error as ApiError;

  return (
    apiError.response?.data?.detail ||
    apiError.response?.data?.message ||
    fallback
  );
}

/* ================= SETTINGS PAGE ================= */

export default function Settings() {
  const isDark = useThemeMode();

  const [settings, setSettings] =
    useState<ProtectionSettings>(DEFAULT_SETTINGS);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  /* ================= THEME STYLES ================= */

  const headingClass = isDark ? "text-white" : "text-slate-900";

  const mutedClass = isDark ? "text-slate-400" : "text-slate-500";

  const cardClass = isDark
    ? "border border-white/[0.08] bg-white/[0.045] shadow-[0_15px_45px_rgba(0,0,0,0.18)]"
    : "border border-white/80 bg-white/75 shadow-[0_15px_45px_rgba(31,41,55,0.06)]";

  const innerCardClass = isDark
    ? "border border-white/[0.07] bg-slate-950/30"
    : "border border-slate-200/80 bg-slate-50/70";

  const dividerClass = isDark
    ? "divide-white/[0.08]"
    : "divide-slate-200";

  /* ================= LOAD SETTINGS ================= */

  useEffect(() => {
    let active = true;

    async function loadSettings() {
      setLoading(true);
      setError("");

      try {
        const response = await api.get<Partial<ProtectionSettings>>(
          "/api/protection/settings"
        );

        if (active) {
          setSettings({
            ...DEFAULT_SETTINGS,
            ...response.data,
          });
        }
      } catch (err: unknown) {
        if (active) {
          setError(
            getErrorMessage(
              err,
              "Unable to load protection settings. Check your login and backend."
            )
          );
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    void loadSettings();

    return () => {
      active = false;
    };
  }, []);

  /* ================= UPDATE SETTINGS ================= */

  function updateSetting<K extends keyof ProtectionSettings>(
    key: K,
    value: ProtectionSettings[K]
  ) {
    setSettings((previous) => ({
      ...previous,
      [key]: value,
    }));

    setSuccess("");
    setError("");
  }

  /* ================= SAVE SETTINGS ================= */

  async function saveSettings() {
    if (saving) return;

    setSaving(true);
    setError("");
    setSuccess("");

    try {
      const response = await api.put<Partial<ProtectionSettings>>(
        "/api/protection/settings",
        settings
      );

      setSettings({
        ...DEFAULT_SETTINGS,
        ...response.data,
      });

      setSuccess("Protection settings saved successfully.");
    } catch (err: unknown) {
      setError(
        getErrorMessage(
          err,
          "Failed to save settings. Please try again."
        )
      );
    } finally {
      setSaving(false);
    }
  }

  /* ================= RESET SETTINGS ================= */

  function resetSettings() {
    setSettings(DEFAULT_SETTINGS);
    setSuccess("");
    setError("");
  }

  /* ================= LOADING SCREEN ================= */

  if (loading) {
    return (
      <div
        className={`flex min-h-64 items-center justify-center ${
          isDark ? "text-slate-400" : "text-slate-500"
        }`}
      >
        <Loader2 className="mr-2 h-5 w-5 animate-spin text-cyan-500" />
        Loading protection settings...
      </div>
    );
  }

  /* ================= MAIN UI ================= */

  return (
    <div
      className={`relative mx-auto w-full max-w-6xl space-y-6 overflow-hidden p-4 transition-colors duration-300 sm:p-6 ${
        isDark ? "text-slate-100" : "text-slate-800"
      }`}
    >
      {/* Background effects */}

      <div className="pointer-events-none absolute -left-32 top-10 h-72 w-72 rounded-full bg-cyan-500/[0.06] blur-[100px]" />

      <div className="pointer-events-none absolute -right-32 top-96 h-72 w-72 rounded-full bg-blue-500/[0.06] blur-[100px]" />

      {/* PAGE HEADING */}

      <div className="relative flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-2xl border border-cyan-500/20 bg-cyan-500/10 p-3 text-cyan-500 shadow-lg shadow-cyan-500/10">
            <ShieldCheck size={27} />
          </div>

          <div>
            <h1 className={`text-2xl font-bold tracking-tight ${headingClass}`}>
              Security Settings
            </h1>

            <p className={`mt-1 text-sm ${mutedClass}`}>
              Manage browsing protection and your browser extension.
            </p>
          </div>
        </div>

        <div
          className={`inline-flex w-fit items-center gap-2 rounded-full border px-3 py-2 text-xs font-medium ${
            isDark
              ? "border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-300"
              : "border-emerald-200 bg-emerald-50 text-emerald-700"
          }`}
        >
          <span className="h-2 w-2 rounded-full bg-emerald-400" />
          Protection preferences
        </div>
      </div>

      {/* ERROR MESSAGE */}

      {error && (
        <div
          role="alert"
          className="relative flex items-start gap-3 rounded-2xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-400 backdrop-blur-xl"
        >
          <AlertCircle className="mt-0.5 shrink-0" size={19} />

          <p>{error}</p>
        </div>
      )}

      {/* SUCCESS MESSAGE */}

      {success && (
        <div
          role="status"
          className="relative flex items-start gap-3 rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-sm text-emerald-500 backdrop-blur-xl"
        >
          <CheckCircle2 className="mt-0.5 shrink-0" size={19} />

          <p>{success}</p>
        </div>
      )}

      {/* BROWSER EXTENSION */}

      <section
        className={`relative overflow-hidden rounded-3xl p-5 backdrop-blur-2xl transition-all duration-300 sm:p-6 ${cardClass}`}
      >
        {/* Decorative background */}

        <div className="pointer-events-none absolute -right-16 -top-16 h-48 w-48 rounded-full bg-cyan-500/[0.08] blur-3xl" />

        <div className="relative">
          <div className="mb-5 flex flex-col gap-4 sm:flex-row sm:items-center">
            <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-500 shadow-lg shadow-cyan-500/10">
              <Chrome size={29} />
            </div>

            <div>
              <h2 className={`text-lg font-bold ${headingClass}`}>
                IDPS Shield Browser Extension
              </h2>

              <p className={`mt-1 text-sm leading-6 ${mutedClass}`}>
                Add website security checks to your Chrome browsing workflow.
              </p>
            </div>
          </div>

          {/* Download button */}

          <div className="relative">
            <DownloadExtensionButton />
          </div>

          {/* Installation instructions */}

          <div className={`mt-6 rounded-2xl p-4 sm:p-5 ${innerCardClass}`}>
            <div className="mb-4 flex items-center gap-2">
              <div className="rounded-lg bg-cyan-500/10 p-2 text-cyan-500">
                <Chrome size={18} />
              </div>

              <h3 className={`font-semibold ${headingClass}`}>
                How to install
              </h3>
            </div>

            <ol className={`space-y-3 text-sm leading-6 ${mutedClass}`}>
              <li className="flex items-start gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-xs font-semibold text-cyan-500">
                  1
                </span>
                <span>Download the extension ZIP file.</span>
              </li>

              <li className="flex items-start gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-xs font-semibold text-cyan-500">
                  2
                </span>
                <span>Extract the ZIP into a folder on your computer.</span>
              </li>

              <li className="flex items-start gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-xs font-semibold text-cyan-500">
                  3
                </span>
                <span>
                  Open Chrome and visit{" "}
                  <code
                    className={`rounded-md px-2 py-1 font-mono text-xs ${
                      isDark
                        ? "bg-slate-800 text-cyan-300"
                        : "bg-cyan-50 text-cyan-700"
                    }`}
                  >
                    chrome://extensions
                  </code>
                  .
                </span>
              </li>

              <li className="flex items-start gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-xs font-semibold text-cyan-500">
                  4
                </span>
                <span>Enable Developer mode.</span>
              </li>

              <li className="flex items-start gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-xs font-semibold text-cyan-500">
                  5
                </span>
                <span>
                  Select Load unpacked and choose the extracted folder
                  containing manifest.json.
                </span>
              </li>

              <li className="flex items-start gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-xs font-semibold text-cyan-500">
                  6
                </span>
                <span>
                  Configure the backend URL and access token in the extension
                  if required.
                </span>
              </li>
            </ol>
          </div>

          <p className={`mt-4 text-xs leading-5 ${mutedClass}`}>
            The extension uses the detection rules and API that are actually
            configured. A failed scan does not mean a website is safe.
          </p>
        </div>
      </section>

      {/* WEB PROTECTION */}

      <section
        className={`rounded-3xl p-5 backdrop-blur-2xl transition-all duration-300 sm:p-6 ${cardClass}`}
      >
        <div className="mb-5 flex items-center gap-3">
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-2.5 text-cyan-500">
            <ShieldCheck size={22} />
          </div>

          <div>
            <h2 className={`font-bold ${headingClass}`}>
              Web Protection
            </h2>

            <p className={`mt-1 text-sm ${mutedClass}`}>
              Choose your preferred browsing protection options.
            </p>
          </div>
        </div>

        <div className={`divide-y ${dividerClass}`}>
          <SettingToggle
            title="Safe Browsing"
            description="Enable the safe-browsing preference for website checks."
            checked={settings.safe_browsing}
            onChange={(value) => updateSetting("safe_browsing", value)}
            isDark={isDark}
          />

          <SettingToggle
            title="Strict Mode"
            description="Treat websites with unknown reputation more cautiously."
            checked={settings.strict_mode}
            onChange={(value) => updateSetting("strict_mode", value)}
            isDark={isDark}
          />
        </div>
      </section>

      {/* SAVE AND RESET */}

      <div className="flex flex-col gap-3 sm:flex-row">
        <button
          type="button"
          onClick={saveSettings}
          disabled={saving}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xl hover:shadow-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:translate-y-0"
        >
          {saving ? (
            <Loader2 className="animate-spin" size={18} />
          ) : (
            <Save size={18} />
          )}

          {saving ? "Saving..." : "Save Settings"}
        </button>

        <button
          type="button"
          onClick={resetSettings}
          disabled={saving}
          className={`inline-flex items-center justify-center gap-2 rounded-xl border px-6 py-3 text-sm font-semibold transition-all duration-200 disabled:cursor-not-allowed disabled:opacity-50 ${
            isDark
              ? "border-white/10 bg-white/[0.04] text-slate-300 hover:bg-white/[0.09]"
              : "border-slate-200 bg-white/70 text-slate-600 hover:bg-slate-100"
          }`}
        >
          <RotateCcw size={17} />
          Reset Form
        </button>
      </div>

      {/* SECURITY NOTE */}

      <div
        className={`flex items-start gap-3 rounded-2xl border p-4 text-sm backdrop-blur-xl ${
          isDark
            ? "border-amber-500/20 bg-amber-500/[0.06] text-amber-200"
            : "border-amber-200 bg-amber-50/80 text-amber-800"
        }`}
      >
        <ShieldAlert className="mt-0.5 shrink-0" size={19} />

        <p className="leading-6">
          These preferences are saved to your account. Actual enforcement
          depends on the backend implementation and available detection
          sources. HTTPS alone does not prove a website is trustworthy.
        </p>
      </div>
    </div>
  );
}

/* ================= SETTING TOGGLE ================= */

interface SettingToggleProps {
  title: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  isDark: boolean;
}

function SettingToggle({
  title,
  description,
  checked,
  onChange,
  isDark,
}: SettingToggleProps) {
  const headingClass = isDark ? "text-slate-200" : "text-slate-800";

  const mutedClass = isDark ? "text-slate-400" : "text-slate-500";

  return (
    <div className="flex items-center justify-between gap-4 py-5">
      <div className="min-w-0 flex-1">
        <h3 className={`text-sm font-semibold ${headingClass}`}>
          {title}
        </h3>

        <p className={`mt-1 text-sm leading-5 ${mutedClass}`}>
          {description}
        </p>

        <p
          className={`mt-2 text-[11px] font-medium ${
            checked ? "text-cyan-500" : mutedClass
          }`}
        >
          {checked ? "Enabled" : "Disabled"}
        </p>
      </div>

      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={title}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-7 w-12 shrink-0 items-center rounded-full transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:ring-offset-2 ${
          checked
            ? "bg-gradient-to-r from-cyan-500 to-blue-500"
            : isDark
              ? "bg-slate-700"
              : "bg-slate-300"
        }`}
      >
        <span
          className={`inline-block h-5 w-5 rounded-full bg-white shadow-md transition-transform duration-300 ${
            checked ? "translate-x-6" : "translate-x-1"
          }`}
        />
      </button>
    </div>
  );
}




