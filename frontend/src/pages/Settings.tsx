
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

interface ProtectionSettings {
  safe_browsing: boolean;
  strict_mode: boolean;
}

const DEFAULT_SETTINGS: ProtectionSettings = {
  safe_browsing: true,
  strict_mode: true,
};

export default function Settings() {
  const [settings, setSettings] =
    useState<ProtectionSettings>(DEFAULT_SETTINGS);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

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
      } catch (err: any) {
        if (active) {
          setError(
            err.response?.data?.detail ||
              "Unable to load protection settings. Check your login and backend."
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

  async function saveSettings() {
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
    } catch (err: any) {
      setError(
        err.response?.data?.detail ||
          "Failed to save settings. Please try again."
      );
    } finally {
      setSaving(false);
    }
  }

  function resetSettings() {
    setSettings(DEFAULT_SETTINGS);
    setSuccess("");
    setError("");
  }

  if (loading) {
    return (
      <div className="flex min-h-64 items-center justify-center text-slate-500">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        Loading protection settings...
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4 text-slate-100 sm:p-6">
      {/* Page heading */}
      <div>
        <div className="flex items-center gap-3">
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-3 text-cyan-400">
            <ShieldCheck size={27} />
          </div>

          <div>
            <h1 className="text-2xl font-bold">
              Security Settings
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Manage browsing protection and your browser extension.
            </p>
          </div>
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div
          role="alert"
          className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
        >
          <AlertCircle className="mt-0.5 shrink-0" size={19} />
          <p>{error}</p>
        </div>
      )}

      {/* Success message */}
      {success && (
        <div
          role="status"
          className="flex items-start gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-300"
        >
          <CheckCircle2 className="mt-0.5 shrink-0" size={19} />
          <p>{success}</p>
        </div>
      )}

      {/* Browser extension */}
      <section className="rounded-2xl border border-cyan-500/20 bg-slate-900 p-5 shadow-lg sm:p-6">
        <div className="mb-5 flex items-center gap-3">
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-3 text-cyan-300">
            <Chrome size={25} />
          </div>

          <div>
            <h2 className="text-lg font-semibold">
              IDPS Shield Browser Extension
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Add website security checks to your Chrome browsing workflow.
            </p>
          </div>
        </div>

        <DownloadExtensionButton />

        <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950/60 p-4">
          <h3 className="font-medium text-slate-200">
            How to install
          </h3>

          <ol className="mt-3 list-inside list-decimal space-y-2 text-sm leading-6 text-slate-400">
            <li>Download the extension ZIP file.</li>
            <li>Extract the ZIP into a folder on your computer.</li>
            <li>Open Chrome and visit chrome://extensions.</li>
            <li>Enable Developer mode.</li>
            <li>
              Select Load unpacked and choose the extracted folder
              containing manifest.json.
            </li>
            <li>
              Configure the backend URL and access token in the extension
              if required.
            </li>
          </ol>
        </div>

        <p className="mt-4 text-xs leading-5 text-slate-500">
          The extension uses the detection rules and API that are actually
          configured. A failed scan does not mean a website is safe.
        </p>
      </section>

      {/* Web protection settings */}
      <section className="rounded-2xl border border-slate-700 bg-slate-900 p-5 shadow-sm sm:p-6">
        <div className="mb-5 flex items-center gap-3">
          <ShieldCheck className="text-cyan-400" size={22} />

          <div>
            <h2 className="font-semibold">Web Protection</h2>
            <p className="text-sm text-slate-400">
              Choose your preferred browsing protection options.
            </p>
          </div>
        </div>

        <div className="divide-y divide-slate-800">
          <SettingToggle
            title="Safe Browsing"
            description="Enable the safe-browsing preference for website checks."
            checked={settings.safe_browsing}
            onChange={(value) =>
              updateSetting("safe_browsing", value)
            }
          />

          <SettingToggle
            title="Strict Mode"
            description="Treat websites with unknown reputation more cautiously."
            checked={settings.strict_mode}
            onChange={(value) =>
              updateSetting("strict_mode", value)
            }
          />
        </div>
      </section>

      {/* Save and reset */}
      <div className="flex flex-wrap gap-3">
        <button
          type="button"
          onClick={saveSettings}
          disabled={saving}
          className="inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-500 px-5 py-3 font-medium text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
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
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 px-5 py-3 font-medium text-slate-300 transition hover:bg-slate-800 disabled:opacity-50"
        >
          <RotateCcw size={17} />
          Reset Form
        </button>
      </div>

      {/* Security note */}
      <div className="flex items-start gap-3 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-sm text-amber-200">
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

interface SettingToggleProps {
  title: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}

function SettingToggle({
  title,
  description,
  checked,
  onChange,
}: SettingToggleProps) {
  return (
    <div className="flex items-center justify-between gap-4 py-5">
      <div>
        <h3 className="text-sm font-medium text-slate-200">
          {title}
        </h3>
        <p className="mt-1 text-sm leading-5 text-slate-400">
          {description}
        </p>
      </div>

      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={title}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${
          checked ? "bg-cyan-500" : "bg-slate-600"
        }`}
      >
        <span
          className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${
            checked ? "translate-x-6" : "translate-x-1"
          }`}
        />
      </button>
    </div>
  );
}
