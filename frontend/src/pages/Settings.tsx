import { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  UserRound,
  Save,
  Loader2,
  CheckCircle2,
  AlertCircle,
  RotateCcw,
} from "lucide-react";
import api from "../services/api";

interface ProtectionSettings {
  safe_browsing: boolean;
  strict_mode: boolean;
  age_restriction: boolean;
  minimum_age: number;
}

const DEFAULT_SETTINGS: ProtectionSettings = {
  safe_browsing: true,
  strict_mode: true,
  age_restriction: false,
  minimum_age: 18,
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
        const response = await api.get<ProtectionSettings>(
          "/api/protection/settings"
        );

        if (active) {
          setSettings(response.data);
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

    loadSettings();

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
      const response = await api.put<ProtectionSettings>(
        "/api/protection/settings",
        settings
      );

      setSettings(response.data);
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
    <div className="mx-auto max-w-5xl space-y-6 p-4 text-slate-900 sm:p-6">
      <div>
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-blue-100 p-3 text-blue-700">
            <ShieldCheck size={27} />
          </div>

          <div>
            <h1 className="text-2xl font-bold">Security Settings</h1>
            <p className="mt-1 text-sm text-slate-500">
              Configure your personal IDPS protection preferences.
            </p>
          </div>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700"
        >
          <AlertCircle className="mt-0.5 shrink-0" size={19} />
          <p>{error}</p>
        </div>
      )}

      {success && (
        <div
          role="status"
          className="flex items-start gap-3 rounded-xl border border-green-200 bg-green-50 p-4 text-sm text-green-700"
        >
          <CheckCircle2 className="mt-0.5 shrink-0" size={19} />
          <p>{success}</p>
        </div>
      )}

      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
        <div className="mb-5 flex items-center gap-3">
          <ShieldCheck className="text-blue-600" size={22} />
          <div>
            <h2 className="font-semibold">Web Protection</h2>
            <p className="text-sm text-slate-500">
              Choose your preferred browsing protection options.
            </p>
          </div>
        </div>

        <div className="divide-y divide-slate-100">
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

          <SettingToggle
            title="Age Restriction"
            description="Enable the age-policy preference for website checks."
            checked={settings.age_restriction}
            onChange={(value) =>
              updateSetting("age_restriction", value)
            }
          />
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
        <div className="mb-5 flex items-center gap-3">
          <UserRound className="text-blue-600" size={22} />

          <div>
            <h2 className="font-semibold">Age Policy</h2>
            <p className="text-sm text-slate-500">
              Set the minimum age preference for supported age checks.
            </p>
          </div>
        </div>

        <label
          htmlFor="minimum-age"
          className="mb-2 block text-sm font-medium text-slate-700"
        >
          Minimum age
        </label>

        <div className="flex max-w-xs items-center gap-3">
          <input
            id="minimum-age"
            type="number"
            min={1}
            max={120}
            step={1}
            value={settings.minimum_age}
            onChange={(event) => {
              const value = Number(event.target.value);

              updateSetting(
                "minimum_age",
                Number.isFinite(value) ? value : 18
              );
            }}
            className="w-full rounded-lg border border-slate-300 px-4 py-2.5 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
          />

          <span className="text-sm text-slate-500">years</span>
        </div>

        {!settings.age_restriction && (
          <p className="mt-3 text-xs text-slate-500">
            Age Restriction is currently disabled. Your minimum-age
            preference will be saved but will not itself establish a
            website's actual age requirement.
          </p>
        )}
      </div>

      <div className="flex flex-wrap gap-3">
        <button
          type="button"
          onClick={saveSettings}
          disabled={
            saving ||
            settings.minimum_age < 1 ||
            settings.minimum_age > 120 ||
            !Number.isInteger(settings.minimum_age)
          }
          className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-3 font-medium text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
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
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-300 px-5 py-3 font-medium text-slate-700 transition hover:bg-slate-50 disabled:opacity-50"
        >
          <RotateCcw size={17} />
          Reset Form
        </button>
      </div>

      <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
        <ShieldAlert className="mt-0.5 shrink-0" size={19} />
        <p>
          These preferences are saved to your account. Enforcement
          depends on the backend integration and the available website
          detection sources. A saved age setting alone does not verify
          a website's age restriction.
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
        <h3 className="text-sm font-medium text-slate-800">
          {title}
        </h3>
        <p className="mt-1 text-sm text-slate-500">
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
          checked ? "bg-blue-600" : "bg-slate-300"
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
