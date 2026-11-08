
import { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  LockKeyhole,
  Plus,
  Trash2,
  Save,
  Info,
  CalendarDays,
  Globe,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

type ProtectionSettings = {
  safeBrowsing: boolean;
  strictMode: boolean;
  ageRestriction: boolean;
  minimumAge: number;
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

function calculateAge(
  dateOfBirth: string | null | undefined
): number | null {
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

  if (dob > today || year < 1900) return null;

  let age = today.getFullYear() - year;

  if (
    today.getMonth() < month - 1 ||
    (today.getMonth() === month - 1 && today.getDate() < day)
  ) {
    age--;
  }

  return age >= 0 && age <= 120 ? age : null;
}

function normalizeDomain(value: string): string {
  let domain = value.trim().toLowerCase();

  domain = domain.replace(/^https?:\/\//, "");
  domain = domain.split("/")[0].split("?")[0].split("#")[0];
  domain = domain.replace(/\.$/, "");

  return domain;
}

function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  if (domain.includes("..")) return false;
  if (domain.includes(":") || domain.includes("@")) return false;

  const labels = domain.split(".");

  if (labels.length < 2) return false;

  return labels.every(
    (part) =>
      part.length > 0 &&
      part.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(part)
  );
}

export default function Protection() {
  const { user } = useAuth();
  const isDark = useThemeMode();

  const [settings, setSettings] = useState<ProtectionSettings>({
    safeBrowsing: true,
    strictMode: true,
    ageRestriction: true,
    minimumAge: 18,
  });

  const [allowDomain, setAllowDomain] = useState("");
  const [blockDomain, setBlockDomain] = useState("");
  const [allowedDomains, setAllowedDomains] = useState<string[]>([]);
  const [blockedDomains, setBlockedDomains] = useState<string[]>([]);
  const [message, setMessage] = useState("");

  const registeredAge =
    calculateAge(user?.date_of_birth) ??
    (typeof user?.age === "number" &&
    Number.isInteger(user.age) &&
    user.age >= 0 &&
    user.age <= 120
      ? user.age
      : null);

  const headingClass = isDark ? "text-white" : "text-slate-900";
  const secondaryClass = isDark ? "text-slate-400" : "text-slate-500";

  const glassClass = isDark
    ? "border border-white/10 bg-white/[0.055] shadow-[0_12px_40px_rgba(0,0,0,0.18)]"
    : "border border-white/80 bg-white/75 shadow-[0_12px_40px_rgba(31,41,55,0.07)]";

  const inputClass = isDark
    ? "border-white/10 bg-slate-950/50 text-white placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10"
    : "border-slate-200 bg-white/80 text-slate-900 placeholder:text-slate-400 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/10";

  function addDomain(value: string, type: "allow" | "block") {
    const domain = normalizeDomain(value);

    if (!isValidDomain(domain)) {
      setMessage("Enter a valid domain, such as example.com.");
      return;
    }

    if (type === "allow") {
      if (allowedDomains.includes(domain)) {
        setMessage("This domain is already in the allowlist.");
        return;
      }

      setAllowedDomains((current) => [...current, domain]);
      setAllowDomain("");
    } else {
      if (blockedDomains.includes(domain)) {
        setMessage("This domain is already in the blocklist.");
        return;
      }

      setBlockedDomains((current) => [...current, domain]);
      setBlockDomain("");
    }

    setMessage(
      `${domain} added to the ${
        type === "allow" ? "allowlist" : "blocklist"
      } for this page session.`
    );
  }

  function updateSetting<K extends keyof ProtectionSettings>(
    key: K,
    value: ProtectionSettings[K]
  ) {
    setSettings((current) => ({ ...current, [key]: value }));
    setMessage("");
  }

  function saveSettings() {
    setMessage(
      "Preferences updated for this page session. Permanent saving and backend enforcement are not connected yet."
    );
  }

  return (
    <div className="mx-auto w-full max-w-6xl space-y-7 pb-8">
      {/* Header */}
      <div>
        <div className="mb-2 flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.8)]" />
          <p className="text-xs font-bold tracking-[0.2em] text-cyan-500">
            DEFENSE CONFIGURATION
          </p>
        </div>

        <h1 className={`text-3xl font-bold tracking-tight ${headingClass}`}>
          Protection Center
        </h1>

        <p className={`mt-2 text-sm ${secondaryClass}`}>
          Configure browsing preferences and manage domain protection lists.
        </p>
      </div>

      {/* Information banner */}
      <div className={`flex items-start gap-3 rounded-[22px] p-4 sm:p-5 backdrop-blur-2xl ${glassClass}`}>
        <div className="shrink-0 rounded-xl bg-cyan-500/10 p-2.5 text-cyan-500">
          <Info size={21} />
        </div>

        <div>
          <h3 className={`text-sm font-semibold ${headingClass}`}>
            Protection configuration
          </h3>

          <p className={`mt-1 text-sm leading-6 ${secondaryClass}`}>
            Age restriction is enabled by default. These preferences and
            domain lists currently exist only in this page's state and do not
            yet enforce blocking in the backend.
          </p>
        </div>
      </div>

      {/* Status message */}
      {message && (
        <div
          role="status"
          className={`flex items-start gap-3 rounded-2xl border p-4 text-sm ${
            isDark
              ? "border-cyan-400/20 bg-cyan-400/[0.07] text-cyan-200"
              : "border-cyan-200 bg-cyan-50 text-cyan-800"
          }`}
        >
          <CheckCircle2 size={18} className="mt-0.5 shrink-0" />
          <p>{message}</p>
        </div>
      )}

      {/* Browsing protection */}
      <section className={`rounded-[26px] p-5 backdrop-blur-2xl sm:p-6 ${glassClass}`}>
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-emerald-500/10 p-3 text-emerald-500">
            <ShieldCheck size={23} />
          </div>

          <div>
            <h2 className={`font-semibold ${headingClass}`}>
              Browsing Protection
            </h2>
            <p className={`mt-1 text-xs ${secondaryClass}`}>
              Choose your preferred protection behavior.
            </p>
          </div>
        </div>

        <div className={`mt-5 divide-y ${isDark ? "divide-white/[0.08]" : "divide-slate-200"}`}>
          <SettingToggle
            isDark={isDark}
            title="Safe browsing"
            description="Enable the safe-browsing preference."
            checked={settings.safeBrowsing}
            onChange={(value) => updateSetting("safeBrowsing", value)}
          />

          <SettingToggle
            isDark={isDark}
            title="Strict protection mode"
            description="Prefer caution when a URL's reputation is unknown."
            checked={settings.strictMode}
            onChange={(value) => updateSetting("strictMode", value)}
          />

          <SettingToggle
            isDark={isDark}
            title="Age restriction"
            description="Enable age-based protection for age-restricted websites."
            checked={settings.ageRestriction}
            onChange={(value) => updateSetting("ageRestriction", value)}
          />

          {settings.ageRestriction && (
            <div className="space-y-5 py-5">
              {/* Registered DOB */}
              <div className={`flex items-start gap-3 rounded-2xl border p-4 ${
                isDark
                  ? "border-cyan-400/20 bg-cyan-400/[0.06]"
                  : "border-cyan-200 bg-cyan-50/70"
              }`}>
                <div className="shrink-0 rounded-xl bg-cyan-500/10 p-2.5 text-cyan-500">
                  <CalendarDays size={21} />
                </div>

                <div className="min-w-0">
                  <h3 className={`text-sm font-semibold ${headingClass}`}>
                    Registered date of birth
                  </h3>

                  {user?.date_of_birth ? (
                    <>
                      <p className={`mt-1 text-sm ${secondaryClass}`}>
                        {user.date_of_birth}
                      </p>

                      <p className="mt-1 text-sm font-semibold text-cyan-500">
                        Registered age:{" "}
                        {registeredAge !== null
                          ? `${registeredAge} years`
                          : "Unable to calculate"}
                      </p>
                    </>
                  ) : (
                    <p className="mt-1 text-sm text-amber-500">
                      Date of birth is unavailable. Update your account
                      details before using age-based checks.
                    </p>
                  )}

                  <p className={`mt-2 text-xs leading-5 ${secondaryClass}`}>
                    Your age is derived from the DOB saved to your account.
                    This page does not ask you to enter an age manually.
                  </p>
                </div>
              </div>

              {/* Minimum age */}
              <div>
                <label
                  htmlFor="minimumAge"
                  className={`block text-sm font-semibold ${headingClass}`}
                >
                  Minimum age preference
                </label>

                <select
                  id="minimumAge"
                  value={settings.minimumAge}
                  onChange={(event) =>
                    updateSetting("minimumAge", Number(event.target.value))
                  }
                  className={`mt-2 w-full max-w-xs rounded-xl border px-4 py-3 text-sm outline-none transition ${inputClass}`}
                >
                  <option value={13}>13+</option>
                  <option value={16}>16+</option>
                  <option value={18}>18+</option>
                  <option value={21}>21+</option>
                </select>

                <p className={`mt-2 max-w-2xl text-xs leading-5 ${secondaryClass}`}>
                  This is a preference, not proof of a website's age
                  requirements. Actual access decisions must be enforced by
                  the backend using your registered DOB and applicable rules.
                </p>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Domain lists */}
      <div className="grid gap-5 xl:grid-cols-2">
        <DomainList
          isDark={isDark}
          title="Allowed domains"
          description="Domains you want to add to your local allowlist."
          type="allow"
          value={allowDomain}
          setValue={setAllowDomain}
          domains={allowedDomains}
          onAdd={() => addDomain(allowDomain, "allow")}
          onRemove={(domain) =>
            setAllowedDomains((current) =>
              current.filter((item) => item !== domain)
            )
          }
        />

        <DomainList
          isDark={isDark}
          title="Blocked domains"
          description="Domains you want to add to your local blocklist."
          type="block"
          value={blockDomain}
          setValue={setBlockDomain}
          domains={blockedDomains}
          onAdd={() => addDomain(blockDomain, "block")}
          onRemove={(domain) =>
            setBlockedDomains((current) =>
              current.filter((item) => item !== domain)
            )
          }
        />
      </div>

      {/* Save preferences */}
      <section className={`flex flex-wrap items-center justify-between gap-4 rounded-[24px] p-5 backdrop-blur-2xl sm:p-6 ${glassClass}`}>
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-cyan-500/10 p-3 text-cyan-500">
            <LockKeyhole size={22} />
          </div>

          <div>
            <h2 className={`font-semibold ${headingClass}`}>
              Protection preferences
            </h2>
            <p className={`mt-1 text-xs ${secondaryClass}`}>
              Apply your current selections to this page session.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={saveSettings}
          className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition hover:-translate-y-0.5 hover:shadow-xl hover:shadow-cyan-500/25"
        >
          <Save size={17} />
          Save preferences
        </button>
      </section>

      {/* Backend status note */}
      <div className={`flex items-start gap-3 rounded-2xl border p-4 ${
        isDark
          ? "border-amber-400/15 bg-amber-400/[0.05]"
          : "border-amber-200 bg-amber-50"
      }`}>
        <AlertTriangle size={18} className="mt-0.5 shrink-0 text-amber-500" />
        <p className={`text-xs leading-5 ${
          isDark ? "text-slate-400" : "text-amber-800"
        }`}>
          These settings are currently frontend preferences only. Saving
          them does not persist them to the database or enforce URL blocking
          on the FastAPI backend.
        </p>
      </div>
    </div>
  );
}

function SettingToggle({
  title,
  description,
  checked,
  onChange,
  isDark,
}: {
  title: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  isDark: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-4">
      <div className="min-w-0">
        <h3 className={`text-sm font-semibold ${isDark ? "text-slate-200" : "text-slate-800"}`}>
          {title}
        </h3>

        <p className={`mt-1 text-xs leading-5 ${isDark ? "text-slate-400" : "text-slate-500"}`}>
          {description}
        </p>
      </div>

      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={title}
        onClick={() => onChange(!checked)}
        className={`relative h-7 w-12 shrink-0 rounded-full transition-all duration-300 ${
          checked
            ? "bg-cyan-500 shadow-lg shadow-cyan-500/20"
            : isDark
              ? "bg-slate-700"
              : "bg-slate-300"
        }`}
      >
        <span
          className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow-sm transition-all duration-300 ${
            checked ? "left-[26px]" : "left-1"
          }`}
        />
      </button>
    </div>
  );
}

function DomainList({
  title,
  description,
  type,
  value,
  setValue,
  domains,
  onAdd,
  onRemove,
  isDark,
}: {
  title: string;
  description: string;
  type: "allow" | "block";
  value: string;
  setValue: (value: string) => void;
  domains: string[];
  onAdd: () => void;
  onRemove: (domain: string) => void;
  isDark: boolean;
}) {
  const inputClass = isDark
    ? "border-white/10 bg-slate-950/50 text-white placeholder:text-slate-500 focus:border-cyan-400/60"
    : "border-slate-200 bg-white/80 text-slate-900 placeholder:text-slate-400 focus:border-cyan-500";

  return (
    <section className={`min-w-0 rounded-[24px] p-5 backdrop-blur-2xl sm:p-6 ${
      isDark
        ? "border border-white/10 bg-white/[0.055] shadow-[0_12px_40px_rgba(0,0,0,0.18)]"
        : "border border-white/80 bg-white/75 shadow-[0_12px_40px_rgba(31,41,55,0.07)]"
    }`}>
      <div className="flex items-center gap-3">
        <div className={`rounded-xl p-3 ${
          type === "allow"
            ? "bg-emerald-500/10 text-emerald-500"
            : "bg-red-500/10 text-red-500"
        }`}>
          {type === "allow" ? (
            <ShieldCheck size={22} />
          ) : (
            <ShieldAlert size={22} />
          )}
        </div>

        <div className="min-w-0">
          <h2 className={`font-semibold ${isDark ? "text-white" : "text-slate-900"}`}>
            {title}
          </h2>
          <p className={`mt-1 text-xs leading-5 ${isDark ? "text-slate-400" : "text-slate-500"}`}>
            {description}
          </p>
        </div>
      </div>

      <form
        className="mt-5 flex gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          onAdd();
        }}
      >
        <div className="relative min-w-0 flex-1">
          <Globe
            size={17}
            className={`absolute left-3.5 top-1/2 -translate-y-1/2 ${
              isDark ? "text-slate-500" : "text-slate-400"
            }`}
          />

          <input
            value={value}
            onChange={(event) => setValue(event.target.value)}
            placeholder="example.com"
            aria-label={title}
            maxLength={2048}
            className={`w-full rounded-xl border py-3 pl-10 pr-3 text-sm outline-none transition-all focus:ring-2 focus:ring-cyan-500/10 ${inputClass}`}
          />
        </div>

        <button
          type="submit"
          aria-label={`Add to ${title}`}
          className="shrink-0 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 text-white shadow-lg shadow-cyan-500/15 transition hover:-translate-y-0.5"
        >
          <Plus size={19} />
        </button>
      </form>

      <div className="mt-4 space-y-2">
        {domains.length === 0 ? (
          <div className={`rounded-xl border border-dashed p-6 text-center ${
            isDark
              ? "border-white/10 text-slate-500"
              : "border-slate-300 text-slate-400"
          }`}>
            <Globe size={22} className="mx-auto mb-2 opacity-60" />
            <p className="text-sm">No domains added yet.</p>
          </div>
        ) : (
          domains.map((domain) => (
            <div
              key={domain}
              className={`flex items-center justify-between gap-3 rounded-xl border px-3 py-3 ${
                isDark
                  ? "border-white/[0.08] bg-slate-950/30"
                  : "border-slate-200 bg-white/60"
              }`}
            >
              <span className={`break-all text-sm ${
                isDark ? "text-slate-200" : "text-slate-700"
              }`}>
                {domain}
              </span>

              <button
                type="button"
                onClick={() => onRemove(domain)}
                aria-label={`Remove ${domain}`}
                className="shrink-0 rounded-lg p-2 text-slate-400 transition hover:bg-red-500/10 hover:text-red-500"
              >
                <Trash2 size={16} />
              </button>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
