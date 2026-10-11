
import { useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  LockKeyhole,
  Plus,
  Trash2,
  Save,
  Info,
  CalendarDays,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";

type ProtectionSettings = {
  safeBrowsing: boolean;
  strictMode: boolean;
  ageRestriction: boolean;
  minimumAge: number;
};

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

  // Age restriction is ON by default.
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
    <div className="space-y-6">
      <div>
        <p className="text-sm font-medium text-cyan-300">
          DEFENSE CONFIGURATION
        </p>

        <h1 className="mt-1 text-3xl font-bold text-white">
          Protection Center
        </h1>

        <p className="mt-2 text-sm text-slate-400">
          Configure browsing preferences and manage domain lists.
        </p>
      </div>

      <div className="flex gap-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
        <Info size={20} className="mt-0.5 shrink-0 text-cyan-300" />

        <p className="text-sm leading-6 text-slate-300">
          Age restriction is enabled by default. These preferences and
          domain lists currently exist only in this page's state and do not
          yet enforce blocking in the backend.
        </p>
      </div>

      {message && (
        <div
          role="status"
          className="rounded-xl border border-slate-700 bg-slate-900 p-4 text-sm text-slate-200"
        >
          {message}
        </div>
      )}

      <section className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="flex items-center gap-3">
          <ShieldCheck size={22} className="text-emerald-300" />

          <div>
            <h2 className="font-semibold text-white">
              Browsing protection
            </h2>

            <p className="text-xs text-slate-400">
              Choose your preferred protection behavior.
            </p>
          </div>
        </div>

        <div className="divide-y divide-slate-800">
          <SettingToggle
            title="Safe browsing"
            description="Enable the safe-browsing preference."
            checked={settings.safeBrowsing}
            onChange={(value) => updateSetting("safeBrowsing", value)}
          />

          <SettingToggle
            title="Strict protection mode"
            description="Prefer caution when a URL's reputation is unknown."
            checked={settings.strictMode}
            onChange={(value) => updateSetting("strictMode", value)}
          />

          <SettingToggle
            title="Age restriction"
            description="Enable age-based protection for age-restricted websites."
            checked={settings.ageRestriction}
            onChange={(value) => updateSetting("ageRestriction", value)}
          />

          {settings.ageRestriction && (
            <div className="space-y-4 py-4">
              <div className="flex items-start gap-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
                <CalendarDays
                  size={21}
                  className="mt-0.5 shrink-0 text-cyan-300"
                />

                <div>
                  <h3 className="text-sm font-medium text-white">
                    Registered date of birth
                  </h3>

                  {user?.date_of_birth ? (
                    <>
                      <p className="mt-1 text-sm text-slate-300">
                        {user.date_of_birth}
                      </p>

                      <p className="mt-1 text-sm text-cyan-300">
                        Registered age:{" "}
                        {registeredAge !== null
                          ? `${registeredAge} years`
                          : "Unable to calculate"}
                      </p>
                    </>
                  ) : (
                    <p className="mt-1 text-sm text-amber-300">
                      Date of birth is unavailable. Update your account
                      details before using age-based checks.
                    </p>
                  )}

                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    Your age is derived from the DOB saved to your account.
                    This page does not ask you to enter an age manually.
                  </p>
                </div>
              </div>

              <div>
                <label
                  htmlFor="minimumAge"
                  className="block text-sm font-medium text-slate-200"
                >
                  Minimum age preference
                </label>

                <select
                  id="minimumAge"
                  value={settings.minimumAge}
                  onChange={(event) =>
                    updateSetting("minimumAge", Number(event.target.value))
                  }
                  className="mt-2 w-full max-w-xs rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white"
                >
                  <option value={13}>13+</option>
                  <option value={16}>16+</option>
                  <option value={18}>18+</option>
                  <option value={21}>21+</option>
                </select>

                <p className="mt-2 text-xs leading-5 text-slate-500">
                  This is a preference, not proof of a website's age
                  requirements. Actual access decisions must be enforced by
                  the backend using your registered DOB and applicable rules.
                </p>
              </div>
            </div>
          )}
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        <DomainList
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

      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="flex items-center gap-3">
          <LockKeyhole size={22} className="text-cyan-300" />

          <div>
            <h2 className="font-semibold text-white">
              Protection preferences
            </h2>

            <p className="text-xs text-slate-400">
              Apply your current selections to this page session.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={saveSettings}
          className="inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-5 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-400"
        >
          <Save size={17} />
          Save preferences
        </button>
      </div>
    </div>
  );
}

function SettingToggle({
  title,
  description,
  checked,
  onChange,
}: {
  title: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-4">
      <div>
        <h3 className="text-sm font-medium text-slate-200">{title}</h3>

        <p className="mt-1 text-xs leading-5 text-slate-400">
          {description}
        </p>
      </div>

      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={title}
        onClick={() => onChange(!checked)}
        className={`relative h-6 w-11 shrink-0 rounded-full transition ${
          checked ? "bg-cyan-500" : "bg-slate-700"
        }`}
      >
        <span
          className={`absolute top-1 h-4 w-4 rounded-full bg-white transition ${
            checked ? "left-6" : "left-1"
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
}: {
  title: string;
  description: string;
  type: "allow" | "block";
  value: string;
  setValue: (value: string) => void;
  domains: string[];
  onAdd: () => void;
  onRemove: (domain: string) => void;
}) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="flex items-center gap-3">
        {type === "allow" ? (
          <ShieldCheck size={22} className="text-emerald-300" />
        ) : (
          <ShieldAlert size={22} className="text-red-300" />
        )}

        <div>
          <h2 className="font-semibold text-white">{title}</h2>
          <p className="mt-1 text-xs text-slate-400">{description}</p>
        </div>
      </div>

      <form
        className="mt-5 flex gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          onAdd();
        }}
      >
        <input
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="example.com"
          aria-label={title}
          maxLength={2048}
          className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-950 px-3 py-3 text-sm text-white outline-none focus:border-cyan-500"
        />

        <button
          type="submit"
          aria-label={`Add to ${title}`}
          className="rounded-xl border border-slate-700 px-3 text-slate-200 hover:bg-slate-800"
        >
          <Plus size={19} />
        </button>
      </form>

      <div className="mt-4 space-y-2">
        {domains.length === 0 ? (
          <p className="rounded-xl border border-dashed border-slate-700 p-5 text-center text-sm text-slate-500">
            No domains added yet.
          </p>
        ) : (
          domains.map((domain) => (
            <div
              key={domain}
              className="flex items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-3"
            >
              <span className="break-all text-sm text-slate-200">
                {domain}
              </span>

              <button
                type="button"
                onClick={() => onRemove(domain)}
                aria-label={`Remove ${domain}`}
                className="shrink-0 rounded-lg p-2 text-slate-400 hover:bg-red-500/10 hover:text-red-300"
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
