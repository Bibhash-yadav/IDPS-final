
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Plus,
  Trash2,
  RefreshCw,
  Info,
  Globe,
  CheckCircle2,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import api from "../services/api";

type RuleType = "ALLOW" | "BLOCK";

type DomainRule = {
  id: number;
  domain: string;
  rule_type: RuleType;
  created_at: string | null;
};

type ProtectionProps = {
  items?: DomainRule[];
  rules?: DomainRule[];
};

function normalizeDomain(value: string): string {
  let domain = value.trim().toLowerCase();

  domain = domain.replace(/^https?:\/\//, "");
  domain = domain.split("/")[0].split("?")[0].split("#")[0];
  domain = domain.replace(/\.$/, "");

  return domain;
}

function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253 || domain.includes("..")) {
    return false;
  }

  const labels = domain.split(".");

  if (labels.length < 2) return false;

  return labels.every(
    (part) =>
      part.length > 0 &&
      part.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(part)
  );
}

function getErrorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "response" in error) {
    const response = (
      error as {
        response?: {
          data?: {
            detail?: string | Array<{ msg?: string }>;
          };
        };
      }
    ).response;

    const detail = response?.data?.detail;

    if (typeof detail === "string") return detail;

    if (Array.isArray(detail)) {
      return detail.map((item) => item.msg || "Validation error").join(", ");
    }
  }

  return "Something went wrong. Please try again.";
}

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

    return () => observer.disconnect();
  }, []);

  return isDark;
}

export default function Protection() {
  const isDark = useThemeMode();

  const [rules, setRules] = useState<DomainRule[]>([]);
  const [allowInput, setAllowInput] = useState("");
  const [blockInput, setBlockInput] = useState("");

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<RuleType | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const allowRules = useMemo(
    () => rules.filter((rule) => rule.rule_type === "ALLOW"),
    [rules]
  );

  const blockRules = useMemo(
    () => rules.filter((rule) => rule.rule_type === "BLOCK"),
    [rules]
  );

  // Load saved rules from the authenticated backend.
  const loadRules = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await api.get<
        DomainRule[] | ProtectionProps
      >("/api/protection/domains");

      const data = response.data;

      // Supports either a direct list or an object containing items/rules.
      const list = Array.isArray(data)
        ? data
        : data.items || data.rules || [];

      const validRules = list.filter(
        (rule): rule is DomainRule =>
          typeof rule.id === "number" &&
          typeof rule.domain === "string" &&
          (rule.rule_type === "ALLOW" || rule.rule_type === "BLOCK")
      );

      setRules(
        validRules.sort((a, b) =>
          a.domain.localeCompare(b.domain)
        )
      );
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadRules();
  }, [loadRules]);

  // Add a rule to PostgreSQL.
  async function addRule(type: RuleType) {
    const input = type === "ALLOW" ? allowInput : blockInput;
    const domain = normalizeDomain(input);

    if (!isValidDomain(domain)) {
      setError("Enter a valid domain, such as example.com.");
      setMessage("");
      return;
    }

    const duplicate = rules.some(
      (rule) =>
        rule.domain.toLowerCase() === domain &&
        rule.rule_type === type
    );

    if (duplicate) {
      setError(`${domain} is already in your ${type.toLowerCase()}list.`);
      return;
    }

    setSaving(type);
    setError("");
    setMessage("");

    try {
      const response = await api.post<DomainRule>(
        "/api/protection/domains",
        {
          domain,
          rule_type: type,
        }
      );

      // Use the actual record returned by the backend.
      setRules((current) => {
        const withoutDuplicate = current.filter(
          (item) => item.id !== response.data.id
        );

        return [...withoutDuplicate, response.data].sort((a, b) =>
          a.domain.localeCompare(b.domain)
        );
      });

      if (type === "ALLOW") {
        setAllowInput("");
      } else {
        setBlockInput("");
      }

      setMessage(
        `${response.data.domain} successfully added to the ${type.toLowerCase()}list.`
      );
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setSaving(null);
    }
  }

  // Delete the rule from PostgreSQL.
  async function removeRule(rule: DomainRule) {
    const confirmed = window.confirm(
      `Remove ${rule.domain} from the ${rule.rule_type.toLowerCase()}list?`
    );

    if (!confirmed) return;

    setDeletingId(rule.id);
    setError("");
    setMessage("");

    try {
      await api.delete(`/api/protection/domains/${rule.id}`);

      setRules((current) =>
        current.filter((item) => item.id !== rule.id)
      );

      setMessage(`${rule.domain} was successfully removed.`);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setDeletingId(null);
    }
  }

  const headingClass = isDark ? "text-white" : "text-slate-900";
  const secondaryClass = isDark ? "text-slate-400" : "text-slate-500";

  const glassClass = isDark
    ? "border border-white/10 bg-white/[0.055] shadow-[0_12px_40px_rgba(0,0,0,0.18)]"
    : "border border-white/80 bg-white/75 shadow-[0_12px_40px_rgba(31,41,55,0.07)]";

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

        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className={`text-3xl font-bold tracking-tight ${headingClass}`}>
              Protection Center
            </h1>

            <p className={`mt-2 text-sm ${secondaryClass}`}>
              Manage your saved allowed and blocked websites.
            </p>
          </div>

          <button
            type="button"
            onClick={() => void loadRules()}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-xl border border-cyan-500/30 px-4 py-2.5 text-sm font-semibold text-cyan-500 transition hover:bg-cyan-500/10 disabled:opacity-50"
          >
            <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {/* Backend information */}
      <div className={`flex items-start gap-3 rounded-[22px] p-4 sm:p-5 backdrop-blur-2xl ${glassClass}`}>
        <div className="shrink-0 rounded-xl bg-cyan-500/10 p-2.5 text-cyan-500">
          <Info size={21} />
        </div>

        <div>
          <h3 className={`text-sm font-semibold ${headingClass}`}>
            Live database synchronization
          </h3>

          <p className={`mt-1 text-sm leading-6 ${secondaryClass}`}>
            Domain rules are loaded from your FastAPI backend and saved in
            PostgreSQL. Changes are reflected here immediately.
          </p>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div
          role="alert"
          className="flex items-start gap-3 rounded-2xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-500"
        >
          <AlertTriangle size={18} className="mt-0.5 shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {/* Success */}
      {message && (
        <div
          role="status"
          className="flex items-start gap-3 rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-sm text-emerald-500"
        >
          <CheckCircle2 size={18} className="mt-0.5 shrink-0" />
          <p>{message}</p>
        </div>
      )}

      {/* Statistics */}
      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard
          title="Total rules"
          count={rules.length}
          icon={<Globe size={21} />}
          isDark={isDark}
        />

        <StatCard
          title="Allowed websites"
          count={allowRules.length}
          icon={<ShieldCheck size={21} />}
          isDark={isDark}
          color="emerald"
        />

        <StatCard
          title="Blocked websites"
          count={blockRules.length}
          icon={<ShieldAlert size={21} />}
          isDark={isDark}
          color="red"
        />
      </div>

      {/* Domain lists */}
      <div className="grid gap-5 xl:grid-cols-2">
        <DomainList
          title="Allowed websites"
          description="Websites with your saved ALLOW rules."
          type="ALLOW"
          value={allowInput}
          setValue={setAllowInput}
          domains={allowRules}
          onAdd={() => void addRule("ALLOW")}
          onRemove={removeRule}
          loading={loading}
          saving={saving === "ALLOW"}
          deletingId={deletingId}
          isDark={isDark}
        />

        <DomainList
          title="Blocked websites"
          description="Websites with your saved BLOCK rules."
          type="BLOCK"
          value={blockInput}
          setValue={setBlockInput}
          domains={blockRules}
          onAdd={() => void addRule("BLOCK")}
          onRemove={removeRule}
          loading={loading}
          saving={saving === "BLOCK"}
          deletingId={deletingId}
          isDark={isDark}
        />
      </div>

      <div className={`flex items-start gap-3 rounded-2xl border p-4 ${
        isDark
          ? "border-amber-400/15 bg-amber-400/[0.05]"
          : "border-amber-200 bg-amber-50"
      }`}>
        <Info size={18} className="mt-0.5 shrink-0 text-amber-500" />

        <p className={`text-xs leading-5 ${
          isDark ? "text-slate-400" : "text-amber-800"
        }`}>
          These lists display saved domain rules. URL analysis decisions such
          as malware, phishing, or risk-based BLOCK/WARN results are separate
          security events and are not automatically added to these manual
          domain lists.
        </p>
      </div>
    </div>
  );
}

function StatCard({
  title,
  count,
  icon,
  isDark,
  color = "cyan",
}: {
  title: string;
  count: number;
  icon: React.ReactNode;
  isDark: boolean;
  color?: "cyan" | "emerald" | "red";
}) {
  const colorClass = {
    cyan: "bg-cyan-500/10 text-cyan-500",
    emerald: "bg-emerald-500/10 text-emerald-500",
    red: "bg-red-500/10 text-red-500",
  }[color];

  return (
    <div className={`rounded-[22px] border p-5 ${
      isDark
        ? "border-white/10 bg-white/[0.055]"
        : "border-slate-200 bg-white/80"
    }`}>
      <div className="flex items-center justify-between">
        <span className={`text-sm ${isDark ? "text-slate-400" : "text-slate-500"}`}>
          {title}
        </span>

        <div className={`rounded-xl p-2.5 ${colorClass}`}>
          {icon}
        </div>
      </div>

      <p className={`mt-3 text-3xl font-bold ${isDark ? "text-white" : "text-slate-900"}`}>
        {count}
      </p>
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
  loading,
  saving,
  deletingId,
  isDark,
}: {
  title: string;
  description: string;
  type: RuleType;
  value: string;
  setValue: (value: string) => void;
  domains: DomainRule[];
  onAdd: () => void;
  onRemove: (rule: DomainRule) => void;
  loading: boolean;
  saving: boolean;
  deletingId: number | null;
  isDark: boolean;
}) {
  const isAllow = type === "ALLOW";

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
          isAllow
            ? "bg-emerald-500/10 text-emerald-500"
            : "bg-red-500/10 text-red-500"
        }`}>
          {isAllow ? <ShieldCheck size={22} /> : <ShieldAlert size={22} />}
        </div>

        <div className="min-w-0">
          <h2 className={`font-semibold ${isDark ? "text-white" : "text-slate-900"}`}>
            {title}
          </h2>

          <p className={`mt-1 text-xs leading-5 ${isDark ? "text-slate-400" : "text-slate-500"}`}>
            {description}
          </p>
        </div>

        <span className={`ml-auto rounded-full px-3 py-1 text-xs font-bold ${
          isAllow
            ? "bg-emerald-500/10 text-emerald-500"
            : "bg-red-500/10 text-red-500"
        }`}>
          {domains.length}
        </span>
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
          disabled={saving || !value.trim()}
          aria-label={`Add to ${title}`}
          className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 text-white shadow-lg shadow-cyan-500/15 transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {saving ? <Loader2 size={18} className="animate-spin" /> : <Plus size={19} />}
        </button>
      </form>

      <div className="mt-4 space-y-2">
        {loading ? (
          <div className={`flex items-center justify-center gap-2 rounded-xl border border-dashed p-8 text-sm ${
            isDark ? "border-white/10 text-slate-400" : "border-slate-300 text-slate-500"
          }`}>
            <Loader2 size={18} className="animate-spin" />
            Loading saved websites...
          </div>
        ) : domains.length === 0 ? (
          <div className={`rounded-xl border border-dashed p-8 text-center ${
            isDark
              ? "border-white/10 text-slate-500"
              : "border-slate-300 text-slate-400"
          }`}>
            <Globe size={22} className="mx-auto mb-2 opacity-60" />
            <p className="text-sm">No {isAllow ? "allowed" : "blocked"} websites yet.</p>
          </div>
        ) : (
          domains.map((rule, index) => (
            <div
              key={rule.id}
              className={`flex items-center justify-between gap-3 rounded-xl border px-3 py-3 ${
                isDark
                  ? "border-white/[0.08] bg-slate-950/30"
                  : "border-slate-200 bg-white/60"
              }`}
            >
              <div className="flex min-w-0 items-start gap-3">
                <span className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg text-xs font-bold ${
                  isAllow
                    ? "bg-emerald-500/10 text-emerald-500"
                    : "bg-red-500/10 text-red-500"
                }`}>
                  {index + 1}
                </span>

                <p className={`min-w-0 break-all pt-0.5 text-sm font-medium ${
                  isDark ? "text-slate-200" : "text-slate-700"
                }`}>
                  {rule.domain}
                </p>
              </div>

              <button
                type="button"
                disabled={deletingId === rule.id}
                onClick={() => onRemove(rule)}
                aria-label={`Remove ${rule.domain}`}
                className="shrink-0 rounded-lg p-2 text-slate-400 transition hover:bg-red-500/10 hover:text-red-500 disabled:opacity-50"
              >
                {deletingId === rule.id ? (
                  <Loader2 size={16} className="animate-spin" />
                ) : (
                  <Trash2 size={16} />
                )}
              </button>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
