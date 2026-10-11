import { useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  Bot,
  CheckCircle2,
  Clock3,
  Fingerprint,
  Globe,
  Info,
  LockKeyhole,
  MessageSquare,
  ScanSearch,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Trash2,
  Wifi,
  XCircle,
} from "lucide-react";

import api from "../services/api";
import { useAuth } from "../context/AuthContext";

type URLCheckResult = {
  check_id?: number;
  url: string;
  domain?: string;
  risk_score: number;
  risk_level: string;
  decision: string;
  reasons?: string[];
  recommendation?: string;
  analysis_method?: string;
  domain_reputation?: string;
  https_enabled?: boolean;
  ssl_status?: string;
  safe_browsing_enabled?: boolean;
  strict_mode_enabled?: boolean;
  user_age?: number;
  age_decision?: string;
  required_age?: number;
  malware?: {
    malware_detected?: boolean;
    detected?: boolean;
    reason?: string;
    findings?: string[];
  };
  phishing?: {
    phishing_detected?: boolean;
    detected?: boolean;
    reason?: string;
    findings?: string[];
  };
  url_analysis?: {
    findings?: string[];
    risk_contribution?: number;
    https_enabled?: boolean;
  };
  detection_status?: Record<string, string>;
};

type Message = {
  id: string;
  role: "assistant" | "user";
  text: string;
  result?: URLCheckResult;
  timestamp: string;
};

const QUICK_ACTIONS = [
  {
    title: "Analyze a website",
    description: "Check a URL for risk indicators",
    prompt: "https://example.com",
    icon: ScanSearch,
  },
  {
    title: "Explain phishing",
    description: "Understand common phishing signs",
    prompt: "Explain how to identify a phishing website.",
    icon: Fingerprint,
  },
  {
    title: "HTTPS security",
    description: "Understand encryption and trust",
    prompt: "What does HTTPS protect me from?",
    icon: LockKeyhole,
  },
];

function calculateAge(
  dateOfBirth: string | null | undefined
): number | null {
  if (!dateOfBirth) return null;

  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(
    dateOfBirth
  );

  if (!match) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);

  const dob = new Date(year, month - 1, day);

  // Reject invalid dates such as 2020-02-31.
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
    (today.getMonth() === month - 1 &&
      today.getDate() < day)
  ) {
    age--;
  }

  return age >= 0 && age <= 120 ? age : null;
}

function formatTime(value: string) {
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function decisionOf(result: URLCheckResult) {
  const decision = (result.decision || "").toUpperCase();

  if (["ALLOW", "ALLOWED"].includes(decision)) {
    return "ALLOW";
  }

  if (["BLOCK", "BLOCKED"].includes(decision)) {
    return "BLOCK";
  }

  if (["WARN", "WARNING"].includes(decision)) {
    return "WARN";
  }

  return "UNKNOWN";
}

function getDecisionPresentation(decision: string) {
  if (decision === "ALLOW") {
    return {
      label: "No blocking indicators found",
      shortLabel: "ALLOW",
      description:
        "The configured checks did not identify a blocking condition. This is not a guarantee that the website is safe.",
      color: "text-emerald-300",
      border: "border-emerald-500/25",
      surface: "bg-emerald-500/10",
      Icon: ShieldCheck,
    };
  }

  if (decision === "BLOCK") {
    return {
      label: "Access not recommended",
      shortLabel: "BLOCK",
      description:
        "A security detection or policy indicates that this URL should not be opened.",
      color: "text-red-300",
      border: "border-red-500/25",
      surface: "bg-red-500/10",
      Icon: ShieldX,
    };
  }

  if (decision === "WARN") {
    return {
      label: "Caution advised",
      shortLabel: "WARN",
      description:
        "The configured checks recommend caution. Review the findings before continuing.",
      color: "text-amber-300",
      border: "border-amber-500/25",
      surface: "bg-amber-500/10",
      Icon: ShieldAlert,
    };
  }

  return {
    label: "Decision unavailable",
    shortLabel: "UNKNOWN",
    description:
      "The server returned an unrecognized decision. Review the API response.",
    color: "text-slate-300",
    border: "border-slate-700",
    surface: "bg-slate-800/50",
    Icon: Info,
  };
}

function getRiskPresentation(level: string) {
  switch ((level || "").toUpperCase()) {
    case "CRITICAL":
      return {
        color: "text-red-300",
        bar: "bg-red-500",
      };

    case "HIGH":
      return {
        color: "text-orange-300",
        bar: "bg-orange-500",
      };

    case "MEDIUM":
      return {
        color: "text-amber-300",
        bar: "bg-amber-500",
      };

    case "LOW":
      return {
        color: "text-emerald-300",
        bar: "bg-emerald-500",
      };

    default:
      return {
        color: "text-slate-300",
        bar: "bg-slate-500",
      };
  }
}

function normalizeURLInput(value: string) {
  const trimmed = value.trim();

  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }

  return `https://${trimmed}`;
}

function isURLInput(value: string) {
  const trimmed = value.trim();

  if (!trimmed || /\s/.test(trimmed)) return false;

  try {
    const normalized = normalizeURLInput(trimmed);
    const parsed = new URL(normalized);

    return (
      ["http:", "https:"].includes(parsed.protocol) &&
      Boolean(parsed.hostname.includes(".") ||
        parsed.hostname === "localhost" ||
        /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname) ||
        parsed.hostname.startsWith("["))
    );
  } catch {
    return false;
  }
}

function uniqueReasons(reasons?: string[]) {
  if (!Array.isArray(reasons)) return [];

  return Array.from(
    new Set(
      reasons.filter(
        (reason) =>
          typeof reason === "string" &&
          reason.trim().length > 0
      )
    )
  );
}

function ResultCard({
  result,
}: {
  result: URLCheckResult;
}) {
  const decision = decisionOf(result);
  const presentation = getDecisionPresentation(decision);
  const risk = getRiskPresentation(result.risk_level);
  const DecisionIcon = presentation.Icon;

  const score = Math.max(
    0,
    Math.min(100, Number(result.risk_score) || 0)
  );

  const reasons = uniqueReasons(result.reasons);

  const httpsEnabled =
    result.https_enabled ??
    result.url_analysis?.https_enabled ??
    false;

  const malwareDetected = Boolean(
    result.malware?.malware_detected ??
    result.malware?.detected
  );

  const phishingDetected = Boolean(
    result.phishing?.phishing_detected ??
    result.phishing?.detected
  );

  return (
    <div className="mt-4 space-y-4">
      <div
        className={`overflow-hidden rounded-2xl border ${presentation.border} bg-slate-950/80`}
      >
        <div
          className={`flex items-start gap-3 p-4 ${presentation.surface}`}
        >
          <div
            className={`rounded-xl border ${presentation.border} bg-slate-950/50 p-3 ${presentation.color}`}
          >
            <DecisionIcon size={25} />
          </div>

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <p
                className={`font-semibold ${presentation.color}`}
              >
                {presentation.label}
              </p>

              <span
                className={`rounded-md border ${presentation.border} px-2 py-0.5 text-[10px] font-bold tracking-wider ${presentation.color}`}
              >
                {presentation.shortLabel}
              </span>
            </div>

            <p className="mt-1 break-all text-sm text-slate-300">
              {result.domain || result.url}
            </p>

            <p className="mt-2 text-xs leading-5 text-slate-400">
              {result.recommendation ||
                presentation.description}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-px border-t border-slate-800 bg-slate-800 sm:grid-cols-4">
          <div className="bg-slate-950/90 p-3">
            <p className="text-[11px] text-slate-500">
              Risk score
            </p>

            <p className={`mt-1 text-xl font-bold ${risk.color}`}>
              {score}
              <span className="text-xs font-normal text-slate-500">
                {" "}/ 100
              </span>
            </p>

            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-800">
              <div
                className={`h-full rounded-full ${risk.bar}`}
                style={{ width: `${score}%` }}
              />
            </div>
          </div>

          <div className="bg-slate-950/90 p-3">
            <p className="text-[11px] text-slate-500">
              Risk level
            </p>

            <p className={`mt-2 text-sm font-semibold ${risk.color}`}>
              {result.risk_level || "UNKNOWN"}
            </p>
          </div>

          <div className="bg-slate-950/90 p-3">
            <p className="text-[11px] text-slate-500">HTTPS</p>

            <p
              className={`mt-2 flex items-center gap-1.5 text-sm font-semibold ${
                httpsEnabled
                  ? "text-emerald-300"
                  : "text-amber-300"
              }`}
            >
              {httpsEnabled ? (
                <LockKeyhole size={14} />
              ) : (
                <AlertTriangle size={14} />
              )}

              {httpsEnabled ? "Enabled" : "Not enabled"}
            </p>
          </div>

          <div className="bg-slate-950/90 p-3">
            <p className="text-[11px] text-slate-500">SSL/TLS</p>

            <p className="mt-2 text-sm font-semibold text-slate-300">
              {result.ssl_status || "Not checked"}
            </p>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
        <div className="flex items-center gap-2">
          <Activity size={16} className="text-cyan-300" />

          <h4 className="text-sm font-semibold text-white">
            Detection summary
          </h4>
        </div>

        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <DetectionItem
            title="Malware"
            detected={malwareDetected}
            positiveText="Detection reported"
            negativeText="No local list match"
          />

          <DetectionItem
            title="Phishing"
            detected={phishingDetected}
            positiveText="Detection reported"
            negativeText="No local rule triggered"
          />

          <div className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/70 p-3">
            <Globe size={18} className="shrink-0 text-cyan-300" />

            <div>
              <p className="text-xs font-medium text-slate-200">
                Domain reputation
              </p>

              <p className="mt-0.5 text-xs text-slate-500">
                {result.domain_reputation || "UNKNOWN"}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/70 p-3">
            <Fingerprint
              size={18}
              className="shrink-0 text-cyan-300"
            />

            <div>
              <p className="text-xs font-medium text-slate-200">
                Analysis method
              </p>

              <p className="mt-0.5 text-xs text-slate-500">
                {result.analysis_method || "Local heuristics"}
              </p>
            </div>
          </div>
        </div>

        {result.age_decision && (
          <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/70 p-3">
            <p className="text-xs font-medium text-slate-200">
              Age policy result
            </p>

            <p className="mt-1 text-sm text-slate-300">
              {result.age_decision}
              {typeof result.required_age === "number"
                ? ` · Required age: ${result.required_age}+`
                : ""}
            </p>
          </div>
        )}

        <div className="mt-4 border-t border-slate-800 pt-4">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Findings and explanations
          </p>

          {reasons.length > 0 ? (
            <ul className="mt-3 space-y-2">
              {reasons.map((reason, index) => (
                <li
                  key={`${index}-${reason}`}
                  className="flex gap-2 text-sm leading-5 text-slate-300"
                >
                  <span className="mt-0.5 text-cyan-400">•</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-sm text-slate-500">
              No specific detection reasons were returned.
            </p>
          )}
        </div>

        <p className="mt-4 flex items-start gap-2 text-xs leading-5 text-slate-500">
          <Info size={15} className="mt-0.5 shrink-0" />

          HTTPS encrypts the connection but does not establish
          that a website is trustworthy. Detection results depend
          on the checks configured on your backend.
        </p>
      </div>
    </div>
  );
}

function DetectionItem({
  title,
  detected,
  positiveText,
  negativeText,
}: {
  title: string;
  detected: boolean;
  positiveText: string;
  negativeText: string;
}) {
  return (
    <div className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/70 p-3">
      {detected ? (
        <XCircle size={18} className="shrink-0 text-red-400" />
      ) : (
        <CheckCircle2
          size={18}
          className="shrink-0 text-emerald-400"
        />
      )}

      <div>
        <p className="text-xs font-medium text-slate-200">
          {title}
        </p>

        <p className="mt-0.5 text-xs text-slate-500">
          {detected ? positiveText : negativeText}
        </p>
      </div>
    </div>
  );
}

function AssistantMessage({
  message,
}: {
  message: Message;
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="mt-0.5 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
        <Bot size={19} />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-white">
            IDPS Copilot
          </span>

          <span className="text-[10px] text-slate-600">
            {formatTime(message.timestamp)}
          </span>
        </div>

        <div className="mt-3 whitespace-pre-wrap break-words text-base leading-7 text-slate-300 sm:text-[17px] sm:leading-8">
          {message.text}
        </div>

        {message.result && (
          <ResultCard result={message.result} />
        )}
      </div>
    </div>
  );
}

export default function AIAssistant() {
  const { user } = useAuth();

  const registeredAge = calculateAge(user?.date_of_birth);

  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "assistant",
      text:
        "Welcome to IDPS Copilot.\n\n" +
        "I can run your configured URL security checks and explain their results. Enter a website below, or choose a quick action to get started.\n\n" +
        "This version uses your URL-check API and rule-based explanations. A generative AI model and external threat-intelligence service are not connected.",
      timestamp: new Date().toISOString(),
    },
  ]);

  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showScrollButton, setShowScrollButton] =
    useState(false);

  const conversationRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const messageEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({
      behavior: "smooth",
      block: "end",
    });
  }, [messages, loading]);

  function clearConversation() {
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        role: "assistant",
        text:
          "Conversation cleared. Enter a URL to run a new security assessment.",
        timestamp: new Date().toISOString(),
      },
    ]);

    setError("");
    setInput("");
    inputRef.current?.focus();
  }

  function addAssistantMessage(
    text: string,
    result?: URLCheckResult
  ) {
    setMessages((current) => [
      ...current,
      {
        id: `assistant-${Date.now()}-${Math.random()}`,
        role: "assistant",
        text,
        result,
        timestamp: new Date().toISOString(),
      },
    ]);
  }

  async function analyzeURL(rawURL: string) {
    const url = normalizeURLInput(rawURL);

    if (!user) {
      setError("Please log in before analyzing a website.");
      return;
    }

    if (registeredAge === null) {
      setError(
        "Your registered date of birth is missing or invalid. Update your account DOB and sign in again before checking websites."
      );
      return;
    }

    setMessages((current) => [
      ...current,
      {
        id: `user-${Date.now()}`,
        role: "user",
        text: `Analyze website: ${url}`,
        timestamp: new Date().toISOString(),
      },
    ]);

    setInput("");
    setLoading(true);
    setError("");

    try {
      // The backend must derive the age from the authenticated user's DOB.
      // Do not send a client-selected age.
      const response = await api.post<URLCheckResult>(
        "/api/url/check",
        { url }
      );

      const result = response.data;
      const decision = decisionOf(result);
      const presentation = getDecisionPresentation(decision);

      addAssistantMessage(
        `Analysis complete for ${result.domain || result.url}.\n\n` +
          `${presentation.label}. Risk score: ${result.risk_score}/100, classified as ${result.risk_level}.\n\n` +
          `${result.recommendation || presentation.description}\n\n` +
          "Review the detailed detection summary below. These results reflect your configured checks and do not guarantee that a website is safe.",
        result
      );
    } catch (err: unknown) {
      let errorText =
        "The URL analysis failed. Check that the backend is running and that you are logged in.";

      if (typeof err === "object" && err !== null && "response" in err) {
        const response = (
          err as {
            response?: {
              status?: number;
              data?: { detail?: string };
            };
          }
        ).response;

        if (response?.data?.detail) {
          errorText =
            typeof response.data.detail === "string"
              ? response.data.detail
              : JSON.stringify(response.data.detail);
        } else if (response?.status === 401) {
          errorText = "Your session has expired. Please log in again.";
        }
      }

      setError(errorText);

      addAssistantMessage(
        "I could not complete the URL analysis. Review the error message and try again after correcting the issue."
      );
    } finally {
      setLoading(false);
    }
  }

  function sendMessage(rawInput = input) {
    const value = rawInput.trim();

    if (!value || loading) return;

    setError("");

    if (isURLInput(value)) {
      void analyzeURL(value);
      return;
    }

    setMessages((current) => [
      ...current,
      {
        id: `user-${Date.now()}`,
        role: "user",
        text: value,
        timestamp: new Date().toISOString(),
      },
    ]);

    setInput("");

    const lower = value.toLowerCase();

    let reply =
      "This assistant currently explains URL analysis results from the configured IDPS checks. To investigate a website, enter its URL. I cannot perform a live web search or claim to have verified a site's reputation.";

    if (
      lower.includes("https") ||
      lower.includes("ssl") ||
      lower.includes("tls")
    ) {
      reply =
        "HTTPS encrypts data between your browser and the website, helping protect it from interception in transit. However, phishing and malware websites can also use HTTPS. A secure connection does not prove that the site operator is trustworthy. SSL/TLS verification may not be available unless your backend performs a separate certificate check.";
    } else if (
      lower.includes("phishing") ||
      lower.includes("fake website")
    ) {
      reply =
        "Common phishing indicators include lookalike domains, misleading login links, unexpected requests for passwords or payment details, unusual URL paths, and urgent messages. These are indicators, not proof by themselves. Submit a URL to run your configured phishing and URL-structure checks.";
    } else if (
      lower.includes("malware") ||
      lower.includes("virus")
    ) {
      reply =
        "Your malware detector checks the submitted URL against its configured detection rules. A result of 'no local list match' means those configured checks did not match; it does not mean website files or downloads were fully scanned.";
    } else if (
      lower.includes("risk score") ||
      lower.includes("risk level") ||
      lower.includes("warn")
    ) {
      reply =
        "Your risk engine combines URL-structure findings, configured malware and phishing detections, domain reputation, and applicable policy rules. ALLOW means no configured blocking condition was found; WARN recommends caution; BLOCK means a detection or policy requires blocking. A LOW score is not a guarantee of safety.";
    } else if (
      lower.includes("my age") ||
      lower.includes("date of birth") ||
      lower.includes("dob")
    ) {
      reply =
        registeredAge === null
          ? "Your registered date of birth is not available or is invalid. Update your account details and sign in again."
          : `Your age calculated from your registered date of birth is ${registeredAge}. The backend must use the DOB stored on your account to enforce age restrictions.`;
    }

    window.setTimeout(() => {
      addAssistantMessage(reply);
    }, 250);
  }

  const lastResult = [...messages]
    .reverse()
    .find((message) => message.result)?.result;

  return (
    <div className="mx-auto flex min-h-[850px] w-full max-w-7xl flex-col gap-5 pb-4 lg:min-h-[calc(100dvh-7rem)]">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
            <Sparkles size={15} />
            Security operations
          </div>

          <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
            AI Security Copilot
          </h1>

          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            Analyze website risk, understand detection findings, and review
            security recommendations in one workspace.
          </p>
        </div>

        <button
          type="button"
          onClick={clearConversation}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 disabled:opacity-50"
        >
          <Trash2 size={16} />
          New conversation
        </button>
      </header>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Wifi size={15} className="text-emerald-400" />
            Backend integration
          </div>

          <p className="mt-2 text-sm font-semibold text-white">
            URL Check API
          </p>

          <p className="mt-1 text-[11px] text-slate-500">
            Requests use your authenticated session
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Shield size={15} className="text-cyan-300" />
            Detection engine
          </div>

          <p className="mt-2 text-sm font-semibold text-white">
            Rule-based analysis
          </p>

          <p className="mt-1 text-[11px] text-slate-500">
            Local configured checks
          </p>
        </div>

        <div className="col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-3 sm:col-span-1">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Clock3 size={15} className="text-violet-300" />
            Latest assessment
          </div>

          <p className="mt-2 truncate text-sm font-semibold text-white">
            {lastResult?.domain || "No analysis yet"}
          </p>

          <p className="mt-1 text-[11px] text-slate-500">
            {lastResult
              ? `${lastResult.risk_level} · ${lastResult.risk_score}/100`
              : "Submit a URL to begin"}
          </p>
        </div>
      </div>

      <section
        className="flex min-h-[650px] flex-1 flex-col overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-2xl shadow-black/10 lg:min-h-[700px]"
        aria-label="Security copilot conversation"
      >
        <div className="flex items-center gap-3 border-b border-slate-800 bg-slate-950/50 p-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
            <Bot size={22} />
          </div>

          <div>
            <h2 className="text-sm font-semibold text-white">
              IDPS Security Assistant
            </h2>

            <p className="mt-1 text-xs text-slate-500">
              URL analysis and security explanations
            </p>
          </div>

          <div className="ml-auto flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3 py-1.5 text-[11px] text-slate-400">
            <span
              className={`h-2 w-2 rounded-full ${
                loading
                  ? "animate-pulse bg-amber-400"
                  : "bg-emerald-400"
              }`}
            />
            {loading ? "Analyzing" : "Ready"}
          </div>
        </div>

        <div
          ref={conversationRef}
          onScroll={(event) => {
            const element = event.currentTarget;

            setShowScrollButton(
              element.scrollHeight -
                element.scrollTop -
                element.clientHeight >
                100
            );
          }}
          className="relative min-h-[400px] flex-1 space-y-8 overflow-y-auto p-5 sm:p-8 lg:p-10"
        >
          {messages.map((message) =>
            message.role === "assistant" ? (
              <AssistantMessage
                key={message.id}
                message={message}
              />
            ) : (
              <div
                key={message.id}
                className="flex justify-end gap-3"
              >
                <div className="max-w-[90%] sm:max-w-[75%]">
                  <div className="mb-1 flex justify-end">
                    <span className="text-[10px] text-slate-600">
                      You · {formatTime(message.timestamp)}
                    </span>
                  </div>

                  <div className="whitespace-pre-wrap break-words rounded-2xl rounded-tr-sm border border-cyan-400/20 bg-cyan-500/10 px-4 py-3 text-sm leading-6 text-cyan-50">
                    {message.text}
                  </div>
                </div>

                <div className="mt-5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-700 bg-slate-800 text-slate-300">
                  <MessageSquare size={16} />
                </div>
              </div>
            )
          )}

          {loading && (
            <div className="flex items-start gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                <Bot size={19} />
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3">
                <div className="flex items-center gap-2 text-sm text-slate-300">
                  <span className="flex gap-1">
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400" />
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400 [animation-delay:150ms]" />
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400 [animation-delay:300ms]" />
                  </span>
                  Running configured security checks...
                </div>

                <p className="mt-1 text-xs text-slate-500">
                  This may take a moment.
                </p>
              </div>
            </div>
          )}

          {!loading && messages.length === 1 && (
            <div className="pt-2">
              <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                Quick actions
              </p>

              <div className="grid gap-3 sm:grid-cols-3">
                {QUICK_ACTIONS.map((action) => {
                  const Icon = action.icon;

                  return (
                    <button
                      key={action.title}
                      type="button"
                      onClick={() => {
                        if (isURLInput(action.prompt)) {
                          void analyzeURL(action.prompt);
                        } else {
                          sendMessage(action.prompt);
                        }
                      }}
                      className="group rounded-xl border border-slate-800 bg-slate-950/50 p-4 text-left transition hover:border-cyan-500/40 hover:bg-cyan-500/5"
                    >
                      <div className="flex items-center justify-between">
                        <Icon
                          size={19}
                          className="text-cyan-300"
                        />

                        <ArrowRight
                          size={15}
                          className="text-slate-600 transition group-hover:translate-x-1 group-hover:text-cyan-300"
                        />
                      </div>

                      <p className="mt-4 text-sm font-semibold text-white">
                        {action.title}
                      </p>

                      <p className="mt-1 text-xs leading-5 text-slate-500">
                        {action.description}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <div ref={messageEndRef} />

          {showScrollButton && (
            <button
              type="button"
              onClick={() =>
                messageEndRef.current?.scrollIntoView({
                  behavior: "smooth",
                })
              }
              className="sticky bottom-2 left-full flex h-12 w-12 items-center justify-center rounded-full border border-slate-700 bg-slate-800 text-white shadow-lg"
              aria-label="Scroll to latest message"
            >
              <ArrowDown size={17} />
            </button>
          )}
        </div>

        {error && (
          <div
            role="alert"
            className="mx-4 mb-3 flex items-start gap-2 rounded-xl border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-300"
          >
            <AlertTriangle size={17} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form
          onSubmit={(event) => {
            event.preventDefault();
            sendMessage();
          }}
          className="border-t border-slate-800 bg-slate-950/60 p-4 sm:p-5"
        >
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <ShieldCheck size={15} className="text-cyan-300" />
              Age policy uses your registered DOB
            </div>

            <span className="text-xs text-slate-500">
              {registeredAge === null
                ? "DOB unavailable"
                : `Registered age: ${registeredAge}`}
            </span>
          </div>

          {registeredAge === null && (
            <p className="mb-3 text-xs leading-5 text-amber-300">
              URL checks require a valid DOB on your account. Update your
              account details and sign in again if your DOB is missing.
            </p>
          )}

          <div className="flex items-end gap-2 rounded-2xl border border-slate-700 bg-slate-900 p-2 transition focus-within:border-cyan-500/60 focus-within:ring-2 focus-within:ring-cyan-500/10">
            <input
              ref={inputRef}
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder="Enter a URL or ask a security question..."
              aria-label="URL or security question"
              disabled={loading}
              className="min-w-0 flex-1 bg-transparent px-3 py-3 text-sm text-white outline-none placeholder:text-slate-500 disabled:opacity-50"
            />

            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="inline-flex h-11 items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
              aria-label="Send message"
            >
              <Send size={16} />
              <span className="hidden sm:inline">Send</span>
            </button>
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500">
            <span className="flex items-center gap-1.5">
              <LockKeyhole size={13} />
              Avoid submitting URLs containing private tokens or credentials.
            </span>

            <span>Rule-based mode</span>
          </div>
        </form>
      </section>

      <p className="text-center text-[11px] leading-5 text-slate-600">
        IDPS Shield · Results depend on configured detection rules.
        No scan can guarantee that a website is safe.
      </p>
    </div>
  );
}