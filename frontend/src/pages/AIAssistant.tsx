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

type SecurityAnswer = {
  title: string;
  answer: string;
  actions: string[];
};

const QUICK_ACTIONS = [
  {
    title: "Analyze a website",
    description: "Check a URL using your configured security services",
    prompt: "https://example.com",
    icon: ScanSearch,
  },
  {
    title: "Is my browser safe?",
    description: "Understand browser security risks",
    prompt: "Is my browser safe?",
    icon: ShieldCheck,
  },
  {
    title: "Secure my browser",
    description: "Get a browser hardening checklist",
    prompt: "How can I make my browser more secure?",
    icon: LockKeyhole,
  },
  {
    title: "Identify phishing",
    description: "Learn to recognize fake websites",
    prompt: "How can I identify a phishing website?",
    icon: Fingerprint,
  },
  {
    title: "HTTPS security",
    description: "Understand encrypted connections",
    prompt: "What does HTTPS protect me from?",
    icon: Globe,
  },
  {
    title: "Protect my privacy",
    description: "Review tracking and permissions",
    prompt: "How can I improve my browser privacy?",
    icon: Shield,
  },
];

function normalizeURLInput(value: string) {
  const trimmed = value.trim();
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function isURLInput(value: string) {
  const trimmed = value.trim();
  if (!trimmed || /\s/.test(trimmed)) return false;

  try {
    const parsed = new URL(normalizeURLInput(trimmed));
    return (
      ["http:", "https:"].includes(parsed.protocol) &&
      (parsed.hostname.includes(".") ||
        parsed.hostname === "localhost" ||
        /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname) ||
        parsed.hostname.startsWith("["))
    );
  } catch {
    return false;
  }
}

function formatTime(value: string) {
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function decisionOf(result: URLCheckResult): "ALLOW" | "BLOCK" | "WARN" | "UNKNOWN" {
  const decision = (result.decision || "").toUpperCase();
  if (["ALLOW", "ALLOWED"].includes(decision)) return "ALLOW";
  if (["BLOCK", "BLOCKED"].includes(decision)) return "BLOCK";
  if (["WARN", "WARNING"].includes(decision)) return "WARN";
  return "UNKNOWN";
}

function getSecurityAnswer(question: string): SecurityAnswer {
  const q = question.toLowerCase();

  if (
    q.includes("is my browser safe") ||
    q.includes("browser secure") ||
    q.includes("browser safety") ||
    q.includes("check my browser") ||
    q.includes("is my browser secure")
  ) {
    return {
      title: "Browser safety assessment",
      answer:
        "I cannot directly inspect your complete browser configuration from this chat. A browser's safety depends on its updates, built-in protections, installed extensions, downloads, saved credentials and browsing habits. A URL scan cannot prove that your entire browser or device is safe. The following checklist is guidance, not a completed audit.",
      actions: [
        "Update your browser to the latest stable version.",
        "Enable built-in phishing and malware protection.",
        "Review extensions and remove anything unfamiliar or unnecessary.",
        "Check camera, microphone, location and notification permissions.",
        "Use unique passwords and enable multifactor authentication.",
        "Review recent downloads and scan suspicious files with trusted security software.",
        "Check for unwanted redirects, pop-ups and unfamiliar browser changes.",
      ],
    };
  }

  if (
    q.includes("make my browser safe") ||
    q.includes("secure my browser") ||
    q.includes("improve browser security") ||
    q.includes("browser more safe") ||
    q.includes("protect my browser")
  ) {
    return {
      title: "Browser hardening checklist",
      answer:
        "You can reduce browser risks by enabling built-in security features, limiting permissions and keeping software updated. Menu names vary by browser.",
      actions: [
        "Enable automatic browser updates.",
        "Enable Safe Browsing or equivalent phishing and malware protection.",
        "Remove unknown extensions and review their permissions.",
        "Block third-party cookies or tracking where practical.",
        "Restrict camera, microphone, location and notification permissions.",
        "Use a reputable password manager and unique passwords.",
        "Enable multifactor authentication or passkeys.",
        "Avoid pirated software and suspicious downloads.",
        "Keep your operating system and security software updated.",
      ],
    };
  }

  if (
    q.includes("phishing") ||
    q.includes("fake website") ||
    q.includes("suspicious link") ||
    q.includes("fake login")
  ) {
    return {
      title: "Phishing protection",
      answer:
        "Phishing websites imitate trusted services to steal passwords, payment details or personal information. HTTPS does not prove a website is legitimate.",
      actions: [
        "Check the exact domain spelling.",
        "Open important services using an official bookmark or app.",
        "Do not enter passwords after following unexpected messages or links.",
        "Never share one-time codes or recovery codes.",
        "Treat urgent payment requests and unexpected attachments cautiously.",
        "Submit suspicious URLs to IDPS Shield for its configured checks.",
      ],
    };
  }

  if (
    q.includes("malware") ||
    q.includes("virus") ||
    q.includes("infected") ||
    q.includes("hacked my browser")
  ) {
    return {
      title: "Malware and compromise response",
      answer:
        "A suspicious URL result does not prove that your device is infected. If you suspect compromise, avoid interacting with suspicious files and use a trusted security product to investigate.",
      actions: [
        "Do not open or run suspicious downloads.",
        "Run a full scan using updated, trusted security software.",
        "Remove unfamiliar extensions and unwanted applications.",
        "Review browser settings for unexpected changes.",
        "If credentials may have been stolen, change them from a trusted device.",
        "Review active account sessions and sign out unfamiliar devices.",
        "Seek professional assistance if suspicious activity continues.",
      ],
    };
  }

  if (
    q.includes("https") ||
    q.includes("ssl") ||
    q.includes("tls") ||
    q.includes("padlock") ||
    q.includes("http secure")
  ) {
    return {
      title: "HTTPS and connection security",
      answer:
        "HTTPS encrypts traffic between your browser and a website and helps authenticate the server. It does not prove the site is trustworthy or free of malware. IDPS Shield's HTTPS result should only be treated as verified if its backend actually checks the submitted URL.",
      actions: [
        "Do not bypass certificate or privacy warnings.",
        "Verify the domain before entering sensitive information.",
        "Avoid entering credentials over plain HTTP.",
        "Keep your browser updated.",
        "Remember that phishing websites can also use HTTPS.",
      ],
    };
  }

  if (
    q.includes("password") ||
    q.includes("account hacked") ||
    q.includes("stolen credential") ||
    q.includes("account security")
  ) {
    return {
      title: "Password and account protection",
      answer:
        "Unique passwords help prevent a breach at one service from compromising your other accounts.",
      actions: [
        "Use a reputable password manager.",
        "Use a different strong password for every account.",
        "Enable multifactor authentication or passkeys.",
        "Change passwords that were reused or exposed.",
        "Review active sessions and sign out unfamiliar devices.",
        "Never share one-time codes or recovery codes.",
      ],
    };
  }

  if (
    q.includes("privacy") ||
    q.includes("tracking") ||
    q.includes("personal data") ||
    q.includes("cookies") ||
    q.includes("anonymous")
  ) {
    return {
      title: "Browser privacy",
      answer:
        "Privacy settings can reduce tracking and unnecessary data collection, but they do not make you completely anonymous. Websites, network providers and services may still receive information.",
      actions: [
        "Review third-party cookie and tracking protections.",
        "Restrict camera, microphone, location and notification permissions.",
        "Remove extensions that request unnecessary access.",
        "Clear site data when appropriate, knowing this may sign you out.",
        "Avoid submitting private URLs containing tokens or credentials to scanners.",
        "Review account privacy settings on frequently used services.",
      ],
    };
  }

  if (
    q.includes("download") ||
    q.includes("file safe") ||
    q.includes("attachment") ||
    q.includes("exe file")
  ) {
    return {
      title: "Download safety",
      answer:
        "A filename, icon or download source does not prove that a file is safe. URL analysis does not necessarily scan downloaded files.",
      actions: [
        "Download software from official vendor websites.",
        "Avoid unexpected email attachments and executable files.",
        "Check digital signatures where available.",
        "Scan suspicious files using trusted security software.",
        "Never disable security protection just to run an unknown file.",
      ],
    };
  }

  if (
    q.includes("risk score") ||
    q.includes("risk level") ||
    q.includes("security score")
  ) {
    return {
      title: "Understanding risk scores",
      answer:
        "IDPS Shield's URL risk score reflects the checks configured on your backend. It is not a complete measurement of browser security or device health. A low score does not guarantee safety.",
      actions: [
        "Read the findings and explanations, not only the score.",
        "Avoid URLs that receive a BLOCK decision.",
        "Investigate WARN results before continuing.",
        "Do not enter sensitive information if you remain uncertain.",
        "Treat unavailable checks as unknown, not as passed.",
      ],
    };
  }

  if (
    q.includes("extension") ||
    q.includes("browser add-on") ||
    q.includes("browser addon")
  ) {
    return {
      title: "Extension safety",
      answer:
        "Browser extensions can read or change website data depending on their permissions. Only install extensions you trust and understand.",
      actions: [
        "Remove extensions you no longer use.",
        "Review permissions and website access.",
        "Install extensions from official browser stores.",
        "Avoid extensions requesting unrelated permissions.",
        "Keep extensions updated.",
        "If an extension behaves suspiciously, disable it and investigate.",
      ],
    };
  }

  if (
    q.includes("public wifi") ||
    q.includes("public wi-fi") ||
    q.includes("hotel wifi") ||
    q.includes("airport wifi")
  ) {
    return {
      title: "Public Wi-Fi safety",
      answer:
        "Public Wi-Fi networks can expose you to fake access points and other network risks. HTTPS helps protect traffic in transit but does not make every website trustworthy.",
      actions: [
        "Verify the network name with the venue.",
        "Avoid sensitive activity on networks you do not trust.",
        "Keep file sharing disabled on public networks.",
        "Do not ignore certificate warnings.",
        "Use a reputable VPN when appropriate and understand its privacy policy.",
        "Enable multifactor authentication for important accounts.",
      ],
    };
  }

  if (
    q.includes("safe browsing") ||
    q.includes("google safe browsing") ||
    q.includes("browser protection")
  ) {
    return {
      title: "Built-in browser protection",
      answer:
        "Most mainstream browsers provide protections against some phishing, malware and dangerous downloads. The exact features and protection level depend on the browser and its settings.",
      actions: [
        "Open your browser's privacy and security settings.",
        "Enable its phishing and malware protection.",
        "Review download warnings rather than bypassing them.",
        "Install browser updates promptly.",
        "Remember that no protection detects every threat.",
      ],
    };
  }

  return {
    title: "IDPS Security Guidance",
    answer:
      "I can help explain browser security, privacy, phishing, malware, passwords, downloads and IDPS risk results. I cannot claim to have inspected your browser settings, scanned your device or verified a website's live reputation unless a connected security service actually performs that check.",
    actions: [
      "Update your browser and operating system.",
      "Enable built-in phishing and malware protection.",
      "Review extensions and site permissions.",
      "Analyze suspicious URLs before interacting with them.",
      "Tell me your browser name and describe the warning or issue for more specific guidance.",
    ],
  };
}

function useThemeMode() {
  const [isDark, setIsDark] = useState(() => {
    if (typeof document === "undefined") return true;
    return document.documentElement.dataset.theme !== "light";
  });

  useEffect(() => {
    const root = document.documentElement;
    const updateTheme = () => setIsDark(root.dataset.theme !== "light");
    updateTheme();

    const observer = new MutationObserver(updateTheme);
    observer.observe(root, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });

    return () => observer.disconnect();
  }, []);

  return isDark;
}

function ResultCard({
  result,
  isDark,
}: {
  result: URLCheckResult;
  isDark: boolean;
}) {
  const decision = decisionOf(result);
  const styles = {
    ALLOW: {
      title: "No blocking indicators found",
      color: "text-emerald-500",
      badge: "border-emerald-500/25 bg-emerald-500/10 text-emerald-500",
      icon: ShieldCheck,
    },
    BLOCK: {
      title: "Access not recommended",
      color: "text-rose-500",
      badge: "border-rose-500/25 bg-rose-500/10 text-rose-500",
      icon: ShieldX,
    },
    WARN: {
      title: "Caution advised",
      color: "text-amber-500",
      badge: "border-amber-500/25 bg-amber-500/10 text-amber-500",
      icon: ShieldAlert,
    },
    UNKNOWN: {
      title: "Decision unavailable",
      color: isDark ? "text-slate-300" : "text-slate-600",
      badge: isDark
        ? "border-slate-700 bg-slate-800 text-slate-300"
        : "border-slate-200 bg-slate-100 text-slate-600",
      icon: Info,
    },
  }[decision];

  const DecisionIcon = styles.icon;
  const score = Math.max(0, Math.min(100, Number(result.risk_score) || 0));
  const reasons = Array.isArray(result.reasons)
    ? [...new Set(result.reasons.filter((item) => typeof item === "string" && item.trim()))]
    : [];
  const malwareDetected = Boolean(
    result.malware?.malware_detected ?? result.malware?.detected
  );
  const phishingDetected = Boolean(
    result.phishing?.phishing_detected ?? result.phishing?.detected
  );
  const httpsEnabled = result.https_enabled ?? result.url_analysis?.https_enabled;

  const panel = isDark
    ? "border-white/[0.09] bg-slate-950/45"
    : "border-slate-200/80 bg-white/65";
  const muted = isDark ? "text-slate-400" : "text-slate-500";
  const primary = isDark ? "text-slate-100" : "text-slate-800";

  return (
    <div className={`mt-4 overflow-hidden rounded-2xl border shadow-sm ${panel}`}>
      <div className={`flex items-start gap-3 p-4 ${isDark ? "bg-white/[0.035]" : "bg-white/55"}`}>
        <DecisionIcon size={25} className={`${styles.color} mt-0.5 shrink-0`} />
        <div className="min-w-0 flex-1">
          <h3 className={`font-semibold ${primary}`}>{styles.title}</h3>
          <p className={`mt-1 break-all text-sm ${muted}`}>
            {result.domain || result.url}
          </p>
          <p className={`mt-2 text-xs leading-5 ${muted}`}>
            {result.recommendation ||
              "This result reflects configured checks and is not a guarantee of safety."}
          </p>
        </div>
        <span className={`rounded-full border px-3 py-1 text-[10px] font-bold tracking-wider ${styles.badge}`}>
          {decision}
        </span>
      </div>

      <div className={`grid grid-cols-2 gap-px sm:grid-cols-4 ${isDark ? "bg-white/[0.07]" : "bg-slate-200/70"}`}>
        {[
          {
            label: "Risk score",
            value: `${score}/100`,
            extra: (
              <div className={`mt-2 h-1.5 overflow-hidden rounded-full ${isDark ? "bg-slate-800" : "bg-slate-200"}`}>
                <div
                  className="h-full rounded-full bg-cyan-500 transition-all"
                  style={{ width: `${score}%` }}
                />
              </div>
            ),
          },
          { label: "Risk level", value: result.risk_level || "UNKNOWN" },
          {
            label: "HTTPS",
            value:
              httpsEnabled === true
                ? "Enabled"
                : httpsEnabled === false
                  ? "Not enabled"
                  : "Not checked",
          },
          { label: "SSL/TLS", value: result.ssl_status || "Not checked" },
        ].map((item) => (
          <div key={item.label} className={`p-3 ${isDark ? "bg-slate-950/80" : "bg-white/75"}`}>
            <p className={`text-xs ${muted}`}>{item.label}</p>
            <p className={`mt-2 text-sm font-semibold ${primary}`}>{item.value}</p>
            {item.extra}
          </div>
        ))}
      </div>

      <div className="space-y-4 p-4">
        <h4 className={`flex items-center gap-2 text-sm font-semibold ${primary}`}>
          <Activity size={16} className="text-cyan-500" />
          Detection summary
        </h4>

        <div className="grid gap-2 sm:grid-cols-2">
          {[
            {
              title: "Malware",
              detected: malwareDetected,
              detail: result.malware?.reason,
              fallback: "No local list match reported",
            },
            {
              title: "Phishing",
              detected: phishingDetected,
              detail: result.phishing?.reason,
              fallback: "No local rule triggered",
            },
          ].map((item) => (
            <div
              key={item.title}
              className={`flex items-center gap-3 rounded-xl border p-3 ${panel}`}
            >
              {item.detected ? (
                <XCircle size={19} className="shrink-0 text-rose-500" />
              ) : (
                <CheckCircle2 size={19} className="shrink-0 text-emerald-500" />
              )}
              <div>
                <p className={`text-sm font-medium ${primary}`}>{item.title}</p>
                <p className={`mt-1 text-xs ${muted}`}>
                  {item.detail || (item.detected ? "Detection reported" : item.fallback)}
                </p>
              </div>
            </div>
          ))}
        </div>

        <div className={`rounded-xl border p-3 ${panel}`}>
          <p className={`text-xs ${muted}`}>Domain reputation</p>
          <p className={`mt-1 text-sm ${primary}`}>
            {result.domain_reputation || "Unknown / not checked"}
          </p>
          <p className={`mt-3 text-xs ${muted}`}>Analysis method</p>
          <p className={`mt-1 text-sm ${primary}`}>
            {result.analysis_method || "Not specified"}
          </p>
          {result.age_decision && (
            <>
              <p className={`mt-3 text-xs ${muted}`}>Age policy result</p>
              <p className={`mt-1 text-sm ${primary}`}>
                {result.age_decision}
                {typeof result.required_age === "number"
                  ? ` · Required age: ${result.required_age}+`
                  : ""}
              </p>
            </>
          )}
        </div>

        <div>
          <h4 className={`text-sm font-semibold ${primary}`}>
            Findings and explanations
          </h4>
          {reasons.length > 0 ? (
            <ul className="mt-3 space-y-2">
              {reasons.map((reason, index) => (
                <li key={`${index}-${reason}`} className={`flex gap-2 text-sm ${muted}`}>
                  <span className="text-cyan-500">•</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className={`mt-2 text-sm ${muted}`}>
              No specific reasons were returned by the backend.
            </p>
          )}
        </div>

        <p className={`flex items-start gap-2 text-xs leading-5 ${muted}`}>
          <Info size={15} className="mt-0.5 shrink-0" />
          HTTPS encrypts a connection but does not prove a site is trustworthy. A low risk score is not a guarantee that a site is safe.
        </p>
      </div>
    </div>
  );
}

function AssistantMessage({
  message,
  isDark,
}: {
  message: Message;
  isDark: boolean;
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="mt-1 flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-500 shadow-sm">
        <Bot size={20} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className={`text-sm font-semibold ${isDark ? "text-slate-100" : "text-slate-800"}`}>
            IDPS Copilot
          </span>
          <span className={`text-xs ${isDark ? "text-slate-600" : "text-slate-400"}`}>
            {formatTime(message.timestamp)}
          </span>
        </div>
        <div className={`mt-3 whitespace-pre-wrap break-words text-sm leading-7 sm:text-[15px] ${isDark ? "text-slate-300" : "text-slate-600"}`}>
          {message.text}
        </div>
        {message.result && (
          <ResultCard result={message.result} isDark={isDark} />
        )}
      </div>
    </div>
  );
}

export default function AIAssistant() {
  const { user } = useAuth();
  const isDark = useThemeMode();

  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "assistant",
      text:
        "Welcome to IDPS Security Copilot.\n\n" +
        "Ask about browser safety, phishing, malware, HTTPS, passwords, privacy, downloads or browser extensions. You can also submit a URL for configured security checks.\n\n" +
        "Important: general guidance is rule-based. A complete browser audit and a generative AI model are not connected by this component.",
      timestamp: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showScrollButton, setShowScrollButton] = useState(false);

  const conversationRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const surface = isDark
    ? "border-white/[0.08] bg-slate-900/55 shadow-black/20"
    : "border-white/80 bg-white/65 shadow-slate-200/50";
  const innerSurface = isDark
    ? "border-white/[0.07] bg-slate-950/35"
    : "border-slate-200/70 bg-white/55";
  const heading = isDark ? "text-white" : "text-slate-900";
  const body = isDark ? "text-slate-400" : "text-slate-500";
  const subtle = isDark ? "text-slate-500" : "text-slate-400";

  // Skip the initial mount so opening this page from the sidebar
  // does not move the main document. Later, scroll only the chat panel.
  const isFirstRender = useRef(true);

  useEffect(() => {
    if (isFirstRender.current) {
      isFirstRender.current = false;
      return;
    }

    const container = conversationRef.current;
    if (!container) return;

    container.scrollTo({
      top: container.scrollHeight,
      behavior: "smooth",
    });
  }, [messages, loading]);

  function addAssistantMessage(text: string, result?: URLCheckResult) {
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

  function clearConversation() {
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        role: "assistant",
        text:
          "New conversation started. Ask a browser-security question or enter a URL to analyze.",
        timestamp: new Date().toISOString(),
      },
    ]);
    setError("");
    setInput("");
    inputRef.current?.focus();
  }

  async function analyzeURL(rawURL: string) {
    const url = normalizeURLInput(rawURL);

    if (!user) {
      setError("Please log in before analyzing a website.");
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
      const response = await api.post<URLCheckResult>("/api/url/check", {
        url,
      });
      const result = response.data;
      const decision = decisionOf(result);

      const summary =
        decision === "BLOCK"
          ? "The configured security checks recommend blocking this URL."
          : decision === "WARN"
            ? "The configured security checks recommend caution."
            : decision === "ALLOW"
              ? "No blocking indicator was reported by the configured checks. This does not guarantee safety."
              : "The backend did not return a recognized security decision.";

      addAssistantMessage(
        `Analysis complete for ${result.domain || result.url}.\n\n` +
          `${summary}\n\n` +
          `Risk score: ${result.risk_score}/100\n` +
          `Risk level: ${result.risk_level || "UNKNOWN"}\n\n` +
          `${result.recommendation || "Review the findings below before deciding what to do."}`,
        result
      );
    } catch (err: unknown) {
      let errorText =
        "URL analysis failed. Check the backend URL, network connection and login session.";

      if (typeof err === "object" && err !== null && "response" in err) {
        const response = (
          err as {
            response?: {
              status?: number;
              data?: { detail?: unknown };
            };
          }
        ).response;

        if (response?.data?.detail) {
          errorText =
            typeof response.data.detail === "string"
              ? response.data.detail
              : JSON.stringify(response.data.detail);
        } else if (response?.status === 401) {
          errorText = "Your session may have expired. Please log in again.";
        } else if (response?.status === 403) {
          errorText = "The backend denied this request. Check your account permissions.";
        }
      } else if (typeof err === "object" && err !== null && "message" in err) {
        const message = String((err as { message: unknown }).message);
        if (message) errorText = `${errorText} Details: ${message}`;
      }

      setError(errorText);
      addAssistantMessage(
        "I could not complete the URL analysis. Check the error message, backend availability and authentication, then try again."
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

    const security = getSecurityAnswer(value);
    const reply =
      `${security.title}\n\n${security.answer}\n\n` +
      "Recommended actions:\n" +
      security.actions.map((action, index) => `${index + 1}. ${action}`).join("\n");

    window.setTimeout(() => {
      addAssistantMessage(reply);
    }, 200);
  }

  const lastResult = [...messages]
    .reverse()
    .find((message) => message.result)?.result;

  return (
    <div className="mx-auto flex min-h-[calc(100dvh-8rem)] w-full max-w-7xl flex-col gap-5 pb-5">
      {/* Page heading */}
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-500">
            <Sparkles size={15} />
            Security operations
          </div>
          <h1 className={`mt-2 text-3xl font-bold tracking-tight sm:text-4xl ${heading}`}>
            AI Security Copilot
          </h1>
          <p className={`mt-2 max-w-2xl text-sm leading-6 ${body}`}>
            Explore browser security, assess URL risk and get practical recommendations for safer browsing.
          </p>
        </div>

        <button
          type="button"
          onClick={clearConversation}
          disabled={loading}
          className={`inline-flex items-center gap-2 rounded-2xl border px-4 py-2.5 text-sm font-medium shadow-sm backdrop-blur-xl transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-50 ${surface} ${heading}`}
        >
          <Trash2 size={16} />
          New conversation
        </button>
      </header>

      {/* Integration overview */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className={`rounded-2xl border p-4 shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className={`flex items-center gap-2 text-xs ${body}`}>
            <Wifi size={15} className="text-cyan-500" />
            Backend integration
          </div>
          <p className={`mt-2 text-sm font-semibold ${heading}`}>URL Check API</p>
          <p className={`mt-1 text-[11px] ${subtle}`}>Used for URL analysis</p>
        </div>

        <div className={`rounded-2xl border p-4 shadow-lg backdrop-blur-2xl ${surface}`}>
          <div className={`flex items-center gap-2 text-xs ${body}`}>
            <Shield size={15} className="text-cyan-500" />
            Guidance engine
          </div>
          <p className={`mt-2 text-sm font-semibold ${heading}`}>Security rules</p>
          <p className={`mt-1 text-[11px] ${subtle}`}>Rule-based answers, not live AI</p>
        </div>

        <div className={`col-span-2 rounded-2xl border p-4 shadow-lg backdrop-blur-2xl sm:col-span-1 ${surface}`}>
          <div className={`flex items-center gap-2 text-xs ${body}`}>
            <Clock3 size={15} className="text-violet-500" />
            Latest assessment
          </div>
          <p className={`mt-2 truncate text-sm font-semibold ${heading}`}>
            {lastResult?.domain || "No analysis yet"}
          </p>
          <p className={`mt-1 text-[11px] ${subtle}`}>
            {lastResult
              ? `${lastResult.risk_level} · ${lastResult.risk_score}/100`
              : "Submit a URL to begin"}
          </p>
        </div>
      </div>

      {/* Conversation shell */}
      <section
        className={`flex min-h-[650px] flex-1 flex-col overflow-hidden rounded-[28px] border shadow-2xl backdrop-blur-2xl lg:min-h-[700px] ${surface}`}
        aria-label="Security copilot conversation"
      >
        <div className={`flex items-center gap-3 border-b p-4 sm:px-5 ${isDark ? "border-white/[0.07] bg-slate-950/35" : "border-slate-200/70 bg-white/45"}`}>
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-500">
            <Bot size={22} />
          </div>
          <div>
            <h2 className={`text-sm font-semibold ${heading}`}>IDPS Security Assistant</h2>
            <p className={`mt-1 text-xs ${body}`}>
              URL analysis and browser-security guidance
            </p>
          </div>
          <div className={`ml-auto flex items-center gap-2 rounded-full border px-3 py-1.5 text-[11px] ${innerSurface} ${body}`}>
            <span
              className={`h-2 w-2 rounded-full ${
                loading ? "animate-pulse bg-amber-400" : "bg-emerald-400"
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
              element.scrollHeight - element.scrollTop - element.clientHeight > 100
            );
          }}
          className="relative min-h-[400px] flex-1 space-y-8 overflow-y-auto p-5 sm:p-8 lg:p-10"
        >
          {messages.map((message) =>
            message.role === "assistant" ? (
              <AssistantMessage
                key={message.id}
                message={message}
                isDark={isDark}
              />
            ) : (
              <div key={message.id} className="flex justify-end gap-3">
                <div className="max-w-[90%] sm:max-w-[75%]">
                  <div className="mb-1 flex justify-end">
                    <span className={`text-[10px] ${subtle}`}>
                      You · {formatTime(message.timestamp)}
                    </span>
                  </div>
                  <div className={`whitespace-pre-wrap break-words rounded-2xl rounded-tr-md border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-sm leading-6 shadow-sm ${isDark ? "text-cyan-100" : "text-cyan-800"}`}>
                    {message.text}
                  </div>
                </div>
                <div className={`mt-5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border ${innerSurface} ${body}`}>
                  <MessageSquare size={16} />
                </div>
              </div>
            )
          )}

          {loading && (
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-500">
                <Bot size={19} />
              </div>
              <div className={`rounded-2xl border px-4 py-3 ${innerSurface}`}>
                <div className={`flex items-center gap-2 text-sm ${body}`}>
                  <span className="flex gap-1">
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-500" />
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-500 [animation-delay:150ms]" />
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-500 [animation-delay:300ms]" />
                  </span>
                  Running configured security checks...
                </div>
                <p className={`mt-1 text-xs ${subtle}`}>This may take a moment.</p>
              </div>
            </div>
          )}

          {!loading && messages.length === 1 && (
            <div className="pt-2">
              <p className={`mb-3 text-xs font-semibold uppercase tracking-wider ${subtle}`}>
                Explore security topics
              </p>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {QUICK_ACTIONS.map((action) => {
                  const Icon = action.icon;
                  return (
                    <button
                      key={action.title}
                      type="button"
                      onClick={() => sendMessage(action.prompt)}
                      className={`group rounded-2xl border p-4 text-left shadow-sm backdrop-blur-xl transition duration-200 hover:-translate-y-1 hover:border-cyan-500/40 hover:shadow-lg ${innerSurface}`}
                    >
                      <div className="flex items-center justify-between">
                        <Icon size={19} className="text-cyan-500" />
                        <ArrowRight
                          size={15}
                          className={`transition group-hover:translate-x-1 group-hover:text-cyan-500 ${subtle}`}
                        />
                      </div>
                      <p className={`mt-4 text-sm font-semibold ${heading}`}>
                        {action.title}
                      </p>
                      <p className={`mt-1 text-xs leading-5 ${body}`}>
                        {action.description}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {showScrollButton && (
            <button
              type="button"
              onClick={() => {
                const container = conversationRef.current;
                container?.scrollTo({
                  top: container.scrollHeight,
                  behavior: "smooth",
                });
              }}
              className="sticky bottom-2 left-full flex h-11 w-11 items-center justify-center rounded-full border border-cyan-500/25 bg-cyan-500 text-white shadow-lg transition hover:scale-105"
              aria-label="Scroll to latest message"
            >
              <ArrowDown size={17} />
            </button>
          )}
        </div>

        {error && (
          <div
            role="alert"
            className="mx-4 mb-3 flex items-start gap-2 rounded-2xl border border-rose-500/25 bg-rose-500/10 p-3 text-sm text-rose-500"
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
          className={`border-t p-4 sm:p-5 ${isDark ? "border-white/[0.07] bg-slate-950/35" : "border-slate-200/70 bg-white/45"}`}
        >
          <div className={`mb-3 flex items-center gap-2 text-xs ${body}`}>
            <ShieldCheck size={15} className="text-cyan-500" />
            Ask a security question or submit a website URL
          </div>

          <div className={`flex items-end gap-2 rounded-2xl border p-2 shadow-inner transition focus-within:border-cyan-500/50 focus-within:ring-4 focus-within:ring-cyan-500/10 ${isDark ? "border-white/10 bg-slate-900/80" : "border-slate-200 bg-white/80"}`}>
            <input
              ref={inputRef}
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder="Is my browser safe? How do I detect phishing?"
              aria-label="URL or security question"
              disabled={loading}
              className={`min-w-0 flex-1 bg-transparent px-3 py-3 text-sm outline-none placeholder:text-slate-400 disabled:opacity-50 ${heading}`}
            />
            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="inline-flex h-11 items-center justify-center gap-2 rounded-xl bg-cyan-500 px-4 text-sm font-semibold text-white shadow-md shadow-cyan-500/20 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
              aria-label="Send message"
            >
              <Send size={16} />
              <span className="hidden sm:inline">Send</span>
            </button>
          </div>

          <div className={`mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] ${subtle}`}>
            <span className="flex items-center gap-1.5">
              <LockKeyhole size={13} />
              Do not submit URLs containing private tokens or credentials.
            </span>
            <span>Rule-based guidance · URL Check API</span>
          </div>
        </form>
      </section>

      <p className={`text-center text-[11px] leading-5 ${subtle}`}>
        IDPS Shield · Results depend on configured detection rules. No scan can guarantee that a website or browser is safe.
      </p>
    </div>
  );
}
