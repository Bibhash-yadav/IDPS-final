
import { useState } from "react";
import { Download, Chrome, ShieldCheck, AlertCircle } from "lucide-react";

const API_URL = (
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

export default function DownloadExtensionButton() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleDownload() {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(
        `${API_URL}/api/extension/download`,
        { method: "GET" }
      );

      if (!response.ok) {
        const body = await response.json().catch(() => ({}));

        throw new Error(
          body.detail || `Download failed (HTTP ${response.status}).`
        );
      }

      const blob = await response.blob();

      if (!blob.size) {
        throw new Error("The downloaded ZIP file is empty.");
      }

      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = objectUrl;
      link.download = "idps-shield-extension.zip";
      document.body.appendChild(link);
      link.click();
      link.remove();

      // Revoke the temporary URL after initiating the download.
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not download the extension."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="rounded-2xl border border-slate-700 bg-slate-900 p-6 text-white shadow-lg">
      <div className="flex items-start gap-4">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
          <Chrome size={30} />
        </div>

        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Browser protection
          </p>

          <h2 className="mt-2 text-xl font-bold">
            IDPS Shield for Chrome
          </h2>

          <p className="mt-2 text-sm leading-6 text-slate-400">
            Check websites while browsing and connect the extension
            to your IDPS security API.
          </p>

          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span className="inline-flex items-center gap-1 rounded-full bg-slate-800 px-3 py-1.5">
              <ShieldCheck size={14} className="text-emerald-400" />
              Chrome extension
            </span>
            <span className="rounded-full bg-slate-800 px-3 py-1.5">
              ZIP package
            </span>
          </div>

          <button
            type="button"
            onClick={handleDownload}
            disabled={loading}
            className="mt-5 inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-500 px-5 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Download size={18} />
            {loading ? "Preparing download..." : "Download Extension (.ZIP)"}
          </button>

          {error && (
            <p
              role="alert"
              className="mt-3 flex items-start gap-2 text-sm text-rose-400"
            >
              <AlertCircle size={18} className="mt-0.5 shrink-0" />
              {error}
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
