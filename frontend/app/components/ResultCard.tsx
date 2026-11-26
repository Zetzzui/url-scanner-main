import { CornerDownRight } from "lucide-react";
import type { ScanResult } from "../lib/api";
import { VERDICTS } from "../lib/verdicts";

export default function ResultCard({ result, detailed = false }: { result: ScanResult; detailed?: boolean }) {
  const verdict = VERDICTS[result.verdict] ?? VERDICTS.error;
  const Icon = verdict.icon;
  const vt = result.virustotal;

  return (
    <div className={`glass rounded-3xl animate-rise ${detailed ? "p-6" : "p-4"}`}>
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm text-foreground/80 break-all">{result.url}</p>
        {result.risk_score !== null && (
          <span className="glass-inset rounded-full px-2.5 py-0.5 text-xs font-medium tabular-nums shrink-0">
            {result.risk_score}/100
          </span>
        )}
      </div>

      <span className={`mt-2 inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-sm font-semibold ${verdict.pill}`}>
        <Icon className="size-4" aria-hidden />
        {verdict.label}
      </span>

      {result.final_url && result.final_url !== result.url && (
        <p className="mt-2 flex items-start gap-1.5 text-sm text-amber-800 break-all">
          <CornerDownRight className="size-4 mt-0.5 shrink-0" aria-hidden />
          Redirects to {result.final_url}
        </p>
      )}

      {result.warnings.length > 0 && (
        <ul className="mt-3 space-y-1 text-sm text-amber-900">
          {result.warnings.map((w) => (
            <li key={w} className="flex gap-2">
              <span className="mt-1.5 size-1.5 rounded-full bg-amber-500 shrink-0" />
              {w}
            </li>
          ))}
        </ul>
      )}

      {result.errors.length > 0 && (
        <ul className="mt-3 space-y-1 text-sm text-red-700">
          {result.errors.map((e) => (
            <li key={e} className="flex gap-2">
              <span className="mt-1.5 size-1.5 rounded-full bg-red-500 shrink-0" />
              {e}
            </li>
          ))}
        </ul>
      )}

      {detailed && result.verdict !== "error" && (
        <dl className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-2 text-sm">
          <Detail label="Malicious" value={vt ? String(vt.malicious) : "--"} />
          <Detail label="Suspicious" value={vt ? String(vt.suspicious) : "--"} />
          <Detail label="Safe Browsing" value={result.google_safe_browsing ?? "--"} />
          <Detail label="Domain age" value={result.domain_age_days != null ? `${result.domain_age_days} days` : "unknown"} />
        </dl>
      )}

      {detailed && result.verdict === "clean" && (
        <p className="mt-4 text-xs text-muted">
          No scanner flagged this link, but that isn&apos;t a guarantee. Be careful with links you weren&apos;t expecting.
        </p>
      )}
      {detailed && result.cached && <p className="mt-1 text-xs text-muted">Cached result from the last hour.</p>}
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="glass-inset rounded-2xl px-3 py-2">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="font-semibold capitalize">{value}</dd>
    </div>
  );
}
