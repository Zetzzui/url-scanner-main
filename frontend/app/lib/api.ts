export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

export type Verdict = "dangerous" | "suspicious" | "clean" | "unknown" | "error";

export interface VirusTotalStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

export interface ScanResult {
  url: string;
  final_url?: string;
  verdict: Verdict;
  risk_score: number | null;
  virustotal?: VirusTotalStats | null;
  google_safe_browsing?: "flagged" | "clean" | "not checked" | "error";
  domain_age_days?: number | null;
  warnings: string[];
  errors: string[];
  cached?: boolean;
}

/** Turns FastAPI's error bodies ({detail: "..."} or {detail: [{msg}]}) into one readable sentence. */
function errorMessage(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    return detail.map((d: { msg?: string }) => d.msg ?? "Invalid input").join("; ");
  }
  return `The scanner returned an error (HTTP ${status}).`;
}

export async function postJson<T>(path: string, payload: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new Error(`Can't reach the scanner backend at ${API_URL}. Is it running?`);
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(errorMessage(body, response.status));
  return body as T;
}
