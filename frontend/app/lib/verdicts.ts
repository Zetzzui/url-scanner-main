import { ShieldCheck, ShieldQuestionMark, ShieldX, TriangleExclamationPoint, type LucideIcon } from "lucide-react";
import type { Verdict } from "./api";

export const VERDICTS: Record<Verdict, { label: string; icon: LucideIcon; pill: string; dot: string }> = {
  dangerous: { label: "Dangerous", icon: ShieldX, pill: "bg-red-500/15 text-red-700", dot: "bg-red-500" },
  suspicious: {
    label: "Suspicious",
    icon: TriangleExclamationPoint,
    pill: "bg-amber-400/20 text-amber-800",
    dot: "bg-amber-500",
  },
  clean: { label: "No threats found", icon: ShieldCheck, pill: "bg-emerald-500/15 text-emerald-800", dot: "bg-emerald-500" },
  unknown: {
    label: "Could not verify",
    icon: ShieldQuestionMark,
    pill: "bg-stone-500/15 text-stone-700",
    dot: "bg-stone-400",
  },
  error: { label: "Error", icon: ShieldX, pill: "bg-red-500/15 text-red-700", dot: "bg-red-400" },
};

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}
