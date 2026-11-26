"use client";
import { useEffect, useState, useSyncExternalStore, type FormEvent, type ReactNode } from "react";
import {
  ArrowUpRight,
  ChevronRight,
  Layers,
  Link2,
  LoaderCircle,
  Mail,
  ScanSearch,
  ShieldCheck,
  ShieldX,
  TriangleExclamationPoint,
  X,
  type LucideIcon,
} from "lucide-react";
import ResultCard from "./components/ResultCard";
import RiskRing from "./components/RiskRing";
import { API_URL, postJson, type ScanResult } from "./lib/api";
import { VERDICTS, hostOf } from "./lib/verdicts";

type Tab = "single" | "bulk" | "email";
type HistoryItem = { result: ScanResult; at: number };

const TABS: { id: Tab; label: string; icon: LucideIcon }[] = [
  { id: "single", label: "Single URL", icon: Link2 },
  { id: "bulk", label: "Bulk scan", icon: Layers },
  { id: "email", label: "Email links", icon: Mail },
];

type StatId = "all" | "dangerous" | "suspicious" | "clean";
type Stat = {
  id: StatId;
  label: string;
  note: string;
  icon: LucideIcon;
  idle: string; // tinted glass when not selected
  active: string; // solid color when selected
  activeText: string;
  number: string;
  iconBg: string;
  dot: string;
};

const STATS: Stat[] = [
  {
    id: "all",
    label: "Links scanned",
    note: "Saved in this browser",
    icon: ScanSearch,
    idle: "bg-white/30 border-white/50 shadow-[0_12px_40px_-12px_rgb(50_90_65/0.22)]",
    active: "bg-gradient-to-br from-[#6b4c42] to-[#3b2a24] shadow-[0_20px_50px_-15px_rgb(59_42_36/0.6)]",
    activeText: "text-white",
    number: "text-foreground",
    iconBg: "bg-white/50 text-foreground/70",
    dot: "bg-[#6b4c42]",
  },
  {
    id: "dangerous",
    label: "Dangerous",
    note: "Flagged as malicious",
    icon: ShieldX,
    idle: "bg-red-300/25 border-red-200/70 shadow-[0_12px_40px_-12px_rgb(220_38_38/0.3)]",
    active: "bg-gradient-to-br from-red-400 to-red-600 shadow-[0_20px_50px_-15px_rgb(220_38_38/0.6)]",
    activeText: "text-white",
    number: "text-red-600",
    iconBg: "bg-red-500/15 text-red-600",
    dot: "bg-red-500",
  },
  {
    id: "suspicious",
    label: "Suspicious",
    note: "Red flags found",
    icon: TriangleExclamationPoint,
    idle: "bg-amber-200/30 border-amber-200/80 shadow-[0_12px_40px_-12px_rgb(217_119_6/0.3)]",
    active: "bg-gradient-to-br from-amber-400 to-orange-500 shadow-[0_20px_50px_-15px_rgb(234_88_12/0.6)]",
    activeText: "text-white",
    number: "text-amber-600",
    iconBg: "bg-amber-500/15 text-amber-700",
    dot: "bg-amber-500",
  },
  {
    id: "clean",
    label: "No threats found",
    note: "Nothing flagged them",
    icon: ShieldCheck,
    idle: "bg-emerald-200/30 border-emerald-200/80 shadow-[0_12px_40px_-12px_rgb(5_150_105/0.3)]",
    active: "bg-gradient-to-br from-[#d4f0dd] to-[#a9d4bb] shadow-[0_20px_50px_-15px_rgb(95_148_120/0.55)]",
    activeText: "text-accent-ink",
    number: "text-emerald-600",
    iconBg: "bg-emerald-500/15 text-emerald-700",
    dot: "bg-emerald-500",
  },
];

const MAX_BULK = 20;
const HISTORY_KEY = "url-scanner-history";
const HISTORY_MAX = 50;
const SLOW_NOTE = "Links VirusTotal hasn't seen before can take a minute or more.";

/** Loading/error/result state for one tab, so tabs don't interfere with each other. */
function useScan<T>(onDone: (data: T) => void) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<T | null>(null);

  async function run(task: () => Promise<T>) {
    setLoading(true);
    setError(null);
    setData(null);
    try {
      const result = await task();
      setData(result);
      onDone(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  return { loading, error, data, run };
}

function scanMany(urls: string[]) {
  return postJson<{ results: ScanResult[] }>("/scan/bulk", { urls }).then((r) => r.results);
}

function loadHistory(): HistoryItem[] {
  try {
    const saved = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    return Array.isArray(saved) ? saved : [];
  } catch {
    return [];
  }
}

function saveHistory(items: HistoryItem[]) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
  } catch {
    // Storage unavailable (private window, blocked site data): history just won't persist.
  }
}

const subscribeNever = () => () => {};

function greetingFor(hour: number) {
  return hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
}

const accentInput =
  "w-full rounded-2xl bg-white/35 border border-white/60 px-4 py-3 text-accent-ink placeholder:text-accent-ink/45 outline-none focus:bg-white/50 focus:border-white/90 transition";
const whiteButton =
  "inline-flex items-center justify-center gap-1.5 rounded-full bg-white px-5 py-2.5 text-sm font-semibold text-accent-deep shadow-sm hover:bg-white/90 disabled:opacity-60 disabled:cursor-not-allowed transition";

export default function Home() {
  const [tab, setTab] = useState<Tab>("single");
  const [url, setUrl] = useState("");
  const [bulkUrls, setBulkUrls] = useState("");
  const [emailText, setEmailText] = useState("");
  const [savedHistory, setHistory] = useState<HistoryItem[]>(() => (typeof window === "undefined" ? [] : loadHistory()));
  const [online, setOnline] = useState<boolean | null>(null);
  const [filter, setFilter] = useState<StatId | null>(null);

  // The clock and saved history only exist in the browser. Show them only after hydration,
  // so the first client render matches the server-rendered HTML.
  const hydrated = useSyncExternalStore(subscribeNever, () => true, () => false);
  const history = hydrated ? savedHistory : [];
  const now = hydrated ? new Date() : null;

  useEffect(() => {
    fetch(`${API_URL}/`)
      .then((r) => setOnline(r.ok))
      .catch(() => setOnline(false));
  }, []);

  function remember(results: ScanResult[]) {
    const fresh = results.filter((r) => r.verdict !== "error").map((result) => ({ result, at: Date.now() }));
    if (fresh.length === 0) return;
    setHistory((prev) => {
      const next = [...fresh, ...prev].slice(0, HISTORY_MAX);
      saveHistory(next);
      return next;
    });
  }

  function clearHistory() {
    setHistory([]);
    saveHistory([]);
  }

  const single = useScan<ScanResult>((r) => remember([r]));
  const bulk = useScan<ScanResult[]>(remember);
  const email = useScan<ScanResult[]>(remember);
  const active = { single, bulk, email }[tab];

  const bulkList = bulkUrls.split("\n").map((u) => u.trim()).filter(Boolean);
  const count = (v: string) => history.filter((h) => h.result.verdict === v).length;
  const ringScore = tab === "single" ? (single.data?.risk_score ?? null) : maxRisk(active.data as ScanResult[] | null);

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (tab === "single") single.run(() => postJson<ScanResult>("/scan", { url }));
    if (tab === "bulk") bulk.run(() => scanMany(bulkList));
    if (tab === "email") {
      email.run(async () => {
        const { urls } = await postJson<{ urls: string[] }>("/extract-links", { text: emailText });
        if (urls.length === 0) return [];
        if (urls.length > MAX_BULK) throw new Error(`Found ${urls.length} links; only ${MAX_BULK} can be scanned at once.`);
        return scanMany(urls);
      });
    }
  }

  const canSubmit =
    !active.loading &&
    (tab === "single" ? url.trim() !== "" : tab === "bulk" ? bulkList.length > 0 && bulkList.length <= MAX_BULK : emailText.trim() !== "");

  return (
    <div className="relative min-h-screen overflow-hidden">
      <Backdrop />

      <div className="relative mx-auto flex max-w-7xl flex-col gap-4 p-4 md:flex-row md:gap-6 md:p-6">
        {/* Sidebar: vertical pill on desktop, horizontal bar on phones */}
        <nav
          aria-label="Scan mode"
          className="glass flex shrink-0 items-center gap-2 self-start rounded-full p-2 md:sticky md:top-6 md:flex-col md:py-4"
        >
          <div className="grid size-10 place-items-center rounded-full bg-gradient-to-br from-[#a8d5ba] to-[#4f8569] text-white shadow-md">
            <ScanSearch className="size-5" aria-hidden />
          </div>
          <div className="mx-1 h-6 w-px bg-white/50 md:mx-0 md:my-2 md:h-px md:w-6" />
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              aria-label={t.label}
              aria-pressed={tab === t.id}
              title={t.label}
              className={`grid size-10 place-items-center rounded-full transition ${
                tab === t.id ? "bg-white/80 text-accent-deep shadow-sm" : "text-foreground/60 hover:bg-white/40"
              }`}
            >
              <t.icon className="size-[18px]" aria-hidden />
            </button>
          ))}
        </nav>

        <main className="min-w-0 flex-1">
          {/* Header */}
          <header className="mb-5 flex flex-wrap items-center justify-between gap-3">
            <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">
              {now ? greetingFor(now.getHours()) : "Hello"},{" "}
              <span className="font-serif font-normal text-foreground/55">stay safe</span>
            </h1>
            <div className="flex items-center gap-2 text-sm">
              <span className="glass inline-flex items-center gap-2 rounded-full px-3.5 py-1.5">
                <span
                  className={`size-2 rounded-full ${online === null ? "bg-stone-400" : online ? "bg-emerald-500" : "bg-red-500"}`}
                />
                {online === null ? "Connecting…" : online ? "Scanner online" : "Backend offline"}
              </span>
              {history.length > 0 && (
                <button onClick={clearHistory} className="glass rounded-full px-3.5 py-1.5 hover:bg-white/40 transition">
                  Clear history
                </button>
              )}
            </div>
          </header>

          <div className="grid gap-4 lg:grid-cols-3 md:gap-5">
            {/* Hero: the scan form */}
            <section className="glass-accent relative overflow-hidden rounded-[2rem] p-6 text-accent-ink md:p-8 lg:col-span-2">
              <div className="pointer-events-none absolute -right-16 -top-24 size-72 rounded-full bg-white/10 blur-2xl" />
              <span className="inline-flex items-center gap-2 rounded-full bg-white/40 px-3 py-1 text-xs font-medium">
                <span className="size-1.5 rounded-full bg-accent-deep" />
                VirusTotal · Safe Browsing · WHOIS
              </span>

              <div className="mt-4 flex items-center gap-4 sm:gap-6">
                <div className="min-w-0 flex-1">
                  <h2 className="text-2xl font-semibold leading-tight sm:text-3xl md:text-4xl">
                    Check a link before you <span className="font-serif font-normal">click</span> it
                  </h2>
                  <p className="mt-2 max-w-md text-sm text-accent-ink/75">
                    {tab === "single" && "Paste any link. We follow redirects and check where it really goes."}
                    {tab === "bulk" && `Paste up to ${MAX_BULK} links, one per line.`}
                    {tab === "email" && "Paste a whole email. Every link in it gets extracted and scanned."}
                  </p>
                </div>
                <RiskRing score={ringScore} loading={active.loading} />
              </div>

              <form onSubmit={onSubmit} className="mt-6">
                {tab === "single" && (
                  <div className="flex flex-col gap-2 sm:flex-row">
                    <input
                      className={accentInput}
                      placeholder="https://example.com"
                      aria-label="URL to scan"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                    />
                    <SubmitButton disabled={!canSubmit} loading={active.loading}>
                      Scan
                    </SubmitButton>
                  </div>
                )}
                {tab === "bulk" && (
                  <>
                    <textarea
                      className={`${accentInput} h-36 resize-none`}
                      placeholder="One URL per line"
                      aria-label="URLs to scan, one per line"
                      value={bulkUrls}
                      onChange={(e) => setBulkUrls(e.target.value)}
                    />
                    <div className="mt-3 flex items-center justify-between gap-3">
                      <span className={`text-sm ${bulkList.length > MAX_BULK ? "font-semibold" : "text-accent-ink/70"}`}>
                        {bulkList.length}/{MAX_BULK} links
                      </span>
                      <SubmitButton disabled={!canSubmit} loading={active.loading}>
                        Scan all
                      </SubmitButton>
                    </div>
                  </>
                )}
                {tab === "email" && (
                  <>
                    <textarea
                      className={`${accentInput} h-36 resize-none`}
                      placeholder="Paste the full email text here"
                      aria-label="Email text"
                      value={emailText}
                      onChange={(e) => setEmailText(e.target.value)}
                    />
                    <div className="mt-3 flex justify-end">
                      <SubmitButton disabled={!canSubmit} loading={active.loading}>
                        Extract and scan
                      </SubmitButton>
                    </div>
                  </>
                )}
              </form>

              {active.loading && <p className="mt-4 text-sm text-accent-ink/80">Scanning… {SLOW_NOTE}</p>}
              {active.error && (
                <p className="mt-4 rounded-2xl bg-white/90 px-4 py-2.5 text-sm font-medium text-red-700">{active.error}</p>
              )}
            </section>

            {/* Recent scans */}
            <section className="glass flex flex-col rounded-[2rem] p-5 md:p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-end gap-3">
                  <span className="text-5xl font-semibold leading-none text-accent tabular-nums">
                    {now ? String(now.getDate()).padStart(2, "0") : "--"}
                  </span>
                  <div className="pb-0.5">
                    <p className="font-semibold leading-tight">
                      {now ? now.toLocaleDateString(undefined, { weekday: "long" }) : ""}
                    </p>
                    <p className="text-xs text-muted">
                      {now ? now.toLocaleDateString(undefined, { month: "long", year: "numeric" }) : ""}
                    </p>
                  </div>
                </div>
                <span className="glass-inset rounded-full px-2.5 py-1 text-xs font-medium">Recent</span>
              </div>

              <ul className="mt-5 flex flex-1 flex-col gap-2">
                {history.length === 0 && (
                  <li className="glass-inset rounded-2xl px-4 py-6 text-center text-sm text-muted">
                    Your scans will show up here.
                  </li>
                )}
                {history.slice(0, 6).map((h, i) => (
                  <HistoryRow key={`${h.at}-${i}`} item={h} />
                ))}
              </ul>
            </section>

            {/* Stats: click one to list the scans in that category */}
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4 md:gap-5 lg:col-span-3">
              {STATS.map((s) => (
                <StatCard
                  key={s.id}
                  stat={s}
                  value={s.id === "all" ? history.length : count(s.id)}
                  selected={filter === s.id}
                  onClick={() => setFilter(filter === s.id ? null : s.id)}
                />
              ))}
            </div>

            {filter && (
              <FilteredHistory
                stat={STATS.find((s) => s.id === filter)!}
                items={filter === "all" ? history : history.filter((h) => h.result.verdict === filter)}
                onClose={() => setFilter(null)}
              />
            )}
          </div>

          {/* Results for the current tab */}
          <Results tab={tab} single={single.data} list={tab === "bulk" ? bulk.data : tab === "email" ? email.data : null} />
        </main>
      </div>
    </div>
  );
}

function maxRisk(results: ScanResult[] | null): number | null {
  const scores = (results ?? []).map((r) => r.risk_score).filter((s): s is number => s !== null);
  return scores.length ? Math.max(...scores) : null;
}

function SubmitButton({ disabled, loading, children }: { disabled: boolean; loading: boolean; children: ReactNode }) {
  return (
    <button type="submit" disabled={disabled} className={`${whiteButton} shrink-0`}>
      {loading ? <LoaderCircle className="size-4 animate-spin" aria-hidden /> : null}
      {loading ? "Scanning" : children}
      {!loading && <ArrowUpRight className="size-4" aria-hidden />}
    </button>
  );
}

function StatCard({
  stat,
  value,
  selected,
  onClick,
}: {
  stat: Stat;
  value: number;
  selected: boolean;
  onClick: () => void;
}) {
  const Icon = stat.icon;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={selected}
      aria-controls="filtered-history"
      className={`group relative rounded-[1.75rem] border p-5 text-left backdrop-blur-xl transition duration-200 hover:-translate-y-1 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-foreground/40 ${
        selected ? `${stat.active} ${stat.activeText} border-white/40` : `${stat.idle} hover:shadow-lg`
      }`}
    >
      <span
        className={`absolute right-4 top-4 grid size-9 place-items-center rounded-full transition ${
          selected ? "bg-white/30" : `${stat.iconBg} group-hover:scale-110`
        }`}
      >
        <Icon className="size-[18px]" aria-hidden />
      </span>
      <p className={`text-4xl font-semibold tabular-nums ${selected ? "" : stat.number}`}>
        {String(value).padStart(2, "0")}
      </p>
      <p className="mt-3 text-sm font-semibold">{stat.label}</p>
      <p className={`flex items-center gap-1 text-xs ${selected ? "opacity-80" : "text-muted"}`}>
        {selected ? "Hide list" : stat.note}
        <ChevronRight
          className={`size-3.5 transition ${selected ? "rotate-90" : "opacity-0 group-hover:translate-x-0.5 group-hover:opacity-100"}`}
          aria-hidden
        />
      </p>
    </button>
  );
}

function HistoryRow({ item, withDate = false }: { item: HistoryItem; withDate?: boolean }) {
  const v = VERDICTS[item.result.verdict] ?? VERDICTS.error;
  const when = new Date(item.at);
  return (
    <li className="glass-inset flex items-center gap-3 rounded-2xl px-3 py-2.5">
      <span className={`${withDate ? "w-16" : "w-11"} shrink-0 text-xs tabular-nums text-muted`}>
        {withDate && <span className="block">{when.toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>}
        {when.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
      </span>
      <span className={`h-8 w-1 shrink-0 rounded-full ${v.dot}`} />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{hostOf(item.result.url)}</p>
        <p className="truncate text-xs text-muted">{withDate ? item.result.url : v.label}</p>
      </div>
      {item.result.risk_score !== null && (
        <span className={`rounded-full px-2 py-0.5 text-xs font-semibold tabular-nums ${v.pill}`}>
          {item.result.risk_score}
        </span>
      )}
    </li>
  );
}

function FilteredHistory({ stat, items, onClose }: { stat: Stat; items: HistoryItem[]; onClose: () => void }) {
  return (
    <section id="filtered-history" className="glass animate-rise rounded-[2rem] p-5 md:p-6 lg:col-span-3">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h3 className="flex items-center gap-2 text-lg font-semibold">
          <span className={`size-2.5 rounded-full ${stat.dot}`} />
          {stat.label}
          <span className="font-normal text-muted">({items.length})</span>
        </h3>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close list"
          className="grid size-8 place-items-center rounded-full text-foreground/60 transition hover:bg-white/40"
        >
          <X className="size-4" aria-hidden />
        </button>
      </div>
      {items.length === 0 ? (
        <p className="glass-inset rounded-2xl px-4 py-6 text-center text-sm text-muted">No scans in this category yet.</p>
      ) : (
        <ul className="grid gap-2 md:grid-cols-2">
          {items.map((h, i) => (
            <HistoryRow key={`${h.at}-${i}`} item={h} withDate />
          ))}
        </ul>
      )}
    </section>
  );
}

function Results({ tab, single, list }: { tab: Tab; single: ScanResult | null; list: ScanResult[] | null }) {
  if (tab === "single" && single) {
    return (
      <div className="mt-5">
        <ResultCard result={single} detailed />
      </div>
    );
  }
  if (list && list.length === 0) {
    return <p className="glass mt-5 rounded-3xl p-5 text-sm text-muted">No links found in the text.</p>;
  }
  if (list) {
    return (
      <div className="mt-5 grid gap-3 md:grid-cols-2">
        {list.map((r, i) => (
          <ResultCard key={`${r.url}-${i}`} result={r} />
        ))}
      </div>
    );
  }
  return null;
}

/** Warm blurred light blobs behind the glass, standing in for a photo background. */
function Backdrop() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-[#e8f1ea] via-[#d6e6da] to-[#bfd5c6]" />
      <div className="absolute -left-32 -top-32 size-[34rem] rounded-full bg-[#a8d5ba]/45 blur-[120px]" />
      <div className="absolute right-[-10rem] top-1/4 size-[30rem] rounded-full bg-[#d4f0dd]/70 blur-[110px]" />
      <div className="absolute bottom-[-12rem] left-1/3 size-[36rem] rounded-full bg-[#8fb5a0]/50 blur-[130px]" />
      <div className="absolute inset-0 opacity-[0.04] [background-image:radial-gradient(#3b2a24_1px,transparent_1px)] [background-size:18px_18px]" />
    </div>
  );
}
