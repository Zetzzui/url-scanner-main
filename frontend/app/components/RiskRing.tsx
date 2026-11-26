/** Circular gauge for a 0–100 risk score, drawn for the pastel green card. */
export default function RiskRing({ score, loading }: { score: number | null; loading: boolean }) {
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const value = score ?? 0;

  return (
    <div className="relative size-24 shrink-0 sm:size-32" role="img" aria-label={score === null ? "No risk score yet" : `Risk score ${score} out of 100`}>
      <svg viewBox="0 0 100 100" className={`size-full -rotate-90 ${loading ? "animate-spin [animation-duration:2.5s]" : ""}`}>
        <circle cx="50" cy="50" r={radius} fill="none" stroke="rgb(30 59 47 / 0.12)" strokeWidth="6" />
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke="#2f6049"
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={loading ? circumference * 0.75 : circumference * (1 - value / 100)}
          className="transition-[stroke-dashoffset] duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-accent-ink">
        <span className="text-xl font-semibold tabular-nums sm:text-2xl">{loading ? "…" : score === null ? "--" : `${score}%`}</span>
        <span className="text-[11px] text-accent-ink/70">risk</span>
      </div>
    </div>
  );
}
