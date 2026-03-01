"use client";

import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { streamSoulCampaign } from "@/lib/api";
import type { SoulCampaignUpdate } from "@/types/soul";

// ── Severity / phase colors ────────────────────────────────────
const phaseColor: Record<string, string> = {
  initialization: "text-zinc-400",
  static_analysis: "text-blue-400",
  mutation: "text-purple-400",
  taint_analysis: "text-orange-400",
  symbolic_execution: "text-cyan-400",
  concolic: "text-emerald-400",
  differential: "text-yellow-400",
  property_testing: "text-red-400",
  gas_profiling: "text-pink-400",
  exploit_synthesis: "text-red-500",
  reporting: "text-green-400",
};

const getPhaseColor = (phase: string) => phaseColor[phase] || "text-zinc-400";

// ── Helper: sparkline bar ──────────────────────────────────────
function Sparkline({
  data,
  max,
  color = "bg-emerald-500",
}: {
  data: number[];
  max: number;
  color?: string;
}) {
  const visible = data.slice(-60);
  return (
    <div className="flex items-end gap-px h-10 overflow-hidden">
      {visible.map((v, i) => {
        const h = max > 0 ? Math.max(1, (v / max) * 100) : 1;
        return (
          <div
            key={i}
            className={`w-1 rounded-sm ${color} opacity-80`}
            style={{ height: `${h}%` }}
          />
        );
      })}
    </div>
  );
}

// ── Heatmap cell ───────────────────────────────────────────────
function HeatCell({ value, max }: { value: number; max: number }) {
  const intensity = max > 0 ? Math.min(value / max, 1) : 0;
  const bg =
    intensity === 0
      ? "bg-zinc-800"
      : intensity < 0.25
        ? "bg-emerald-900/60"
        : intensity < 0.5
          ? "bg-emerald-700/70"
          : intensity < 0.75
            ? "bg-yellow-600/70"
            : "bg-red-500/80";

  return (
    <div
      className={`w-3 h-3 rounded-sm ${bg} border border-zinc-700/50`}
      title={`hits: ${value}`}
    />
  );
}

// ── Coverage heatmap grid ──────────────────────────────────────
function CoverageHeatmap({ coverage }: { coverage: Record<string, number> }) {
  const entries = Object.entries(coverage);
  const maxVal = Math.max(1, ...entries.map(([, v]) => v));

  if (entries.length === 0) {
    return <p className="text-zinc-500 text-sm">No coverage data yet.</p>;
  }

  return (
    <div className="space-y-2">
      {entries.map(([label, hits]) => (
        <div key={label} className="flex items-center gap-2">
          <span className="text-xs text-zinc-400 w-32 truncate" title={label}>
            {label}
          </span>
          <div className="flex-1">
            <div className="w-full bg-zinc-800 rounded-full h-2">
              <div
                className="bg-emerald-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${Math.min((hits / maxVal) * 100, 100)}%` }}
              />
            </div>
          </div>
          <span className="text-xs text-zinc-500 w-10 text-right">{hits}</span>
        </div>
      ))}
    </div>
  );
}

// ── Mutation graph ─────────────────────────────────────────────
function MutationGraph({
  history,
}: {
  history: { iterations: number; corpus: number; violations: number }[];
}) {
  const maxIter = Math.max(1, ...history.map((h) => h.iterations));
  const maxCorpus = Math.max(1, ...history.map((h) => h.corpus));

  const visible = history.slice(-80);

  return (
    <div className="relative h-32 bg-zinc-900 rounded-lg border border-zinc-800 overflow-hidden">
      {/* Corpus size line */}
      <svg
        className="absolute inset-0 w-full h-full"
        viewBox={`0 0 ${visible.length} 100`}
        preserveAspectRatio="none"
      >
        {/* Corpus area */}
        <polyline
          fill="none"
          stroke="#10b981"
          strokeWidth="1.5"
          points={visible
            .map((h, i) => `${i},${100 - (h.corpus / maxCorpus) * 90}`)
            .join(" ")}
        />
        {/* Violation markers */}
        {visible.map((h, i) =>
          h.violations > 0 ? (
            <circle
              key={i}
              cx={i}
              cy={100 - (h.corpus / maxCorpus) * 90}
              r="2"
              fill="#ef4444"
            />
          ) : null,
        )}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-1 right-2 flex items-center gap-3 text-[10px]">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-emerald-500" />
          Corpus
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-red-500" />
          Violations
        </span>
      </div>
    </div>
  );
}

// ── Stat card ──────────────────────────────────────────────────
function StatCard({
  label,
  value,
  delta,
  unit,
}: {
  label: string;
  value: number | string;
  delta?: number;
  unit?: string;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
      <p className="text-xs text-zinc-500 uppercase tracking-wider">{label}</p>
      <p className="text-2xl font-bold text-zinc-100 mt-1">
        {value}
        {unit && <span className="text-sm text-zinc-400 ml-1">{unit}</span>}
      </p>
      {delta !== undefined && delta > 0 && (
        <p className="text-xs text-emerald-400 mt-0.5">+{delta} new</p>
      )}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────
export default function LiveFuzzingPage() {
  const [campaignId, setCampaignId] = useState("");
  const [inputId, setInputId] = useState("");
  const [connected, setConnected] = useState(false);

  const [update, setUpdate] = useState<SoulCampaignUpdate | null>(null);
  const [history, setHistory] = useState<
    { iterations: number; corpus: number; violations: number }[]
  >([]);
  const [coverageHistory, setCoverageHistory] = useState<number[]>([]);

  const stopRef = useRef<(() => void) | null>(null);

  // ── Connect handler ──────────────────────────────────────────
  const startStream = useCallback(() => {
    const id = inputId.trim();
    if (!id) return;

    // Stop any previous stream
    stopRef.current?.();

    setCampaignId(id);
    setConnected(true);
    setHistory([]);
    setCoverageHistory([]);
    setUpdate(null);

    const stop = streamSoulCampaign(
      id,
      (raw) => {
        const data = raw as unknown as SoulCampaignUpdate;
        setUpdate(data);

        setHistory((prev) => [
          ...prev.slice(-200),
          {
            iterations: data.iterations ?? 0,
            corpus: data.corpus_size ?? 0,
            violations: data.violations_count ?? 0,
          },
        ]);

        const totalCov = Object.values(data.coverage ?? {}).reduce(
          (a, b) => a + b,
          0,
        );
        setCoverageHistory((prev) => [...prev.slice(-200), totalCov]);
      },
      () => setConnected(false),
    );

    stopRef.current = stop;
  }, [inputId]);

  // Cleanup on unmount
  useEffect(() => () => stopRef.current?.(), []);

  // ── Derived stats ────────────────────────────────────────────
  const totalCovPaths = useMemo(
    () => Object.values(update?.coverage ?? {}).reduce((a, b) => a + b, 0),
    [update],
  );

  const lastCov = coverageHistory.at(-2) ?? 0;
  const covDelta = totalCovPaths - lastCov;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-zinc-100">
          Live Fuzzing Monitor
        </h1>
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Campaign ID"
            value={inputId}
            onChange={(e) => setInputId(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && startStream()}
            className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-zinc-200 w-64 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          />
          <button
            onClick={startStream}
            className="bg-emerald-600 hover:bg-emerald-700 text-white text-sm px-4 py-1.5 rounded-lg transition-colors"
          >
            {connected ? "Reconnect" : "Connect"}
          </button>
          {connected && (
            <button
              onClick={() => {
                stopRef.current?.();
                setConnected(false);
              }}
              className="bg-red-600 hover:bg-red-700 text-white text-sm px-4 py-1.5 rounded-lg transition-colors"
            >
              Stop
            </button>
          )}
        </div>
      </div>

      {/* Connection status */}
      <div className="flex items-center gap-2 text-sm">
        <span
          className={`w-2 h-2 rounded-full ${
            connected ? "bg-emerald-500 animate-pulse" : "bg-zinc-600"
          }`}
        />
        <span className={connected ? "text-emerald-400" : "text-zinc-500"}>
          {connected ? `Streaming campaign ${campaignId}` : "Not connected"}
        </span>
        {update?.current_phase && (
          <span
            className={`ml-2 px-2 py-0.5 rounded text-xs font-medium ${getPhaseColor(update.current_phase)}`}
          >
            {update.current_phase.replace(/_/g, " ")}
          </span>
        )}
      </div>

      {!update && !connected && (
        <div className="text-center py-20 text-zinc-500">
          <p className="text-lg">Enter a campaign ID to start monitoring</p>
          <p className="text-sm mt-2">
            Real-time coverage heatmap, mutation graph, and phase tracking
          </p>
        </div>
      )}

      {update && (
        <>
          {/* Stat cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <StatCard
              label="Iterations"
              value={update.iterations?.toLocaleString() ?? "0"}
            />
            <StatCard
              label="Coverage Paths"
              value={totalCovPaths}
              delta={covDelta > 0 ? covDelta : undefined}
            />
            <StatCard label="Corpus Size" value={update.corpus_size ?? 0} />
            <StatCard label="Violations" value={update.violations_count ?? 0} />
            <StatCard label="Taint Flows" value={update.taint_flows ?? 0} />
            <StatCard
              label="Elapsed"
              value={Math.round(update.elapsed_sec ?? 0)}
              unit="s"
            />
          </div>

          {/* v2 stats row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="DoS Vectors" value={update.dos_vectors ?? 0} />
            <StatCard
              label="Invariants Synth."
              value={update.synthesized_invariants ?? 0}
            />
            <StatCard
              label="State Snapshots"
              value={update.state_snapshots ?? 0}
            />
            <StatCard
              label="Exploit Chains"
              value={update.exploit_chains ?? 0}
            />
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Coverage sparkline */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-zinc-300 mb-3">
                Coverage Over Time
              </h3>
              <Sparkline
                data={coverageHistory}
                max={Math.max(1, ...coverageHistory)}
                color="bg-emerald-500"
              />
            </div>

            {/* Mutation / corpus graph */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-zinc-300 mb-3">
                Corpus Growth &amp; Violations
              </h3>
              <MutationGraph history={history} />
            </div>
          </div>

          {/* Coverage heatmap */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-zinc-300 mb-3">
              Coverage Heatmap
            </h3>
            <CoverageHeatmap coverage={update.coverage ?? {}} />
          </div>

          {/* Error display */}
          {update.error && (
            <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-4">
              <p className="text-sm text-red-400 font-mono">{update.error}</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
