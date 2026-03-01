"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import {
  soulFuzz,
  soulQuickFuzz,
  soulStaticScan,
  soulConcolic,
  soulDifferential,
  soulSymbolic,
  soulPropertyTest,
  getSoulForgeStatus,
  streamSoulCampaign,
} from "@/lib/api";
import type {
  SoulFuzzResult,
  SoulStaticScanResult,
  SoulConcolicResult,
  SoulDifferentialResult,
  SoulSymbolicResult,
  SoulPropertyTestResult,
  SoulForgeStatus,
  PowerSchedule,
} from "@/types/soul";

// ── Severity colors ────────────────────────────────────────────
const severityColor: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  LOW: "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

const getSevColor = (sev: string) =>
  severityColor[sev] || "text-zinc-400 bg-zinc-500/10 border-zinc-500/30";

type FuzzMode =
  | "quick"
  | "standard"
  | "deep"
  | "concolic"
  | "differential"
  | "symbolic"
  | "property";

type ResultTab =
  | "violations"
  | "static"
  | "coverage"
  | "mutations"
  | "advanced"
  | "differential"
  | "properties"
  | "symbolic"
  | "corpus"
  | "strategies"
  | "taint"
  | "exploits"
  | "gas";

// ── Score badge ────────────────────────────────────────────────
function ScoreBadge({ score }: { score: number }) {
  const color =
    score >= 80
      ? "text-emerald-400 border-emerald-500/30"
      : score >= 60
        ? "text-yellow-400 border-yellow-500/30"
        : score >= 40
          ? "text-orange-400 border-orange-500/30"
          : "text-red-400 border-red-500/30";

  const grade =
    score >= 90
      ? "A+"
      : score >= 80
        ? "A"
        : score >= 70
          ? "B"
          : score >= 60
            ? "C"
            : score >= 40
              ? "D"
              : "F";

  return (
    <div className={`flex items-center gap-3 rounded-xl border p-4 ${color}`}>
      <span className="text-4xl font-bold font-mono">{grade}</span>
      <div>
        <p className="text-sm opacity-70">Security Score</p>
        <p className="text-2xl font-bold">{score.toFixed(1)}</p>
      </div>
    </div>
  );
}

// ── Stat Card ─────────────────────────────────────────────────
function StatCard({
  label,
  value,
  sub,
  color,
}: {
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
}) {
  return (
    <div className="bg-[#12121a] border border-zinc-800 rounded-xl p-4">
      <p className="text-xs text-zinc-500 mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color || "text-zinc-200"}`}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      {sub && <p className="text-xs text-zinc-600 mt-1">{sub}</p>}
    </div>
  );
}

// ── Coverage Bar ──────────────────────────────────────────────
function CoverageBar({ label, value }: { label: string; value: number }) {
  const pct = (value * 100).toFixed(1);
  return (
    <div className="bg-[#12121a] border border-zinc-800 rounded-xl p-5">
      <p className="text-xs text-zinc-500 capitalize mb-2">{label} Coverage</p>
      <div className="relative h-2 bg-zinc-800 rounded-full overflow-hidden mb-2">
        <div
          className="absolute inset-y-0 left-0 bg-gradient-to-r from-violet-500 to-cyan-500 rounded-full transition-all duration-500"
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="text-xl font-bold text-zinc-200">{pct}%</p>
    </div>
  );
}

// ── Page ────────────────────────────────────────────────────────
export default function SoulFuzzerPage() {
  // State
  const [sourceCode, setSourceCode] = useState("");
  const [prevSource, setPrevSource] = useState("");
  const [contractName, setContractName] = useState("SoulContract");
  const [mode, setMode] = useState<FuzzMode>("standard");
  const [powerSchedule, setPowerSchedule] = useState<PowerSchedule>("fast");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SoulFuzzResult | null>(null);
  const [concolicResult, setConcolicResult] =
    useState<SoulConcolicResult | null>(null);
  const [diffResult, setDiffResult] = useState<SoulDifferentialResult | null>(
    null,
  );
  const [symbolicResult, setSymbolicResult] =
    useState<SoulSymbolicResult | null>(null);
  const [propertyResult, setPropertyResult] =
    useState<SoulPropertyTestResult | null>(null);
  const [staticResult, setStaticResult] = useState<SoulStaticScanResult | null>(
    null,
  );
  const [forgeStatus, setForgeStatus] = useState<SoulForgeStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<ResultTab>("violations");
  const [liveStatus, setLiveStatus] = useState<Record<string, unknown> | null>(
    null,
  );
  const cleanupRef = useRef<(() => void) | null>(null);

  // Check Forge status on mount
  useEffect(() => {
    getSoulForgeStatus()
      .then(setForgeStatus)
      .catch(() => {});
    return () => {
      cleanupRef.current?.();
    };
  }, []);

  // ── Mode descriptions ─────────────────────────────────────────
  const modeInfo: Record<
    FuzzMode,
    { label: string; desc: string; gradient: string }
  > = {
    quick: {
      label: "Quick (60s)",
      desc: "Fast broad coverage",
      gradient: "from-emerald-600 to-teal-600",
    },
    standard: {
      label: "Standard (5m)",
      desc: "Balanced fuzz + symbolic + LLM",
      gradient: "from-violet-600 to-fuchsia-600",
    },
    deep: {
      label: "Deep (15m)",
      desc: "Exhaustive 18-phase pipeline",
      gradient: "from-red-600 to-orange-600",
    },
    concolic: {
      label: "Concolic",
      desc: "SAGE-style concrete + symbolic",
      gradient: "from-cyan-600 to-blue-600",
    },
    differential: {
      label: "Differential",
      desc: "Cross-version comparison",
      gradient: "from-amber-600 to-yellow-600",
    },
    symbolic: {
      label: "Symbolic",
      desc: "Constraint-based path analysis",
      gradient: "from-indigo-600 to-purple-600",
    },
    property: {
      label: "Property",
      desc: "Cross-contract invariant testing",
      gradient: "from-pink-600 to-rose-600",
    },
  };

  // ── Handlers ──────────────────────────────────────────────────

  const clearResults = () => {
    setResult(null);
    setConcolicResult(null);
    setDiffResult(null);
    setSymbolicResult(null);
    setPropertyResult(null);
    setStaticResult(null);
    setLiveStatus(null);
  };

  const handleFuzz = useCallback(async () => {
    if (!sourceCode.trim()) {
      setError("Paste Solidity source code to fuzz");
      return;
    }
    setLoading(true);
    setError(null);
    clearResults();

    try {
      switch (mode) {
        case "concolic": {
          const res = await soulConcolic({
            source_code: sourceCode,
            contract_name: contractName,
          });
          setConcolicResult(res);
          setTab("advanced");
          break;
        }
        case "differential": {
          if (!prevSource.trim()) {
            setError("Paste previous version source for differential testing");
            setLoading(false);
            return;
          }
          const res = await soulDifferential({
            source_code: sourceCode,
            contract_name: contractName,
            previous_source: prevSource,
          });
          setDiffResult(res);
          setTab("differential");
          break;
        }
        case "symbolic": {
          const res = await soulSymbolic({
            source_code: sourceCode,
            contract_name: contractName,
          });
          setSymbolicResult(res);
          setTab("symbolic");
          break;
        }
        case "property": {
          const res = await soulPropertyTest({
            source_code: sourceCode,
            contract_name: contractName,
          });
          setPropertyResult(res);
          setTab("properties");
          break;
        }
        default: {
          const modeMap: Record<string, string> = {
            quick: "quick",
            standard: "standard",
            deep: "deep",
          };
          const res = await soulFuzz({
            source_code: sourceCode,
            contract_name: contractName,
            mode: modeMap[mode] || "standard",
            enable_llm: true,
            enable_static_scan: true,
            enable_symbolic: mode !== "quick",
            enable_concolic: mode === "deep",
            enable_forge: true,
            enable_property_testing: mode === "deep",
            enable_advanced_corpus: true,
            power_schedule: powerSchedule,
          });
          setResult(res);
          setTab("violations");

          // Start SSE streaming for background campaigns
          if (res.status === "starting" && res.campaign_id) {
            cleanupRef.current?.();
            cleanupRef.current = streamSoulCampaign(
              res.campaign_id,
              (update) => setLiveStatus(update),
              () => setLiveStatus(null),
            );
          }
        }
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || "Fuzz failed");
    } finally {
      setLoading(false);
    }
  }, [sourceCode, prevSource, contractName, mode, powerSchedule]);

  const handleQuickFuzz = useCallback(async () => {
    if (!sourceCode.trim()) {
      setError("Paste Solidity source code");
      return;
    }
    setLoading(true);
    setError(null);
    clearResults();
    try {
      const res = await soulQuickFuzz({
        source_code: sourceCode,
        contract_name: contractName,
      });
      setResult(res);
      setTab("violations");
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || "Quick fuzz failed");
    } finally {
      setLoading(false);
    }
  }, [sourceCode, contractName]);

  const handleStaticScan = useCallback(async () => {
    if (!sourceCode.trim()) {
      setError("Paste Solidity source code");
      return;
    }
    setLoading(true);
    setError(null);
    clearResults();
    try {
      const res = await soulStaticScan({
        source_code: sourceCode,
        contract_name: contractName,
      });
      setStaticResult(res);
      setTab("static");
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  }, [sourceCode, contractName]);

  const hasAnyResult =
    result ||
    concolicResult ||
    diffResult ||
    symbolicResult ||
    propertyResult ||
    staticResult;
  const activeScore =
    result?.score ??
    concolicResult?.score ??
    diffResult?.score ??
    propertyResult?.score ??
    null;

  // ── Render ────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-100">
      {/* Header */}
      <header className="border-b border-zinc-800/60 bg-[#0d0d14]/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 flex items-center justify-center text-white font-bold text-sm">
              Z
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight">
                ZASEON Soul Fuzzer
              </h1>
              <p className="text-xs text-zinc-500">
                Advanced Mutation-Feedback Fuzzer — 18-Phase Pipeline, 13
                Engines
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {forgeStatus && (
              <span
                className={`text-xs px-2 py-1 rounded-full border ${forgeStatus.forge_available ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10" : "text-zinc-500 border-zinc-700 bg-zinc-800/50"}`}
              >
                Forge {forgeStatus.forge_available ? "Ready" : "N/A"}
              </span>
            )}
            <a
              href="https://github.com/Soul-Research-Labs/SOUL"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-zinc-500 hover:text-violet-400 transition-colors"
            >
              Soul Protocol GitHub &rarr;
            </a>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Input Section */}
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Source editors */}
          <div className="lg:col-span-2 space-y-3">
            <label className="text-sm font-medium text-zinc-300">
              Solidity Source Code
            </label>
            <textarea
              value={sourceCode}
              onChange={(e) => setSourceCode(e.target.value)}
              placeholder="// Paste your Soul Protocol contract source code here..."
              className="w-full h-64 bg-[#12121a] border border-zinc-800 rounded-xl p-4 font-mono text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-violet-500/50 resize-none"
              spellCheck={false}
            />
            {mode === "differential" && (
              <>
                <label className="text-sm font-medium text-zinc-300">
                  Previous Version (for Differential Testing)
                </label>
                <textarea
                  value={prevSource}
                  onChange={(e) => setPrevSource(e.target.value)}
                  placeholder="// Paste the previous version of the contract..."
                  className="w-full h-40 bg-[#12121a] border border-amber-800/50 rounded-xl p-4 font-mono text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-amber-500/50 resize-none"
                  spellCheck={false}
                />
              </>
            )}
          </div>

          {/* Controls */}
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium text-zinc-300 block mb-1">
                Contract Name
              </label>
              <input
                type="text"
                value={contractName}
                onChange={(e) => setContractName(e.target.value)}
                className="w-full bg-[#12121a] border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-violet-500/50"
              />
            </div>

            {/* Mode Grid */}
            <div>
              <label className="text-sm font-medium text-zinc-300 block mb-2">
                Fuzz Mode
              </label>
              <div className="grid grid-cols-2 gap-2">
                {(Object.keys(modeInfo) as FuzzMode[]).map((m) => (
                  <button
                    key={m}
                    onClick={() => setMode(m)}
                    className={`px-3 py-2 rounded-lg text-xs font-medium border transition-all text-left ${
                      mode === m
                        ? `bg-gradient-to-r ${modeInfo[m].gradient} border-transparent text-white`
                        : "bg-zinc-900 border-zinc-800 text-zinc-500 hover:border-zinc-700"
                    }`}
                  >
                    <span className="block">{modeInfo[m].label}</span>
                    <span className="block text-[10px] opacity-70 mt-0.5">
                      {modeInfo[m].desc}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Power Schedule (for standard/deep modes) */}
            {(mode === "standard" || mode === "deep") && (
              <div>
                <label className="text-sm font-medium text-zinc-300 block mb-1">
                  Power Schedule
                </label>
                <select
                  value={powerSchedule}
                  onChange={(e) =>
                    setPowerSchedule(e.target.value as PowerSchedule)
                  }
                  className="w-full bg-[#12121a] border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-violet-500/50"
                >
                  <option value="fast">FAST — Frequency stochastic</option>
                  <option value="coe">COE — Cut-off exponential</option>
                  <option value="explore">EXPLORE — Uniform exploration</option>
                  <option value="exploit">EXPLOIT — Violation-focused</option>
                  <option value="mmopt">MMOPT — Mutation-aware</option>
                  <option value="rare">RARE — Rare edge boost</option>
                  <option value="lin">LIN — Linear scaling</option>
                  <option value="quad">QUAD — Quadratic decay</option>
                </select>
              </div>
            )}

            {/* Stats badges */}
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-lg p-3 text-center">
                <p className="text-violet-400 font-bold text-lg">24</p>
                <p className="text-zinc-500">Detectors</p>
              </div>
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-lg p-3 text-center">
                <p className="text-fuchsia-400 font-bold text-lg">25</p>
                <p className="text-zinc-500">Invariants</p>
              </div>
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-lg p-3 text-center">
                <p className="text-cyan-400 font-bold text-lg">45+</p>
                <p className="text-zinc-500">Mutations</p>
              </div>
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-lg p-3 text-center">
                <p className="text-emerald-400 font-bold text-lg">13</p>
                <p className="text-zinc-500">Engines</p>
              </div>
            </div>

            {/* Action buttons */}
            <div className="space-y-2">
              <button
                onClick={handleFuzz}
                disabled={loading}
                className={`w-full py-3 rounded-xl bg-gradient-to-r ${modeInfo[mode].gradient} text-white font-semibold text-sm hover:opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed`}
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                        fill="none"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                      />
                    </svg>
                    Running {modeInfo[mode].label}...
                  </span>
                ) : (
                  `Start ${modeInfo[mode].label} ${mode === "differential" ? "Test" : mode === "property" ? "Test" : mode === "symbolic" ? "Analysis" : "Fuzz"}`
                )}
              </button>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={handleQuickFuzz}
                  disabled={loading}
                  className="py-2 rounded-lg border border-zinc-700 text-xs text-zinc-400 hover:text-violet-300 hover:border-violet-500/30 transition-all disabled:opacity-50"
                >
                  Quick Fuzz
                </button>
                <button
                  onClick={handleStaticScan}
                  disabled={loading}
                  className="py-2 rounded-lg border border-zinc-700 text-xs text-zinc-400 hover:text-cyan-300 hover:border-cyan-500/30 transition-all disabled:opacity-50"
                >
                  Static Only
                </button>
              </div>
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-xs text-red-400">
                {error}
              </div>
            )}
          </div>
        </section>

        {/* Live Status Banner */}
        {liveStatus && (
          <div className="bg-violet-500/10 border border-violet-500/30 rounded-xl p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-violet-400 animate-pulse" />
              <span className="text-sm text-violet-300">
                Campaign running — Phase:{" "}
                {String(liveStatus.current_phase || "fuzzing")}
              </span>
            </div>
            <div className="flex items-center gap-6 text-xs text-zinc-400">
              <span>
                Iterations:{" "}
                {Number(liveStatus.iterations || 0).toLocaleString()}
              </span>
              <span>
                Violations: {Number(liveStatus.violations_count || 0)}
              </span>
              <span>Corpus: {Number(liveStatus.corpus_size || 0)}</span>
            </div>
          </div>
        )}

        {/* Results Section */}
        {hasAnyResult && (
          <section className="space-y-6">
            {/* Score + Summary */}
            {(result || concolicResult) && (
              <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                {activeScore !== null && <ScoreBadge score={activeScore} />}
                <StatCard
                  label="Violations"
                  value={
                    result?.violations.length ??
                    concolicResult?.violations.length ??
                    0
                  }
                  sub={`${(result?.violations ?? []).filter((v) => v.severity === "critical").length} critical`}
                  color="text-red-400"
                />
                <StatCard
                  label="Iterations"
                  value={
                    result?.total_iterations ??
                    concolicResult?.total_iterations ??
                    0
                  }
                  sub={`${(result?.duration_sec ?? concolicResult?.duration_sec ?? 0).toFixed(1)}s`}
                  color="text-violet-400"
                />
                <StatCard
                  label="Coverage"
                  value={`${(((result?.coverage ?? concolicResult?.coverage ?? {}).line || 0) * 100).toFixed(1)}%`}
                  sub={`${result?.unique_paths ?? concolicResult?.unique_paths ?? 0} unique paths`}
                  color="text-cyan-400"
                />
                {result && (
                  <StatCard
                    label="Total Findings"
                    value={result.total_findings}
                    sub={`${result.forge_executions} Forge execs`}
                    color="text-fuchsia-400"
                  />
                )}
              </div>
            )}

            {/* Advanced engine stats row */}
            {result &&
              (result.symbolic_paths_explored > 0 ||
                result.concolic_generations > 0 ||
                result.differential_findings.length > 0 ||
                result.property_violations.length > 0) && (
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  {result.symbolic_paths_explored > 0 && (
                    <div className="bg-indigo-500/10 border border-indigo-500/20 rounded-lg p-3 text-center">
                      <p className="text-indigo-400 font-bold text-lg">
                        {result.symbolic_paths_explored}
                      </p>
                      <p className="text-xs text-zinc-500">Symbolic Paths</p>
                    </div>
                  )}
                  {result.concolic_generations > 0 && (
                    <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-lg p-3 text-center">
                      <p className="text-cyan-400 font-bold text-lg">
                        {result.concolic_generations}
                      </p>
                      <p className="text-xs text-zinc-500">Concolic Gens</p>
                    </div>
                  )}
                  {result.differential_findings.length > 0 && (
                    <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 text-center">
                      <p className="text-amber-400 font-bold text-lg">
                        {result.differential_findings.length}
                      </p>
                      <p className="text-xs text-zinc-500">Diff Findings</p>
                    </div>
                  )}
                  {result.property_violations.length > 0 && (
                    <div className="bg-pink-500/10 border border-pink-500/20 rounded-lg p-3 text-center">
                      <p className="text-pink-400 font-bold text-lg">
                        {result.property_violations.length}
                      </p>
                      <p className="text-xs text-zinc-500">
                        Property Violations
                      </p>
                    </div>
                  )}
                  {result.forge_executions > 0 && (
                    <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-3 text-center">
                      <p className="text-emerald-400 font-bold text-lg">
                        {result.forge_executions}
                      </p>
                      <p className="text-xs text-zinc-500">Forge Executions</p>
                    </div>
                  )}
                </div>
              )}

            {/* v2 Engine Stats Row */}
            {result &&
              (result.taint_flows?.length > 0 ||
                result.dos_vectors?.length > 0 ||
                result.exploit_chains?.length > 0 ||
                result.synthesized_invariants?.length > 0 ||
                result.state_snapshots > 0) && (
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  {result.taint_flows?.length > 0 && (
                    <div className="bg-rose-500/10 border border-rose-500/20 rounded-lg p-3 text-center">
                      <p className="text-rose-400 font-bold text-lg">
                        {result.taint_flows.length}
                      </p>
                      <p className="text-xs text-zinc-500">Taint Flows</p>
                    </div>
                  )}
                  {result.dos_vectors?.length > 0 && (
                    <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg p-3 text-center">
                      <p className="text-orange-400 font-bold text-lg">
                        {result.dos_vectors.length}
                      </p>
                      <p className="text-xs text-zinc-500">DoS Vectors</p>
                    </div>
                  )}
                  {result.exploit_chains?.length > 0 && (
                    <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-center">
                      <p className="text-red-400 font-bold text-lg">
                        {result.exploit_chains.length}
                      </p>
                      <p className="text-xs text-zinc-500">Exploit Chains</p>
                    </div>
                  )}
                  {result.synthesized_invariants?.length > 0 && (
                    <div className="bg-teal-500/10 border border-teal-500/20 rounded-lg p-3 text-center">
                      <p className="text-teal-400 font-bold text-lg">
                        {result.synthesized_invariants.length}
                      </p>
                      <p className="text-xs text-zinc-500">New Invariants</p>
                    </div>
                  )}
                  {result.state_snapshots > 0 && (
                    <div className="bg-sky-500/10 border border-sky-500/20 rounded-lg p-3 text-center">
                      <p className="text-sky-400 font-bold text-lg">
                        {result.state_snapshots}
                      </p>
                      <p className="text-xs text-zinc-500">State Snapshots</p>
                    </div>
                  )}
                </div>
              )}

            {/* Differential / Symbolic / Property score cards */}
            {diffResult && (
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <ScoreBadge score={diffResult.score} />
                <StatCard
                  label="Inputs Tested"
                  value={diffResult.total_inputs_tested}
                  color="text-amber-400"
                />
                <StatCard
                  label="Divergences"
                  value={diffResult.differential_findings.length}
                  sub={`${diffResult.inputs_with_divergence_pct.toFixed(1)}% divergence`}
                  color="text-red-400"
                />
                <StatCard
                  label="Duration"
                  value={`${diffResult.duration_sec.toFixed(1)}s`}
                  color="text-zinc-300"
                />
              </div>
            )}
            {symbolicResult && (
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <StatCard
                  label="Paths Explored"
                  value={symbolicResult.paths_explored}
                  color="text-indigo-400"
                />
                <StatCard
                  label="Constraints"
                  value={symbolicResult.constraints_generated}
                  color="text-purple-400"
                />
                <StatCard
                  label="Seeds Generated"
                  value={symbolicResult.seeds_generated}
                  color="text-cyan-400"
                />
                <StatCard
                  label="Unreachable"
                  value={symbolicResult.unreachable_branches}
                  sub="dead branches"
                  color="text-zinc-400"
                />
              </div>
            )}
            {propertyResult && (
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <ScoreBadge score={propertyResult.score} />
                <StatCard
                  label="Sequences"
                  value={propertyResult.sequences_tested}
                  color="text-pink-400"
                />
                <StatCard
                  label="Properties"
                  value={propertyResult.properties_checked}
                  sub={
                    propertyResult.all_properties_held
                      ? "All held"
                      : "Violations found"
                  }
                  color="text-fuchsia-400"
                />
                <StatCard
                  label="Violations"
                  value={propertyResult.property_violations.length}
                  color="text-red-400"
                />
              </div>
            )}

            {/* Tabs */}
            <div className="flex gap-1 border-b border-zinc-800 overflow-x-auto">
              {(
                [
                  result && {
                    key: "violations" as ResultTab,
                    label: `Violations (${result.violations.length})`,
                  },
                  (result || staticResult) && {
                    key: "static" as ResultTab,
                    label: `Static (${result?.static_findings?.length || staticResult?.findings?.length || 0})`,
                  },
                  (result || concolicResult) && {
                    key: "coverage" as ResultTab,
                    label: "Coverage",
                  },
                  result && {
                    key: "mutations" as ResultTab,
                    label: "Mutations",
                  },
                  (result?.differential_findings?.length || diffResult) && {
                    key: "differential" as ResultTab,
                    label: `Differential (${result?.differential_findings?.length ?? diffResult?.differential_findings?.length ?? 0})`,
                  },
                  (result?.property_violations?.length || propertyResult) && {
                    key: "properties" as ResultTab,
                    label: `Properties (${result?.property_violations?.length ?? propertyResult?.property_violations?.length ?? 0})`,
                  },
                  symbolicResult && {
                    key: "symbolic" as ResultTab,
                    label: `Symbolic (${symbolicResult.paths_explored})`,
                  },
                  result &&
                    (result.llm_strategies?.length > 0 ||
                      result.attack_hypotheses?.length > 0) && {
                      key: "strategies" as ResultTab,
                      label: "AI Strategies",
                    },
                  result?.corpus_stats && {
                    key: "corpus" as ResultTab,
                    label: "Corpus",
                  },
                  result?.taint_flows?.length > 0 && {
                    key: "taint" as ResultTab,
                    label: `Taint (${result.taint_flows.length})`,
                  },
                  result?.exploit_chains?.length > 0 && {
                    key: "exploits" as ResultTab,
                    label: `Exploits (${result.exploit_chains.length})`,
                  },
                  result?.dos_vectors?.length > 0 && {
                    key: "gas" as ResultTab,
                    label: `Gas/DoS (${result.dos_vectors.length})`,
                  },
                ].filter(Boolean) as Array<{ key: ResultTab; label: string }>
              ).map((t) => (
                <button
                  key={t.key}
                  onClick={() => setTab(t.key)}
                  className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 whitespace-nowrap ${
                    tab === t.key
                      ? "text-violet-400 border-violet-400"
                      : "text-zinc-500 border-transparent hover:text-zinc-300"
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab: Violations */}
            {tab === "violations" && result && (
              <div className="space-y-3">
                {result.violations.length === 0 ? (
                  <div className="text-center py-12 text-zinc-500">
                    <p className="text-lg font-medium">
                      No invariant violations found
                    </p>
                    <p className="text-sm mt-1">
                      All {result.invariants_checked.length} invariants held
                    </p>
                  </div>
                ) : (
                  result.violations.map((v, i) => (
                    <div
                      key={i}
                      className={`border rounded-xl p-4 space-y-2 ${getSevColor(v.severity)}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono opacity-70">
                            {v.invariant_id}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSevColor(v.severity)}`}
                          >
                            {v.severity}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 text-xs text-zinc-500">
                          {v.minimized && (
                            <span className="text-emerald-400">minimized</span>
                          )}
                          {v.has_poc && (
                            <span className="text-violet-400">PoC</span>
                          )}
                          <span>iter #{v.iteration}</span>
                        </div>
                      </div>
                      <p className="text-sm">{v.invariant_desc}</p>
                      <div className="flex items-center gap-4 text-xs text-zinc-500">
                        <span>
                          Mutation:{" "}
                          <code className="text-zinc-300">{v.mutation}</code>
                        </span>
                        <span>
                          Coverage: {(v.coverage_at_trigger * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Tab: Static Findings */}
            {tab === "static" && (
              <div className="space-y-3">
                {(result?.static_findings || staticResult?.findings || []).map(
                  (f, i) => (
                    <div
                      key={i}
                      className={`border rounded-xl p-4 space-y-2 ${getSevColor(f.severity)}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono opacity-70">
                            {f.detector_id}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSevColor(f.severity)}`}
                          >
                            {f.severity}
                          </span>
                        </div>
                        {f.start_line > 0 && (
                          <span className="text-xs text-zinc-500">
                            Line {f.start_line}
                          </span>
                        )}
                      </div>
                      <p className="text-sm font-medium">{f.title}</p>
                      <p className="text-xs text-zinc-400">{f.description}</p>
                      {f.remediation && (
                        <div className="bg-black/20 rounded-lg p-3 text-xs">
                          <p className="text-emerald-400 font-medium mb-1">
                            Remediation
                          </p>
                          <p className="text-zinc-300 font-mono text-[11px]">
                            {f.remediation}
                          </p>
                        </div>
                      )}
                    </div>
                  ),
                )}
              </div>
            )}

            {/* Tab: Coverage */}
            {tab === "coverage" && (result || concolicResult) && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {Object.entries(
                    result?.coverage ?? concolicResult?.coverage ?? {},
                  ).map(([key, value]) => (
                    <CoverageBar key={key} label={key} value={value} />
                  ))}
                  <StatCard
                    label="Corpus Size"
                    value={
                      result?.corpus_size ?? concolicResult?.corpus_size ?? 0
                    }
                  />
                  <StatCard
                    label="Unique Paths"
                    value={
                      result?.unique_paths ?? concolicResult?.unique_paths ?? 0
                    }
                  />
                </div>
                {concolicResult && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <StatCard
                      label="Concolic Generations"
                      value={concolicResult.concolic_generations}
                      color="text-cyan-400"
                    />
                    <StatCard
                      label="New Cov from Concolic"
                      value={`${concolicResult.concolic_new_coverage_pct.toFixed(1)}%`}
                      color="text-emerald-400"
                    />
                    <StatCard
                      label="Symbolic Paths"
                      value={concolicResult.symbolic_paths_explored}
                      color="text-indigo-400"
                    />
                  </div>
                )}
              </div>
            )}

            {/* Tab: Mutations */}
            {tab === "mutations" && result && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {Object.entries(result.mutation_stats)
                    .sort(([, a], [, b]) => b - a)
                    .map(([mutation, count]) => (
                      <div
                        key={mutation}
                        className="bg-[#12121a] border border-zinc-800 rounded-lg p-3"
                      >
                        <p className="text-xs font-mono text-zinc-400 truncate">
                          {mutation}
                        </p>
                        <p className="text-lg font-bold text-zinc-200">
                          {count}
                        </p>
                      </div>
                    ))}
                </div>
                {result.llm_insights.length > 0 && (
                  <div className="bg-violet-500/5 border border-violet-500/20 rounded-xl p-5 space-y-3">
                    <h3 className="text-sm font-semibold text-violet-300">
                      AI Insights
                    </h3>
                    {result.llm_insights.map((insight, i) => (
                      <p key={i} className="text-xs text-zinc-300">
                        {insight}
                      </p>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Tab: Differential */}
            {tab === "differential" &&
              (result?.differential_findings?.length || diffResult) && (
                <div className="space-y-4">
                  {diffResult && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {Object.entries(diffResult.findings_by_type).map(
                        ([type, count]) => (
                          <div
                            key={type}
                            className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3"
                          >
                            <p className="text-xs text-amber-300 font-mono">
                              {type}
                            </p>
                            <p className="text-lg font-bold text-zinc-200">
                              {count}
                            </p>
                          </div>
                        ),
                      )}
                    </div>
                  )}
                  <div className="space-y-3">
                    {(
                      result?.differential_findings ??
                      diffResult?.differential_findings ??
                      []
                    ).map((df: any, i: number) => (
                      <div
                        key={i}
                        className={`border rounded-xl p-4 space-y-2 ${getSevColor(df.severity || "medium")}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono text-amber-400">
                              {df.diff_type || df.type}
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSevColor(df.severity || "medium")}`}
                            >
                              {df.severity || "medium"}
                            </span>
                          </div>
                          <span className="text-xs text-zinc-500">
                            {df.function_name || df.function || ""}
                          </span>
                        </div>
                        <p className="text-sm">
                          {df.description || "Behavioral divergence detected"}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            {/* Tab: Property Violations */}
            {tab === "properties" &&
              (result?.property_violations?.length || propertyResult) && (
                <div className="space-y-4">
                  {propertyResult && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {Object.entries(propertyResult.violations_by_type).map(
                        ([type, count]) => (
                          <div
                            key={type}
                            className="bg-pink-500/10 border border-pink-500/20 rounded-lg p-3"
                          >
                            <p className="text-xs text-pink-300 font-mono">
                              {type}
                            </p>
                            <p className="text-lg font-bold text-zinc-200">
                              {count}
                            </p>
                          </div>
                        ),
                      )}
                    </div>
                  )}
                  <div className="space-y-3">
                    {(
                      result?.property_violations ??
                      propertyResult?.property_violations ??
                      []
                    ).map((pv: any, i: number) => (
                      <div
                        key={i}
                        className={`border rounded-xl p-4 space-y-2 ${getSevColor(pv.severity || "medium")}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono text-pink-400">
                              {pv.property_type || pv.type}
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSevColor(pv.severity || "medium")}`}
                            >
                              {pv.severity || "medium"}
                            </span>
                          </div>
                        </div>
                        <p className="text-sm">
                          {pv.description || "Property violation detected"}
                        </p>
                        {pv.sequence && (
                          <div className="bg-black/20 rounded-lg p-3 text-xs font-mono space-y-1">
                            <p className="text-pink-300 font-medium mb-1">
                              Transaction Sequence:
                            </p>
                            {(pv.sequence as any[])
                              .slice(0, 5)
                              .map((step: any, j: number) => (
                                <p key={j} className="text-zinc-400">
                                  {j + 1}. {step.contract}.{step.function}(
                                  {(step.args || []).join(", ")})
                                </p>
                              ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

            {/* Tab: Symbolic */}
            {tab === "symbolic" && symbolicResult && (
              <div className="space-y-4">
                {Object.keys(symbolicResult.target_coverage).length > 0 && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {Object.entries(symbolicResult.target_coverage).map(
                      ([fn, cov]) => (
                        <CoverageBar key={fn} label={fn} value={cov} />
                      ),
                    )}
                  </div>
                )}
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-indigo-300">
                    Interesting Paths
                  </h3>
                  {(symbolicResult.interesting_paths || []).map(
                    (p: any, i: number) => (
                      <div
                        key={i}
                        className="bg-indigo-500/5 border border-indigo-500/20 rounded-xl p-4 space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono text-indigo-400">
                            {p.function_name || `Path #${i + 1}`}
                          </span>
                          <span
                            className={`text-xs ${p.feasible ? "text-emerald-400" : "text-zinc-500"}`}
                          >
                            {p.feasible ? "Feasible" : "Infeasible"} — depth{" "}
                            {p.depth || 0}
                          </span>
                        </div>
                        {p.path_condition && (
                          <p className="text-xs text-zinc-400 font-mono">
                            {p.path_condition}
                          </p>
                        )}
                      </div>
                    ),
                  )}
                </div>
              </div>
            )}

            {/* Tab: AI Strategies */}
            {tab === "strategies" && result && (
              <div className="space-y-6">
                {result.attack_hypotheses?.length > 0 && (
                  <div className="space-y-3">
                    <h3 className="text-sm font-semibold text-red-300">
                      Attack Hypotheses
                    </h3>
                    {result.attack_hypotheses.map((ah: any, i: number) => (
                      <div
                        key={i}
                        className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium text-red-300">
                            {ah.name}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSevColor(ah.estimated_severity || "medium")}`}
                          >
                            {ah.estimated_severity || "medium"}
                          </span>
                        </div>
                        <p className="text-xs text-zinc-400">
                          {ah.description}
                        </p>
                        {ah.steps?.length > 0 && (
                          <div className="bg-black/20 rounded-lg p-3 text-xs space-y-1">
                            {ah.steps.map((step: string, j: number) => (
                              <p key={j} className="text-zinc-300">
                                {j + 1}. {step}
                              </p>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                {result.llm_strategies?.length > 0 && (
                  <div className="space-y-3">
                    <h3 className="text-sm font-semibold text-violet-300">
                      LLM Mutation Strategies
                    </h3>
                    {result.llm_strategies.map((ls: any, i: number) => (
                      <div
                        key={i}
                        className="bg-violet-500/5 border border-violet-500/20 rounded-xl p-4 space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium text-violet-300">
                            {ls.strategy_name || ls.name}
                          </span>
                          <span className="text-xs text-zinc-500">
                            confidence:{" "}
                            {((ls.confidence || 0) * 100).toFixed(0)}%
                          </span>
                        </div>
                        <p className="text-xs text-zinc-400">
                          {ls.description}
                        </p>
                        {ls.mutation_types?.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {ls.mutation_types.map((mt: string, j: number) => (
                              <span
                                key={j}
                                className="px-2 py-0.5 text-[10px] bg-violet-500/10 border border-violet-500/20 rounded text-violet-300"
                              >
                                {mt}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Tab: Corpus Stats */}
            {tab === "corpus" && result?.corpus_stats && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard
                  label="Total Seeds"
                  value={
                    (result.corpus_stats as any).total_seeds ||
                    result.corpus_size
                  }
                  color="text-zinc-200"
                />
                <StatCard
                  label="Favored Seeds"
                  value={(result.corpus_stats as any).favored_seeds || 0}
                  color="text-emerald-400"
                />
                <StatCard
                  label="Power Schedule"
                  value={result.power_schedule.toUpperCase()}
                  color="text-violet-400"
                />
                <StatCard
                  label="Phase"
                  value={(result.corpus_stats as any).phase || "explore"}
                  color="text-cyan-400"
                />
                <StatCard
                  label="Avg Energy"
                  value={((result.corpus_stats as any).avg_energy || 0).toFixed(
                    2,
                  )}
                  color="text-yellow-400"
                />
                <StatCard
                  label="Plateaus"
                  value={
                    (result.corpus_stats as any).coverage_plateau_count || 0
                  }
                  color="text-orange-400"
                />
                <StatCard
                  label="Crossovers"
                  value={(result.corpus_stats as any).genetic_crossovers || 0}
                  color="text-fuchsia-400"
                />
                <StatCard
                  label="Seeds Trimmed"
                  value={(result.corpus_stats as any).seeds_trimmed || 0}
                  color="text-indigo-400"
                />
              </div>
            )}

            {/* Tab: Taint Analysis */}
            {tab === "taint" && result?.taint_flows && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <StatCard
                    label="Taint Flows"
                    value={result.taint_flows.length}
                    color="text-rose-400"
                  />
                  <StatCard
                    label="Mutation Targets"
                    value={result.taint_mutation_targets?.length || 0}
                    color="text-fuchsia-400"
                  />
                  <StatCard
                    label="Critical Flows"
                    value={
                      result.taint_flows.filter(
                        (f: any) => f.criticality === "critical",
                      ).length
                    }
                    color="text-red-400"
                  />
                </div>
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-rose-300">
                    Sensitive Dataflows
                  </h3>
                  {result.taint_flows
                    .slice(0, 20)
                    .map((flow: any, i: number) => (
                      <div
                        key={i}
                        className={`border rounded-xl p-4 space-y-2 ${getSevColor(flow.criticality || "medium")}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono text-rose-400">
                              {flow.source?.type || "source"} →{" "}
                              {flow.sink?.type || "sink"}
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSevColor(flow.criticality || "medium")}`}
                            >
                              {flow.criticality || "medium"}
                            </span>
                          </div>
                        </div>
                        <p className="text-xs text-zinc-400 font-mono">
                          {flow.source?.param || "?"} →{" "}
                          {(flow.path || []).join(" → ")} →{" "}
                          {flow.sink?.location || "?"}
                        </p>
                      </div>
                    ))}
                </div>
                {(result.taint_mutation_targets?.length || 0) > 0 && (
                  <div className="space-y-3">
                    <h3 className="text-sm font-semibold text-fuchsia-300">
                      Taint Mutation Targets
                    </h3>
                    {result.taint_mutation_targets
                      .slice(0, 10)
                      .map((t: any, i: number) => (
                        <div
                          key={i}
                          className="bg-fuchsia-500/5 border border-fuchsia-500/20 rounded-xl p-4 space-y-2"
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-mono text-fuchsia-300">
                              {t.function}.{t.param}
                            </span>
                            <span className="text-xs text-zinc-500">
                              priority: {t.priority}
                            </span>
                          </div>
                          {t.mutations?.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {t.mutations.map((m: string, j: number) => (
                                <span
                                  key={j}
                                  className="px-2 py-0.5 text-[10px] bg-fuchsia-500/10 border border-fuchsia-500/20 rounded text-fuchsia-300"
                                >
                                  {m}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                  </div>
                )}
              </div>
            )}

            {/* Tab: Exploit Chains */}
            {tab === "exploits" && result?.exploit_chains && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <StatCard
                    label="Exploit Chains"
                    value={result.exploit_chains.length}
                    color="text-red-400"
                  />
                  <StatCard
                    label="High Feasibility"
                    value={
                      result.exploit_chains.filter(
                        (c: any) => c.feasibility >= 0.8,
                      ).length
                    }
                    sub="≥80% feasible"
                    color="text-orange-400"
                  />
                  <StatCard
                    label="With PoC"
                    value={
                      result.exploit_chains.filter((c: any) => c.poc_code)
                        .length
                    }
                    color="text-emerald-400"
                  />
                </div>
                <div className="space-y-3">
                  {result.exploit_chains.map((chain: any, i: number) => (
                    <div
                      key={i}
                      className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 space-y-3"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-red-300">
                            {chain.goal || `Chain #${i + 1}`}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-bold ${chain.feasibility >= 0.8 ? "text-red-400 bg-red-500/10" : chain.feasibility >= 0.5 ? "text-orange-400 bg-orange-500/10" : "text-zinc-400 bg-zinc-500/10"}`}
                          >
                            {(chain.feasibility * 100).toFixed(0)}% feasible
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          {chain.poc_code && (
                            <span className="text-xs text-emerald-400">
                              PoC
                            </span>
                          )}
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSevColor(chain.impact || "high")}`}
                          >
                            {chain.impact || "high"}
                          </span>
                        </div>
                      </div>
                      {chain.steps?.length > 0 && (
                        <div className="bg-black/20 rounded-lg p-3 text-xs space-y-1">
                          <p className="text-red-300 font-medium mb-1">
                            Attack Steps:
                          </p>
                          {chain.steps.map((step: any, j: number) => (
                            <p key={j} className="text-zinc-300">
                              {j + 1}. {step.action || step.description || step}
                            </p>
                          ))}
                        </div>
                      )}
                      {chain.primitives?.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {chain.primitives.map((p: string, j: number) => (
                            <span
                              key={j}
                              className="px-2 py-0.5 text-[10px] bg-red-500/10 border border-red-500/20 rounded text-red-300"
                            >
                              {p}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tab: Gas Profile / DoS Vectors */}
            {tab === "gas" && result?.dos_vectors && (
              <div className="space-y-4">
                {result.gas_profile && (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <StatCard
                      label="DoS Vectors"
                      value={result.dos_vectors.length}
                      color="text-orange-400"
                    />
                    <StatCard
                      label="Gas Sampled"
                      value={(result.gas_profile as any).total_gas_sampled || 0}
                      color="text-yellow-400"
                    />
                    <StatCard
                      label="Anomalies"
                      value={(result.gas_profile as any).anomaly_count || 0}
                      color="text-red-400"
                    />
                  </div>
                )}
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-orange-300">
                    DoS Vectors
                  </h3>
                  {result.dos_vectors.map((vec: any, i: number) => (
                    <div
                      key={i}
                      className={`border rounded-xl p-4 space-y-2 ${getSevColor(vec.severity || "medium")}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-orange-400">
                            {vec.type}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSevColor(vec.severity || "medium")}`}
                          >
                            {vec.severity || "medium"}
                          </span>
                        </div>
                        <span className="text-xs text-zinc-500">
                          {vec.function}
                        </span>
                      </div>
                      <p className="text-sm">{vec.description}</p>
                      <div className="flex items-center gap-4 text-xs text-zinc-500">
                        <span>
                          Est. gas:{" "}
                          <code className="text-zinc-300">
                            {Number(vec.estimated_gas).toLocaleString()}
                          </code>
                        </span>
                        <span>
                          Worst case:{" "}
                          <code className="text-red-300">
                            {Number(vec.worst_case_gas).toLocaleString()}
                          </code>
                        </span>
                      </div>
                      {vec.mitigation && (
                        <div className="bg-black/20 rounded-lg p-3 text-xs">
                          <p className="text-emerald-400 font-medium mb-1">
                            Mitigation
                          </p>
                          <p className="text-zinc-300">{vec.mitigation}</p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>
        )}

        {/* Protocol Info Footer */}
        <section className="border-t border-zinc-800/60 pt-8 mt-12">
          <div className="grid grid-cols-3 md:grid-cols-7 gap-4 text-center text-xs text-zinc-500">
            <div>
              <p className="text-zinc-300 font-bold">Nullifier</p>
              <p>4 detectors</p>
            </div>
            <div>
              <p className="text-zinc-300 font-bold">ZK Proof</p>
              <p>5 detectors</p>
            </div>
            <div>
              <p className="text-zinc-300 font-bold">Bridge</p>
              <p>5 detectors</p>
            </div>
            <div>
              <p className="text-zinc-300 font-bold">Privacy</p>
              <p>5 detectors</p>
            </div>
            <div>
              <p className="text-zinc-300 font-bold">Access Ctrl</p>
              <p>4 detectors</p>
            </div>
            <div>
              <p className="text-zinc-300 font-bold">Economic</p>
              <p>5 detectors</p>
            </div>
            <div>
              <p className="text-violet-400 font-bold">13 Engines</p>
              <p>18 phases</p>
            </div>
          </div>
          <p className="text-center text-xs text-zinc-600 mt-6">
            ZASEON Soul Fuzzer — Advanced mutation-feedback fuzzer with
            symbolic, concolic, differential, taint, exploit chain, gas
            profiling, and LLM-guided analysis for{" "}
            <a
              href="https://github.com/Soul-Research-Labs/SOUL"
              className="text-violet-500 hover:text-violet-400"
              target="_blank"
              rel="noopener noreferrer"
            >
              Soul Protocol
            </a>
          </p>
        </section>
      </main>
    </div>
  );
}
