"use client";

import { useState } from "react";
import { Header } from "@/components/layout/header";
import {
  cn,
  CHAINS,
  severityBg,
  scoreColor,
  scoreGrade,
  formatDuration,
} from "@/lib/utils";
import { quickScanAddress, quickScanSource, deepScan } from "@/lib/api";
import type { QuickScanResult, Finding, AnalysisMetadata } from "@/types";
import {
  Zap,
  FileCode,
  Globe,
  Shield,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Loader2,
  Copy,
  Check,
  Brain,
  Activity,
  GitBranch,
  Lock,
  Flame,
} from "lucide-react";

type Tab = "address" | "source";

export default function QuickScanPage() {
  const [tab, setTab] = useState<Tab>("address");
  const [address, setAddress] = useState("");
  const [chain, setChain] = useState("ethereum");
  const [sourceCode, setSourceCode] = useState("");
  const [contractName, setContractName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<QuickScanResult | null>(null);
  const [deepMode, setDeepMode] = useState(false);

  async function handleScan() {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let res: QuickScanResult;

      if (deepMode) {
        // Deep scan with LLM analysis
        const params =
          tab === "address"
            ? { contract_address: address, chain }
            : {
                source_code: sourceCode,
                filename: contractName || "Contract.sol",
              };
        res = await deepScan(params);
      } else if (tab === "address") {
        if (!address.match(/^0x[a-fA-F0-9]{40}$/)) {
          throw new Error("Invalid contract address");
        }
        res = await quickScanAddress(address, chain);
      } else {
        if (!sourceCode.trim()) {
          throw new Error("Please enter Solidity source code");
        }
        res = await quickScanSource(sourceCode, contractName);
      }
      setResult(res);
    } catch (err: any) {
      setError(
        err?.response?.data?.detail ||
          err.message ||
          "Scan failed. Please try again.",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <Header title="QuickScan" />

      <div className="p-6 space-y-6 max-w-5xl mx-auto">
        {/* Tab Selection */}
        <div className="flex gap-2">
          <button
            onClick={() => setTab("address")}
            className={cn(
              "flex items-center gap-2 rounded-lg px-5 py-2.5 text-sm font-medium transition",
              tab === "address"
                ? "bg-primary text-primary-foreground"
                : "bg-secondary text-muted-foreground hover:text-foreground",
            )}
          >
            <Globe className="h-4 w-4" />
            Contract Address
          </button>
          <button
            onClick={() => setTab("source")}
            className={cn(
              "flex items-center gap-2 rounded-lg px-5 py-2.5 text-sm font-medium transition",
              tab === "source"
                ? "bg-primary text-primary-foreground"
                : "bg-secondary text-muted-foreground hover:text-foreground",
            )}
          >
            <FileCode className="h-4 w-4" />
            Paste Source Code
          </button>
        </div>

        {/* Input Section */}
        <div className="rounded-xl border border-border bg-card p-6">
          {tab === "address" ? (
            <div className="space-y-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium">
                  Contract Address
                </label>
                <input
                  type="text"
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  placeholder="0x1234...abcd"
                  className="w-full rounded-lg border border-border bg-background px-4 py-3 font-mono text-sm outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium">
                  Chain
                </label>
                <div className="grid grid-cols-4 gap-2">
                  {Object.entries(CHAINS).map(([id, c]) => (
                    <button
                      key={id}
                      onClick={() => setChain(id)}
                      className={cn(
                        "flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition",
                        chain === id
                          ? "border-primary bg-primary/10 text-primary"
                          : "border-border hover:border-muted-foreground",
                      )}
                    >
                      <span>{c.icon}</span>
                      <span>{c.name}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium">
                  Contract Name (optional)
                </label>
                <input
                  type="text"
                  value={contractName}
                  onChange={(e) => setContractName(e.target.value)}
                  placeholder="MyContract"
                  className="w-full rounded-lg border border-border bg-background px-4 py-2.5 text-sm outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium">
                  Solidity Source Code
                </label>
                <textarea
                  value={sourceCode}
                  onChange={(e) => setSourceCode(e.target.value)}
                  placeholder="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\ncontract MyContract {\n    ...\n}"
                  rows={16}
                  className="w-full rounded-lg border border-border bg-background px-4 py-3 font-mono text-sm outline-none focus:border-primary focus:ring-1 focus:ring-primary resize-none"
                />
              </div>
            </div>
          )}

          <div className="mt-5 flex items-center gap-4">
            <label className="flex items-center gap-2.5 cursor-pointer group">
              <div
                className={cn(
                  "relative h-6 w-11 rounded-full transition-colors",
                  deepMode ? "bg-purple-600" : "bg-secondary",
                )}
                onClick={() => setDeepMode(!deepMode)}
              >
                <div
                  className={cn(
                    "absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform shadow-sm",
                    deepMode ? "translate-x-5" : "translate-x-0.5",
                  )}
                />
              </div>
              <div>
                <span className="text-sm font-medium flex items-center gap-1.5">
                  <Brain className="h-3.5 w-3.5 text-purple-400" />
                  Deep Scan (AI)
                </span>
                <span className="text-xs text-muted-foreground block">
                  LLM analysis + PoC verification · slower but more thorough
                </span>
              </div>
            </label>
          </div>

          <button
            onClick={handleScan}
            disabled={loading}
            className={cn(
              "mt-4 flex w-full items-center justify-center gap-2 rounded-lg px-6 py-3 text-sm font-semibold text-primary-foreground transition disabled:opacity-50",
              deepMode
                ? "bg-purple-600 hover:bg-purple-700"
                : "bg-primary hover:bg-primary/90",
            )}
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                {deepMode ? "Running Deep Analysis..." : "Scanning..."}
              </>
            ) : (
              <>
                {deepMode ? (
                  <Brain className="h-4 w-4" />
                ) : (
                  <Zap className="h-4 w-4" />
                )}
                {deepMode ? "Deep Scan" : "Scan Now"}
              </>
            )}
          </button>

          {error && (
            <div className="mt-4 rounded-lg bg-destructive/10 border border-destructive/20 px-4 py-3 text-sm text-red-400">
              {error}
            </div>
          )}
        </div>

        {/* Results */}
        {result && <ScanResults result={result} />}
      </div>
    </div>
  );
}

function ScanResults({ result }: { result: QuickScanResult }) {
  const grade = scoreGrade(result.security_score);
  const analysis = result.analysis;

  return (
    <div className="space-y-6">
      {/* Score Overview */}
      <div className="grid grid-cols-4 gap-4">
        <div className="col-span-1 rounded-xl border border-border bg-card p-6 flex flex-col items-center justify-center">
          <svg className="h-28 w-28" viewBox="0 0 100 100">
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke="hsl(var(--secondary))"
              strokeWidth="8"
            />
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke={
                result.security_score >= 80
                  ? "#16a34a"
                  : result.security_score >= 60
                    ? "#ca8a04"
                    : "#dc2626"
              }
              strokeWidth="8"
              strokeDasharray={`${(result.security_score / 100) * 283} 283`}
              strokeLinecap="round"
              transform="rotate(-90 50 50)"
              className="score-ring"
            />
            <text
              x="50"
              y="45"
              textAnchor="middle"
              className="fill-foreground text-2xl font-bold"
              fontSize="24"
              fontWeight="bold"
            >
              {result.security_score}
            </text>
            <text
              x="50"
              y="62"
              textAnchor="middle"
              className="fill-muted-foreground"
              fontSize="12"
            >
              Grade {grade}
            </text>
          </svg>
        </div>
        <div className="col-span-3 grid grid-cols-3 gap-4">
          <MiniStat label="Total Findings" value={result.findings.length} />
          <MiniStat
            label="Critical"
            value={
              result.findings.filter((f) => f.severity === "CRITICAL").length
            }
            valueClass="text-critical"
          />
          <MiniStat
            label="High"
            value={result.findings.filter((f) => f.severity === "HIGH").length}
            valueClass="text-high"
          />
          <MiniStat label="Lines Scanned" value={result.lines_of_code} />
          <MiniStat
            label="Duration"
            value={formatDuration(result.scan_duration_ms / 1000)}
            isString
          />
          <MiniStat
            label="Gas Optimizations"
            value={result.gas_optimizations.length}
            valueClass="text-purple-400"
          />
        </div>
      </div>

      {/* Analysis Pipeline */}
      {analysis && (
        <div className="rounded-xl border border-border bg-card">
          <div className="border-b border-border px-5 py-4">
            <h2 className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              Analysis Pipeline
            </h2>
          </div>
          <div className="p-5">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <PipelineStat
                icon={<Shield className="h-4 w-4" />}
                label="Static Detectors"
                value={analysis.static_findings_count}
                sublabel="findings"
              />
              {(analysis.ast_findings_count ?? 0) > 0 && (
                <PipelineStat
                  icon={<GitBranch className="h-4 w-4" />}
                  label="AST + CFG Analysis"
                  value={analysis.ast_findings_count!}
                  sublabel="findings"
                />
              )}
              {(analysis.slither_findings_count ?? 0) > 0 && (
                <PipelineStat
                  icon={<Lock className="h-4 w-4" />}
                  label="Slither"
                  value={analysis.slither_findings_count!}
                  sublabel="findings"
                />
              )}
              {analysis.llm_findings_count > 0 && (
                <PipelineStat
                  icon={<Brain className="h-4 w-4 text-purple-400" />}
                  label="LLM Deep Analysis"
                  value={analysis.llm_findings_count}
                  sublabel="findings"
                />
              )}
              <PipelineStat
                icon={<Flame className="h-4 w-4 text-amber-400" />}
                label="After Dedup"
                value={analysis.total_after_dedup}
                sublabel="unique findings"
              />
            </div>

            {/* Taint & Call Graph Stats */}
            {(analysis.taint_flows_detected || analysis.call_graph_stats) && (
              <div className="mt-4 pt-4 border-t border-border">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                  {analysis.taint_flows_detected !== undefined && (
                    <div className="rounded-lg bg-background p-3">
                      <span className="text-muted-foreground">Taint Flows</span>
                      <p className="text-lg font-semibold">
                        {analysis.taint_flows_detected}
                      </p>
                    </div>
                  )}
                  {analysis.reentrancy_paths_detected !== undefined && (
                    <div className="rounded-lg bg-background p-3">
                      <span className="text-muted-foreground">
                        Reentrancy Paths
                      </span>
                      <p className="text-lg font-semibold">
                        {analysis.reentrancy_paths_detected}
                      </p>
                    </div>
                  )}
                  {analysis.call_graph_stats && (
                    <>
                      <div className="rounded-lg bg-background p-3">
                        <span className="text-muted-foreground">
                          Entry Points
                        </span>
                        <p className="text-lg font-semibold">
                          {analysis.call_graph_stats.entry_points}
                        </p>
                      </div>
                      <div className="rounded-lg bg-background p-3">
                        <span className="text-muted-foreground">
                          External Calls
                        </span>
                        <p className="text-lg font-semibold">
                          {analysis.call_graph_stats.external_calls}
                        </p>
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* LLM Risk Assessment */}
            {analysis.llm_overall_risk && (
              <div className="mt-4 pt-4 border-t border-border">
                <div className="flex items-center gap-2 mb-2">
                  <Brain className="h-4 w-4 text-purple-400" />
                  <span className="text-xs font-medium text-purple-400">
                    AI Risk Assessment
                  </span>
                </div>
                <p className="text-sm text-muted-foreground">
                  {analysis.llm_overall_risk}
                </p>
              </div>
            )}
            {analysis.llm_contract_summary && (
              <div className="mt-3">
                <p className="text-xs text-muted-foreground">
                  {analysis.llm_contract_summary}
                </p>
              </div>
            )}

            {/* Findings by Category */}
            {analysis.findings_by_category &&
              Object.keys(analysis.findings_by_category).length > 0 && (
                <div className="mt-4 pt-4 border-t border-border">
                  <p className="text-xs font-medium mb-2">
                    Findings by Category
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(analysis.findings_by_category)
                      .sort(([, a], [, b]) => b - a)
                      .map(([cat, count]) => (
                        <span
                          key={cat}
                          className="rounded-full bg-background border border-border px-2.5 py-1 text-[11px]"
                        >
                          {cat}: <strong>{count}</strong>
                        </span>
                      ))}
                  </div>
                </div>
              )}
          </div>
        </div>
      )}

      {/* Findings List */}
      <div className="rounded-xl border border-border bg-card">
        <div className="border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold">
            Findings ({result.findings.length})
          </h2>
        </div>
        <div className="divide-y divide-border">
          {result.findings.length === 0 ? (
            <div className="px-5 py-10 text-center text-muted-foreground">
              <Shield className="mx-auto h-10 w-10 mb-3 text-safe" />
              <p className="font-medium">No vulnerabilities found!</p>
              <p className="text-sm mt-1">Your contract looks secure.</p>
            </div>
          ) : (
            result.findings.map((finding, idx) => (
              <FindingCard key={idx} finding={finding} />
            ))
          )}
        </div>
      </div>

      {/* Gas Optimizations */}
      {result.gas_optimizations.length > 0 && (
        <div className="rounded-xl border border-border bg-card">
          <div className="border-b border-border px-5 py-4">
            <h2 className="text-sm font-semibold">
              ⛽ Gas Optimizations ({result.gas_optimizations.length})
            </h2>
          </div>
          <div className="divide-y divide-border">
            {result.gas_optimizations.map((opt, idx) => (
              <div key={idx} className="px-5 py-3.5">
                <p className="text-sm font-medium">{opt.description}</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {opt.suggestion}
                </p>
                {opt.estimated_gas_saved > 0 && (
                  <span className="mt-1 inline-block text-xs text-purple-400">
                    ~{opt.estimated_gas_saved} gas saved
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="px-5 py-4">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-start gap-3 text-left"
      >
        {expanded ? (
          <ChevronDown className="mt-0.5 h-4 w-4 shrink-0" />
        ) : (
          <ChevronRight className="mt-0.5 h-4 w-4 shrink-0" />
        )}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "rounded border px-2 py-0.5 text-[10px] font-semibold uppercase",
                severityBg(finding.severity),
              )}
            >
              {finding.severity}
            </span>
            <span className="text-sm font-medium truncate">
              {finding.title}
            </span>
            {finding.verified && (
              <span className="rounded bg-safe/10 px-1.5 py-0.5 text-[10px] font-medium text-safe border border-safe/20">
                ✓ Verified
              </span>
            )}
          </div>
          <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
            <span>
              {finding.location.file}:{finding.location.start_line}
            </span>
            {finding.cwe_id && <span>{finding.cwe_id}</span>}
            {finding.scwe_id && <span>{finding.scwe_id}</span>}
            <span>{Math.round(finding.confidence * 100)}% confidence</span>
          </div>
        </div>
      </button>

      {expanded && (
        <div className="ml-7 mt-3 space-y-3">
          <p className="text-sm text-muted-foreground">{finding.description}</p>

          {finding.location.snippet && (
            <div className="rounded-lg bg-background border border-border p-3 font-mono text-xs overflow-x-auto">
              <pre>{finding.location.snippet}</pre>
            </div>
          )}

          {finding.remediation && (
            <div className="rounded-lg bg-safe/5 border border-safe/20 p-3">
              <p className="text-xs font-medium text-safe mb-1">Remediation</p>
              <p className="text-xs text-muted-foreground">
                {finding.remediation}
              </p>
            </div>
          )}

          {finding.proof_of_concept && (
            <div className="rounded-lg bg-background border border-border p-3">
              <p className="text-xs font-medium text-primary mb-1">
                Proof of Concept
              </p>
              <pre className="font-mono text-xs overflow-x-auto">
                {finding.proof_of_concept}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MiniStat({
  label,
  value,
  valueClass,
  isString,
}: {
  label: string;
  value: number | string;
  valueClass?: string;
  isString?: boolean;
}) {
  return (
    <div className="rounded-lg border border-border bg-card/50 p-4">
      <p className="text-xs text-muted-foreground uppercase tracking-wider">
        {label}
      </p>
      <p className={cn("mt-1 text-2xl font-bold", valueClass)}>{value}</p>
    </div>
  );
}

function PipelineStat({
  icon,
  label,
  value,
  sublabel,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  sublabel: string;
}) {
  return (
    <div className="rounded-lg bg-background border border-border p-3 flex items-center gap-3">
      <div className="rounded-full bg-primary/10 p-2 text-primary">{icon}</div>
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-lg font-semibold">
          {value}{" "}
          <span className="text-xs font-normal text-muted-foreground">
            {sublabel}
          </span>
        </p>
      </div>
    </div>
  );
}
