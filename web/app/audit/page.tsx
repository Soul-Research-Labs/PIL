"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { cn } from "@/lib/utils";
import {
  ScrollText,
  ShieldCheck,
  Filter,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  BarChart3,
} from "lucide-react";
import { getAuditLogs, getAuditSummary, getComplianceReport } from "@/lib/api";
import type {
  AuditLogEntry,
  AuditSummary,
  ComplianceReport,
  AuditSeverity,
} from "@/types";

type AuditTab = "logs" | "compliance";

const SEVERITY_COLORS: Record<AuditSeverity, string> = {
  info: "bg-blue-500/10 text-blue-500",
  notice: "bg-cyan-500/10 text-cyan-500",
  warning: "bg-yellow-500/10 text-yellow-500",
  critical: "bg-red-500/10 text-red-500",
};

export default function AuditPage() {
  const [tab, setTab] = useState<AuditTab>("logs");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [actionFilter, setActionFilter] = useState<string>("");

  // ── Queries ───────────────────────────────────────────────────────────────

  const { data: logs = [], isLoading: logsLoading } = useQuery({
    queryKey: ["audit-logs", severityFilter, actionFilter],
    queryFn: () =>
      getAuditLogs({
        ...(severityFilter ? { severity: severityFilter } : {}),
        ...(actionFilter ? { action: actionFilter } : {}),
        limit: 100,
      }),
    enabled: tab === "logs",
  });

  const { data: summary } = useQuery<AuditSummary>({
    queryKey: ["audit-summary"],
    queryFn: () => getAuditSummary(),
    enabled: tab === "logs",
  });

  const { data: compliance, isLoading: complianceLoading } =
    useQuery<ComplianceReport>({
      queryKey: ["compliance-report"],
      queryFn: getComplianceReport,
      enabled: tab === "compliance",
    });

  // ── Loading ───────────────────────────────────────────────────────────────

  const isLoading = tab === "logs" ? logsLoading : complianceLoading;

  return (
    <div>
      <Header title="Audit & Compliance" />
      <div className="p-6 max-w-6xl mx-auto space-y-6">
        {/* Tab switcher */}
        <div className="flex gap-1 rounded-md bg-muted p-1 w-fit">
          {(
            [
              { id: "logs", label: "Audit Log", icon: ScrollText },
              { id: "compliance", label: "Compliance", icon: ShieldCheck },
            ] as const
          ).map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-sm px-3 py-1.5 text-sm font-medium transition",
                tab === id
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" /> {label}
            </button>
          ))}
        </div>

        {isLoading && (
          <div className="flex items-center justify-center h-48">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        )}

        {/* ── Audit logs tab ───────────────────────────────────────────── */}
        {tab === "logs" && !logsLoading && (
          <>
            {/* Summary cards */}
            {summary && (
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <SummaryCard
                  label="Total Events"
                  value={summary.total_events}
                  icon={BarChart3}
                />
                <SummaryCard
                  label="Critical"
                  value={summary.by_severity?.critical ?? 0}
                  icon={AlertTriangle}
                  className="text-red-500"
                />
                <SummaryCard
                  label="Warning"
                  value={summary.by_severity?.warning ?? 0}
                  icon={Clock}
                  className="text-yellow-500"
                />
                <SummaryCard
                  label="Info"
                  value={summary.by_severity?.info ?? 0}
                  icon={CheckCircle2}
                  className="text-blue-500"
                />
              </div>
            )}

            {/* Filters */}
            <div className="flex items-center gap-3">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="rounded-md border bg-background px-2 py-1.5 text-sm"
              >
                <option value="">All severities</option>
                <option value="critical">Critical</option>
                <option value="warning">Warning</option>
                <option value="info">Info</option>
              </select>
              <input
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                placeholder="Filter by action…"
                className="rounded-md border bg-background px-3 py-1.5 text-sm w-52"
              />
            </div>

            {/* Log entries */}
            <div className="rounded-lg border bg-card overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground bg-muted/40">
                    <th className="p-3 font-medium">Timestamp</th>
                    <th className="p-3 font-medium">Action</th>
                    <th className="p-3 font-medium">Actor</th>
                    <th className="p-3 font-medium">Resource</th>
                    <th className="p-3 font-medium">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length === 0 ? (
                    <tr>
                      <td
                        colSpan={5}
                        className="p-8 text-center text-muted-foreground"
                      >
                        No audit log entries found.
                      </td>
                    </tr>
                  ) : (
                    logs.map((entry: AuditLogEntry) => (
                      <tr
                        key={entry.id}
                        className="border-b last:border-0 hover:bg-muted/30"
                      >
                        <td className="p-3 text-muted-foreground whitespace-nowrap">
                          {entry.created_at
                            ? new Date(entry.created_at).toLocaleString()
                            : "—"}
                        </td>
                        <td className="p-3 font-mono text-xs">
                          {entry.action}
                        </td>
                        <td className="p-3">{entry.actor_email || "—"}</td>
                        <td className="p-3 text-muted-foreground">
                          {entry.resource_type}
                          {entry.resource_id && (
                            <span className="ml-1 font-mono text-xs">
                              {entry.resource_id.slice(0, 8)}…
                            </span>
                          )}
                        </td>
                        <td className="p-3">
                          <span
                            className={cn(
                              "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
                              SEVERITY_COLORS[entry.severity] ||
                                "bg-muted text-muted-foreground",
                            )}
                          >
                            {entry.severity}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* ── Compliance tab ───────────────────────────────────────────── */}
        {tab === "compliance" && !complianceLoading && compliance && (
          <>
            {/* Overall status banner */}
            <div
              className={cn(
                "rounded-lg border p-4 flex items-center gap-3",
                compliance.overall_status === "pass"
                  ? "border-green-500/30 bg-green-500/5"
                  : compliance.overall_status === "fail"
                    ? "border-red-500/30 bg-red-500/5"
                    : "border-yellow-500/30 bg-yellow-500/5",
              )}
            >
              {compliance.overall_status === "pass" ? (
                <CheckCircle2 className="h-6 w-6 text-green-500" />
              ) : compliance.overall_status === "fail" ? (
                <XCircle className="h-6 w-6 text-red-500" />
              ) : (
                <AlertTriangle className="h-6 w-6 text-yellow-500" />
              )}
              <div>
                <div className="font-semibold capitalize">
                  Compliance: {compliance.overall_status}
                </div>
                <div className="text-sm text-muted-foreground">
                  {
                    compliance.controls.filter((c) => c.status === "pass")
                      .length
                  }
                  /{compliance.controls.length} controls passing &middot;
                  Generated{" "}
                  {new Date(compliance.generated_at).toLocaleDateString()}
                </div>
              </div>
            </div>

            {/* Controls list */}
            <div className="space-y-3">
              {compliance.controls.map((control) => (
                <div
                  key={control.id}
                  className="rounded-lg border bg-card p-4 flex items-start gap-3"
                >
                  {control.status === "pass" ? (
                    <CheckCircle2 className="h-5 w-5 text-green-500 mt-0.5 shrink-0" />
                  ) : control.status === "fail" ? (
                    <XCircle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                  ) : (
                    <Clock className="h-5 w-5 text-yellow-500 mt-0.5 shrink-0" />
                  )}
                  <div className="min-w-0">
                    <div className="font-medium">{control.name}</div>
                    <div className="text-sm text-muted-foreground">
                      {control.description}
                    </div>
                    <div className="flex gap-2 mt-1">
                      <span className="text-xs text-muted-foreground">
                        {control.category}
                      </span>
                      {control.details && (
                        <span className="text-xs text-muted-foreground">
                          &middot; {control.details}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── Summary card ────────────────────────────────────────────────────────────

function SummaryCard({
  label,
  value,
  icon: Icon,
  className,
}: {
  label: string;
  value: number;
  icon: React.ElementType;
  className?: string;
}) {
  return (
    <div className="rounded-lg border bg-card p-4 flex items-center gap-3">
      <Icon className={cn("h-5 w-5 text-muted-foreground", className)} />
      <div>
        <div className="text-sm text-muted-foreground">{label}</div>
        <div className="text-xl font-bold">{value.toLocaleString()}</div>
      </div>
    </div>
  );
}
