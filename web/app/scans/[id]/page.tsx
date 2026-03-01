"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { getScan, getFindings } from "@/lib/api";
import { Header } from "@/components/layout/header";
import { cn, scoreColor, scoreGrade, severityBg } from "@/lib/utils";
import {
  Shield,
  Clock,
  Bug,
  AlertTriangle,
  FileCode,
  ArrowUpRight,
  Loader2,
  Activity,
} from "lucide-react";
import Link from "next/link";
import type { Severity } from "@/types";

const SEVERITY_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
  "GAS",
];

function severityClass(severity: string) {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "text-red-600 bg-red-50 border-red-200 dark:text-red-400 dark:bg-red-900/20 dark:border-red-900/40";
    case "HIGH":
      return "text-orange-600 bg-orange-50 border-orange-200 dark:text-orange-400 dark:bg-orange-900/20 dark:border-orange-900/40";
    case "MEDIUM":
      return "text-yellow-600 bg-yellow-50 border-yellow-200 dark:text-yellow-400 dark:bg-yellow-900/20 dark:border-yellow-900/40";
    case "LOW":
      return "text-blue-600 bg-blue-50 border-blue-200 dark:text-blue-400 dark:bg-blue-900/20 dark:border-blue-900/40";
    default:
      return "text-gray-600 bg-gray-50 border-gray-200 dark:text-gray-400 dark:bg-gray-900/20";
  }
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => getScan(id),
    refetchInterval: (query) => {
      const s = query.state.data;
      return s && (s.status === "COMPLETED" || s.status === "FAILED")
        ? false
        : 5_000;
    },
  });

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ["findings", id],
    queryFn: () => getFindings({ scan_id: id }),
    enabled: scan?.status === "COMPLETED",
  });

  if (scanLoading) {
    return (
      <div>
        <Header title="Scan Details" />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div>
        <Header title="Scan Details" />
        <div className="flex flex-col items-center justify-center h-64 gap-3">
          <AlertTriangle className="h-8 w-8 text-muted-foreground" />
          <p className="text-muted-foreground">Scan not found</p>
          <Link href="/scans" className="text-primary hover:underline text-sm">
            Back to scans
          </Link>
        </div>
      </div>
    );
  }

  const isRunning = !["COMPLETED", "FAILED"].includes(scan.status);

  // Severity summary
  const sevCounts: Record<string, number> = {};
  (findings || []).forEach((f) => {
    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
  });

  return (
    <div>
      <Header title={`Scan ${scan.id.slice(0, 8)}`} />

      <div className="p-6 space-y-6">
        {/* Summary Cards */}
        <div className="grid grid-cols-4 gap-4">
          <div className="rounded-xl border border-border bg-card p-5">
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Status
            </div>
            <div className="mt-2 flex items-center gap-2">
              {isRunning ? (
                <Activity className="h-5 w-5 text-primary animate-pulse" />
              ) : scan.status === "COMPLETED" ? (
                <Shield className="h-5 w-5 text-green-500" />
              ) : (
                <AlertTriangle className="h-5 w-5 text-red-500" />
              )}
              <span className="text-lg font-bold">{scan.status}</span>
            </div>
          </div>
          <div className="rounded-xl border border-border bg-card p-5">
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Score
            </div>
            <div
              className={cn(
                "mt-2 text-3xl font-bold",
                scan.security_score != null
                  ? scoreColor(scan.security_score)
                  : "text-muted-foreground",
              )}
            >
              {scan.security_score != null
                ? Math.round(scan.security_score)
                : "—"}
              {scan.security_score != null && (
                <span className="text-lg text-muted-foreground">/100</span>
              )}
            </div>
            {scan.security_score != null && (
              <p className="mt-1 text-xs text-muted-foreground">
                Grade {scoreGrade(scan.security_score)}
              </p>
            )}
          </div>
          <div className="rounded-xl border border-border bg-card p-5">
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Findings
            </div>
            <div className="mt-2 text-3xl font-bold">{scan.findings_count}</div>
            <div className="mt-1 flex gap-1.5 text-xs">
              {SEVERITY_ORDER.map((sev) =>
                sevCounts[sev] ? (
                  <span
                    key={sev}
                    className={cn(
                      "rounded px-1 py-0.5 font-medium",
                      severityClass(sev),
                    )}
                  >
                    {sevCounts[sev]}
                    {sev[0]}
                  </span>
                ) : null,
              )}
            </div>
          </div>
          <div className="rounded-xl border border-border bg-card p-5">
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Lines Scanned
            </div>
            <div className="mt-2 text-3xl font-bold">
              {scan.total_lines_scanned.toLocaleString()}
            </div>
            <div className="mt-1 text-xs text-muted-foreground">
              <Clock className="inline h-3 w-3 mr-1" />
              {new Date(scan.created_at).toLocaleString()}
            </div>
          </div>
        </div>

        {/* Findings Table */}
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <div className="border-b border-border px-5 py-4">
            <h3 className="text-sm font-semibold">Findings</h3>
          </div>
          {isRunning ? (
            <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
              Scan in progress&hellip;
            </div>
          ) : findingsLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : !findings || findings.length === 0 ? (
            <div className="px-5 py-16 text-center text-sm text-muted-foreground">
              {scan.status === "COMPLETED"
                ? "No findings detected — looking great!"
                : "Scan did not complete."}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-secondary/50">
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Finding
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Location
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {findings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="hover:bg-secondary/30 transition"
                  >
                    <td className="px-5 py-3.5">
                      <span
                        className={cn(
                          "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
                          severityClass(finding.severity),
                        )}
                      >
                        {finding.severity}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="font-medium">{finding.title}</div>
                      {finding.category && (
                        <span className="text-xs text-muted-foreground">
                          {finding.category}
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3.5 text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <FileCode className="h-3.5 w-3.5" />
                        <span className="font-mono text-xs">
                          {finding.location.file}:{finding.location.start_line}
                        </span>
                      </div>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="text-xs capitalize">
                        {finding.status.toLowerCase().replace("_", " ")}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <Link
                        href={`/findings/${finding.id}`}
                        className="text-primary hover:underline"
                      >
                        <ArrowUpRight className="h-4 w-4" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
