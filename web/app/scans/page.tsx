"use client";

import { Header } from "@/components/layout/header";
import { cn, scoreColor, formatDuration } from "@/lib/utils";
import {
  Activity,
  Check,
  X,
  Clock,
  Filter,
  ArrowUpRight,
  Loader2,
} from "lucide-react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { getScans } from "@/lib/api";

const statusConfig: Record<
  string,
  { icon: React.ReactNode; label: string; class: string }
> = {
  COMPLETED: {
    icon: <Check className="h-3.5 w-3.5" />,
    label: "Completed",
    class: "bg-safe/10 text-safe border-safe/20",
  },
  ANALYZING: {
    icon: <Activity className="h-3.5 w-3.5 animate-pulse" />,
    label: "Scanning",
    class: "bg-primary/10 text-primary border-primary/20",
  },
  PENDING: {
    icon: <Clock className="h-3.5 w-3.5" />,
    label: "Pending",
    class: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  },
  FAILED: {
    icon: <X className="h-3.5 w-3.5" />,
    label: "Failed",
    class: "bg-red-500/10 text-red-400 border-red-500/20",
  },
};

export default function ScansPage() {
  const { data: scans, isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => getScans(),
    refetchInterval: 15_000,
  });

  return (
    <div>
      <Header title="Scan History" />

      <div className="p-6 space-y-6">
        {/* Filters */}
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm hover:bg-secondary transition">
            <Filter className="h-3.5 w-3.5" />
            All Statuses
          </button>
          <div className="flex-1" />
          <span className="text-sm text-muted-foreground">
            {isLoading ? "…" : `${scans?.length ?? 0} scans`}
          </span>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : !scans || scans.length === 0 ? (
          <div className="rounded-xl border border-border bg-card p-12 text-center">
            <Activity className="mx-auto h-10 w-10 text-muted-foreground mb-3" />
            <h3 className="text-sm font-semibold">No scans yet</h3>
            <p className="text-xs text-muted-foreground mt-1">
              Create a project and run your first scan.
            </p>
          </div>
        ) : (
          <div className="rounded-xl border border-border bg-card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-secondary/50">
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Scan
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Score
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Findings
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Lines
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Branch
                  </th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.map((scan) => {
                  const status =
                    statusConfig[scan.status] || statusConfig.PENDING;
                  return (
                    <tr
                      key={scan.id}
                      className="hover:bg-secondary/30 transition"
                    >
                      <td className="px-5 py-4">
                        <div className="font-medium font-mono text-xs">
                          {scan.id.slice(0, 8)}
                        </div>
                        <div className="text-xs text-muted-foreground mt-0.5">
                          {new Date(scan.created_at).toLocaleDateString()}
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <span
                          className={cn(
                            "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
                            status.class,
                          )}
                        >
                          {status.icon}
                          {status.label}
                        </span>
                      </td>
                      <td className="px-5 py-4">
                        {scan.security_score != null ? (
                          <span
                            className={cn(
                              "text-lg font-bold",
                              scoreColor(scan.security_score),
                            )}
                          >
                            {Math.round(scan.security_score)}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-5 py-4">
                        <span className="font-medium">
                          {scan.findings_count}
                        </span>
                      </td>
                      <td className="px-5 py-4 text-muted-foreground">
                        {scan.total_lines_scanned > 0
                          ? scan.total_lines_scanned.toLocaleString()
                          : "—"}
                      </td>
                      <td className="px-5 py-4">
                        {scan.branch ? (
                          <code className="rounded bg-secondary px-2 py-0.5 text-xs">
                            {scan.branch}
                          </code>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-5 py-4">
                        <Link
                          href={`/scans/${scan.id}`}
                          className="text-primary hover:underline"
                        >
                          <ArrowUpRight className="h-4 w-4" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
