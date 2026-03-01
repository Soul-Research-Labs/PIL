"use client";

import { cn, scoreColor, scoreGrade, severityBg } from "@/lib/utils";
import { Header } from "@/components/layout/header";
import { useQuery } from "@tanstack/react-query";
import { getDashboardStats, getAnalyticsSummary } from "@/lib/api";
import type { AnalyticsSummary } from "@/lib/api";
import {
  Shield,
  AlertTriangle,
  Bug,
  Activity,
  GitBranch,
  Clock,
  ArrowUpRight,
  TrendingUp,
  Loader2,
  BarChart3,
} from "lucide-react";
import Link from "next/link";

export default function DashboardPage() {
  const {
    data: stats,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: getDashboardStats,
    refetchInterval: 30_000,
  });

  const { data: analytics } = useQuery<AnalyticsSummary>({
    queryKey: ["analytics-summary"],
    queryFn: () => getAnalyticsSummary({ days: 30, granularity: "daily" }),
    refetchInterval: 60_000,
  });

  if (isLoading) {
    return (
      <div>
        <Header title="Dashboard" />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  const dashStats = stats || {
    total_projects: 0,
    total_scans: 0,
    total_findings: 0,
    critical_findings: 0,
    avg_security_score: 0,
    scans_this_month: 0,
    recent_scans: [],
    severity_distribution: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
      GAS: 0,
    },
  };

  const sevDist = dashStats.severity_distribution as Record<string, number>;
  const totalSev =
    Object.values(sevDist).reduce<number>((a, b) => a + (b as number), 0) || 1;
  const severityDistribution = [
    {
      label: "Critical",
      count: (sevDist.CRITICAL ?? 0) as number,
      color: "bg-red-500",
      pct: (((sevDist.CRITICAL ?? 0) as number) / totalSev) * 100,
    },
    {
      label: "High",
      count: (sevDist.HIGH ?? 0) as number,
      color: "bg-orange-500",
      pct: (((sevDist.HIGH ?? 0) as number) / totalSev) * 100,
    },
    {
      label: "Medium",
      count: (sevDist.MEDIUM ?? 0) as number,
      color: "bg-yellow-500",
      pct: (((sevDist.MEDIUM ?? 0) as number) / totalSev) * 100,
    },
    {
      label: "Low",
      count: (sevDist.LOW ?? 0) as number,
      color: "bg-blue-500",
      pct: (((sevDist.LOW ?? 0) as number) / totalSev) * 100,
    },
    {
      label: "Info",
      count: (sevDist.INFO ?? 0) as number,
      color: "bg-gray-400",
      pct: (((sevDist.INFO ?? 0) as number) / totalSev) * 100,
    },
  ];

  return (
    <div>
      <Header title="Dashboard" />

      <div className="p-6 space-y-6">
        {/* Stats Row */}
        <div className="grid grid-cols-4 gap-4">
          <StatCard
            title="Security Score"
            value={Math.round(dashStats.avg_security_score)}
            suffix="/100"
            icon={Shield}
            valueClass={scoreColor(dashStats.avg_security_score)}
            subtitle={`Grade ${scoreGrade(dashStats.avg_security_score)}`}
          />
          <StatCard
            title="Critical Issues"
            value={dashStats.critical_findings}
            icon={AlertTriangle}
            valueClass="text-critical"
            subtitle="Require immediate fix"
          />
          <StatCard
            title="Total Findings"
            value={dashStats.total_findings}
            icon={Bug}
            subtitle={`Across ${dashStats.total_scans} scans`}
          />
          <StatCard
            title="Projects"
            value={dashStats.total_projects}
            icon={GitBranch}
            subtitle={`${dashStats.scans_this_month} scans this month`}
          />
        </div>

        {/* ── Trend Charts ────────────────────────────────────────────── */}
        {analytics && analytics.scans_trend.length > 0 && (
          <div className="grid grid-cols-2 gap-4">
            {/* Scan Volume Trend */}
            <div className="rounded-xl border border-border bg-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <BarChart3 className="h-4 w-4 text-muted-foreground" />
                <h3 className="text-sm font-semibold">Scan Volume (30d)</h3>
              </div>
              <div className="flex items-end gap-1 h-24">
                {analytics.scans_trend.map((point, i) => {
                  const max = Math.max(
                    ...analytics.scans_trend.map((p) => p.value),
                    1,
                  );
                  const height = (point.value / max) * 100;
                  return (
                    <div
                      key={i}
                      className="flex-1 bg-primary/20 hover:bg-primary/40 transition rounded-t relative group"
                      style={{ height: `${Math.max(height, 4)}%` }}
                      title={`${new Date(point.timestamp).toLocaleDateString()}: ${point.value} scans`}
                    >
                      <div
                        className="absolute bottom-0 left-0 right-0 bg-primary rounded-t"
                        style={{ height: `${height}%` }}
                      />
                    </div>
                  );
                })}
              </div>
              <div className="flex justify-between mt-2 text-[10px] text-muted-foreground">
                <span>
                  {analytics.scans_trend.length > 0
                    ? new Date(
                        analytics.scans_trend[0].timestamp,
                      ).toLocaleDateString()
                    : ""}
                </span>
                <span>
                  {analytics.scans_trend.length > 0
                    ? new Date(
                        analytics.scans_trend[analytics.scans_trend.length - 1]
                          .timestamp,
                      ).toLocaleDateString()
                    : ""}
                </span>
              </div>
            </div>

            {/* Security Score Trend */}
            <div className="rounded-xl border border-border bg-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
                <h3 className="text-sm font-semibold">Security Score Trend</h3>
                <span
                  className="ml-auto text-lg font-bold"
                  style={{ color: scoreColor(analytics.avg_security_score) }}
                >
                  {Math.round(analytics.avg_security_score)}
                </span>
              </div>
              <svg
                viewBox="0 0 300 80"
                className="w-full h-20"
                preserveAspectRatio="none"
              >
                {analytics.score_trend.length > 1 && (
                  <>
                    <defs>
                      <linearGradient
                        id="scoreFill"
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop
                          offset="0%"
                          stopColor="hsl(var(--primary))"
                          stopOpacity="0.3"
                        />
                        <stop
                          offset="100%"
                          stopColor="hsl(var(--primary))"
                          stopOpacity="0"
                        />
                      </linearGradient>
                    </defs>
                    <path
                      d={(() => {
                        const pts = analytics.score_trend;
                        const xStep = 300 / Math.max(pts.length - 1, 1);
                        const points = pts.map(
                          (p, i) => `${i * xStep},${80 - (p.score / 100) * 75}`,
                        );
                        return `M${points.join(" L")} L${(pts.length - 1) * xStep},80 L0,80 Z`;
                      })()}
                      fill="url(#scoreFill)"
                    />
                    <polyline
                      points={analytics.score_trend
                        .map((p, i) => {
                          const xStep =
                            300 / Math.max(analytics.score_trend.length - 1, 1);
                          return `${i * xStep},${80 - (p.score / 100) * 75}`;
                        })
                        .join(" ")}
                      fill="none"
                      stroke="hsl(var(--primary))"
                      strokeWidth="2"
                    />
                  </>
                )}
              </svg>
            </div>
          </div>
        )}

        <div className="grid grid-cols-3 gap-6">
          {/* Recent Scans */}
          <div className="col-span-2 rounded-xl border border-border bg-card">
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold">Recent Scans</h2>
              <Link
                href="/scans"
                className="text-xs text-primary hover:underline flex items-center gap-1"
              >
                View all <ArrowUpRight className="h-3 w-3" />
              </Link>
            </div>
            <div className="divide-y divide-border">
              {(dashStats.recent_scans || []).length > 0 ? (
                dashStats.recent_scans.map((scan) => (
                  <div
                    key={scan.id}
                    className="flex items-center gap-4 px-5 py-3.5 hover:bg-secondary/50 transition"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium truncate">
                          Scan {String(scan.id).slice(0, 8)}
                        </span>
                        <span
                          className={cn(
                            "text-xs px-1.5 py-0.5 rounded",
                            scan.status === "COMPLETED"
                              ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
                              : scan.status === "FAILED"
                                ? "bg-red-100 text-red-700"
                                : "bg-blue-100 text-blue-700",
                          )}
                        >
                          {scan.status}
                        </span>
                      </div>
                      <div className="mt-0.5 flex items-center gap-3 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {new Date(scan.created_at).toLocaleDateString()}
                        </span>
                        <span>{scan.findings_count} findings</span>
                      </div>
                    </div>
                    <div className="text-right">
                      {scan.security_score !== null &&
                      scan.security_score !== undefined ? (
                        <div
                          className={cn(
                            "text-lg font-bold",
                            scoreColor(scan.security_score),
                          )}
                        >
                          {Math.round(scan.security_score)}
                        </div>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-primary">
                          <Activity className="h-3 w-3 animate-pulse" />
                          Scanning...
                        </span>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="px-5 py-8 text-center text-sm text-muted-foreground">
                  No scans yet. Start with a QuickScan!
                </div>
              )}
            </div>
          </div>

          {/* Severity Distribution */}
          <div className="rounded-xl border border-border bg-card">
            <div className="border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold">Severity Breakdown</h2>
            </div>
            <div className="p-5 space-y-4">
              {/* Bar */}
              <div className="flex h-3 overflow-hidden rounded-full bg-secondary">
                {severityDistribution.map((s) => (
                  <div
                    key={s.label}
                    className={cn("h-full", s.color)}
                    style={{ width: `${s.pct}%` }}
                  />
                ))}
              </div>
              {/* Legend */}
              <div className="space-y-3">
                {severityDistribution.map((s) => (
                  <div
                    key={s.label}
                    className="flex items-center justify-between text-sm"
                  >
                    <div className="flex items-center gap-2">
                      <div
                        className={cn("h-2.5 w-2.5 rounded-full", s.color)}
                      />
                      <span className="text-muted-foreground">{s.label}</span>
                    </div>
                    <span className="font-medium">{s.count}</span>
                  </div>
                ))}
              </div>
              {/* Quick Actions */}
              <div className="mt-6 space-y-2 border-t border-border pt-4">
                <Link
                  href="/quickscan"
                  className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition"
                >
                  <Activity className="h-4 w-4" />
                  New QuickScan
                </Link>
                <Link
                  href="/repos"
                  className="flex w-full items-center justify-center gap-2 rounded-lg border border-border px-4 py-2.5 text-sm font-medium hover:bg-secondary transition"
                >
                  <GitBranch className="h-4 w-4" />
                  Add Repository
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  title,
  value,
  suffix,
  icon: Icon,
  valueClass,
  subtitle,
}: {
  title: string;
  value: number;
  suffix?: string;
  icon: React.ElementType;
  valueClass?: string;
  subtitle: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          {title}
        </span>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </div>
      <div className={cn("mt-2 text-3xl font-bold", valueClass)}>
        {value}
        {suffix && (
          <span className="text-lg text-muted-foreground">{suffix}</span>
        )}
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>
    </div>
  );
}
