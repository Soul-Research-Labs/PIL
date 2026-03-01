"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { cn } from "@/lib/utils";
import {
  BarChart3,
  TrendingUp,
  Clock,
  Target,
  Loader2,
  Activity,
  Shield,
} from "lucide-react";
import { getAnalyticsSummary, getScanVolume, getScoreTrend } from "@/lib/api";
import type { AnalyticsSummary, TimeSeriesPoint, ScoreTrend } from "@/lib/api";

type Granularity = "daily" | "weekly" | "monthly";

export default function AnalyticsPage() {
  const [days, setDays] = useState(30);
  const [granularity, setGranularity] = useState<Granularity>("daily");

  const { data: summary, isLoading } = useQuery<AnalyticsSummary>({
    queryKey: ["analytics-summary", days, granularity],
    queryFn: () => getAnalyticsSummary({ days, granularity }),
  });

  const { data: volume = [] } = useQuery<TimeSeriesPoint[]>({
    queryKey: ["scan-volume", days, granularity],
    queryFn: () => getScanVolume({ days, granularity }),
  });

  const { data: scores = [] } = useQuery<ScoreTrend[]>({
    queryKey: ["score-trend", days],
    queryFn: () => getScoreTrend({ days }),
  });

  if (isLoading) {
    return (
      <div>
        <Header title="Analytics" />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  const maxVolume = Math.max(...volume.map((p) => p.value), 1);

  return (
    <div>
      <Header title="Analytics" />
      <div className="p-6 max-w-6xl mx-auto space-y-6">
        {/* Controls */}
        <div className="flex items-center gap-3">
          <div className="flex gap-1 rounded-md bg-muted p-1">
            {([7, 30, 90, 365] as const).map((d) => (
              <button
                key={d}
                onClick={() => setDays(d)}
                className={cn(
                  "px-3 py-1.5 rounded-sm text-sm font-medium transition",
                  days === d
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {d === 365 ? "1y" : `${d}d`}
              </button>
            ))}
          </div>
          <select
            value={granularity}
            onChange={(e) => setGranularity(e.target.value as Granularity)}
            className="rounded-md border bg-background px-2 py-1.5 text-sm"
          >
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
          </select>
        </div>

        {/* KPI cards */}
        {summary && (
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <KPICard
              icon={Activity}
              label="Total Scans"
              value={summary.total_scans}
            />
            <KPICard
              icon={Shield}
              label="Avg Score"
              value={`${Math.round(summary.avg_security_score)}/100`}
              className={
                summary.avg_security_score >= 80
                  ? "text-green-500"
                  : summary.avg_security_score >= 60
                    ? "text-yellow-500"
                    : "text-red-500"
              }
            />
            <KPICard
              icon={Target}
              label="Total Findings"
              value={summary.total_findings}
            />
            <KPICard
              icon={Clock}
              label="MTTR"
              value={
                summary.mttr.sample_size > 0
                  ? `${Math.round(summary.mttr.overall_hours)}h`
                  : "N/A"
              }
              subtitle={`${summary.mttr.sample_size} resolved`}
            />
          </div>
        )}

        {/* Scan Volume Chart */}
        <div className="rounded-xl border border-border bg-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <BarChart3 className="h-4 w-4 text-muted-foreground" />
            <h3 className="text-sm font-semibold">Scan Volume</h3>
            <span className="text-xs text-muted-foreground ml-auto">
              {volume.reduce((a, p) => a + p.value, 0)} scans in period
            </span>
          </div>
          <div className="flex items-end gap-[2px] h-40">
            {volume.map((point, i) => {
              const height = (point.value / maxVolume) * 100;
              return (
                <div
                  key={i}
                  className="flex-1 group relative"
                  title={`${new Date(point.timestamp).toLocaleDateString()}: ${point.value}`}
                >
                  <div
                    className="w-full bg-primary/70 hover:bg-primary transition rounded-t"
                    style={{ height: `${Math.max(height, 2)}%` }}
                  />
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block bg-popover text-popover-foreground text-xs rounded px-2 py-1 shadow whitespace-nowrap z-10">
                    {new Date(point.timestamp).toLocaleDateString()} —{" "}
                    {point.value} scans
                  </div>
                </div>
              );
            })}
          </div>
          {volume.length > 0 && (
            <div className="flex justify-between mt-2 text-[10px] text-muted-foreground">
              <span>{new Date(volume[0].timestamp).toLocaleDateString()}</span>
              <span>
                {new Date(
                  volume[volume.length - 1].timestamp,
                ).toLocaleDateString()}
              </span>
            </div>
          )}
        </div>

        {/* Score Trend */}
        <div className="rounded-xl border border-border bg-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
            <h3 className="text-sm font-semibold">Security Score Trend</h3>
          </div>
          {scores.length > 1 ? (
            <svg
              viewBox="0 0 600 120"
              className="w-full h-32"
              preserveAspectRatio="none"
            >
              <defs>
                <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
                  <stop
                    offset="0%"
                    stopColor="hsl(var(--primary))"
                    stopOpacity="0.25"
                  />
                  <stop
                    offset="100%"
                    stopColor="hsl(var(--primary))"
                    stopOpacity="0"
                  />
                </linearGradient>
              </defs>
              {/* Grid lines */}
              {[0, 25, 50, 75, 100].map((v) => (
                <line
                  key={v}
                  x1="0"
                  y1={120 - (v / 100) * 110}
                  x2="600"
                  y2={120 - (v / 100) * 110}
                  stroke="currentColor"
                  strokeOpacity="0.07"
                />
              ))}
              {/* Area fill */}
              <path
                d={(() => {
                  const xStep = 600 / Math.max(scores.length - 1, 1);
                  const points = scores.map(
                    (p, i) => `${i * xStep},${120 - (p.score / 100) * 110}`,
                  );
                  return `M${points.join(" L")} L${(scores.length - 1) * xStep},120 L0,120 Z`;
                })()}
                fill="url(#areaFill)"
              />
              {/* Line */}
              <polyline
                points={scores
                  .map((p, i) => {
                    const xStep = 600 / Math.max(scores.length - 1, 1);
                    return `${i * xStep},${120 - (p.score / 100) * 110}`;
                  })
                  .join(" ")}
                fill="none"
                stroke="hsl(var(--primary))"
                strokeWidth="2"
                strokeLinejoin="round"
              />
              {/* Dots */}
              {scores.length <= 50 &&
                scores.map((p, i) => {
                  const xStep = 600 / Math.max(scores.length - 1, 1);
                  return (
                    <circle
                      key={i}
                      cx={i * xStep}
                      cy={120 - (p.score / 100) * 110}
                      r="3"
                      fill="hsl(var(--primary))"
                    >
                      <title>
                        {new Date(p.timestamp).toLocaleDateString()} — Score:{" "}
                        {Math.round(p.score)}
                      </title>
                    </circle>
                  );
                })}
            </svg>
          ) : (
            <div className="h-32 flex items-center justify-center text-sm text-muted-foreground">
              Not enough data points to display trend
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function KPICard({
  icon: Icon,
  label,
  value,
  subtitle,
  className,
}: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  subtitle?: string;
  className?: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          {label}
        </span>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </div>
      <div className={cn("mt-2 text-2xl font-bold", className)}>{value}</div>
      {subtitle && (
        <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>
      )}
    </div>
  );
}
