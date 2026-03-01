"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getFinding, updateFindingStatus } from "@/lib/api";
import { Header } from "@/components/layout/header";
import { cn } from "@/lib/utils";
import {
  AlertTriangle,
  FileCode,
  Shield,
  Bug,
  Loader2,
  CheckCircle,
  XCircle,
  ChevronDown,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import type { FindingStatus } from "@/types";

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

const STATUS_OPTIONS: FindingStatus[] = [
  "OPEN",
  "CONFIRMED",
  "FALSE_POSITIVE",
  "MITIGATED",
  "ACCEPTED",
];

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [showStatusMenu, setShowStatusMenu] = useState(false);

  const { data: finding, isLoading } = useQuery({
    queryKey: ["finding", id],
    queryFn: () => getFinding(id),
  });

  const statusMutation = useMutation({
    mutationFn: (status: string) => updateFindingStatus(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["finding", id] });
      setShowStatusMenu(false);
    },
  });

  if (isLoading) {
    return (
      <div>
        <Header title="Finding" />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  if (!finding) {
    return (
      <div>
        <Header title="Finding" />
        <div className="flex flex-col items-center justify-center h-64 gap-3">
          <AlertTriangle className="h-8 w-8 text-muted-foreground" />
          <p className="text-muted-foreground">Finding not found</p>
          <Link href="/scans" className="text-primary hover:underline text-sm">
            Back to scans
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div>
      <Header title={finding.title} />

      <div className="p-6 space-y-6">
        {/* Top Bar */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <span
              className={cn(
                "inline-flex items-center rounded-full border px-3 py-1 text-sm font-semibold",
                severityClass(finding.severity),
              )}
            >
              {finding.severity}
            </span>
            {finding.cwe_id && (
              <span className="rounded border border-border px-2 py-0.5 text-xs text-muted-foreground">
                {finding.cwe_id}
              </span>
            )}
            {finding.scwe_id && (
              <span className="rounded border border-border px-2 py-0.5 text-xs text-muted-foreground">
                {finding.scwe_id}
              </span>
            )}
            {finding.verified && (
              <span className="flex items-center gap-1 rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900/30 dark:text-green-400">
                <CheckCircle className="h-3 w-3" />
                Verified
              </span>
            )}
          </div>

          {/* Status dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowStatusMenu(!showStatusMenu)}
              className="flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-sm hover:bg-secondary transition"
            >
              {finding.status.toLowerCase().replace("_", " ")}
              <ChevronDown className="h-3.5 w-3.5" />
            </button>
            {showStatusMenu && (
              <div className="absolute right-0 top-full mt-1 z-10 w-44 rounded-lg border border-border bg-card shadow-lg py-1">
                {STATUS_OPTIONS.map((status) => (
                  <button
                    key={status}
                    onClick={() => statusMutation.mutate(status)}
                    className={cn(
                      "flex w-full items-center px-3 py-2 text-sm hover:bg-secondary transition text-left",
                      finding.status === status && "font-medium text-primary",
                    )}
                  >
                    {status.toLowerCase().replace("_", " ")}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="grid grid-cols-3 gap-6">
          {/* Main Content */}
          <div className="col-span-2 space-y-6">
            {/* Description */}
            <div className="rounded-xl border border-border bg-card p-5">
              <h3 className="text-sm font-semibold mb-3">Description</h3>
              <p className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
                {finding.description}
              </p>
            </div>

            {/* Code Snippet */}
            {finding.location.snippet && (
              <div className="rounded-xl border border-border bg-card overflow-hidden">
                <div className="flex items-center gap-2 border-b border-border px-5 py-3">
                  <FileCode className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-medium font-mono">
                    {finding.location.file}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    L{finding.location.start_line}–{finding.location.end_line}
                  </span>
                </div>
                <pre className="overflow-x-auto bg-secondary/30 p-5 text-xs font-mono leading-relaxed">
                  <code>{finding.location.snippet}</code>
                </pre>
              </div>
            )}

            {/* Remediation */}
            {finding.remediation && (
              <div className="rounded-xl border border-border bg-card p-5">
                <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                  <Shield className="h-4 w-4 text-primary" />
                  Remediation
                </h3>
                <p className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
                  {finding.remediation}
                </p>
              </div>
            )}

            {/* Proof of Concept */}
            {finding.proof_of_concept && (
              <div className="rounded-xl border border-border bg-card overflow-hidden">
                <div className="flex items-center gap-2 border-b border-border px-5 py-3">
                  <Bug className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-semibold">
                    Proof of Concept
                  </span>
                </div>
                <pre className="overflow-x-auto bg-secondary/30 p-5 text-xs font-mono leading-relaxed">
                  <code>{finding.proof_of_concept}</code>
                </pre>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-4">
            <div className="rounded-xl border border-border bg-card p-5 space-y-4">
              <div>
                <div className="text-xs text-muted-foreground">Category</div>
                <div className="mt-1 text-sm font-medium">
                  {finding.category || "—"}
                </div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground">Confidence</div>
                <div className="mt-1 text-sm font-medium">
                  {Math.round(finding.confidence * 100)}%
                </div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground">File</div>
                <div className="mt-1 text-sm font-mono truncate">
                  {finding.location.file}
                </div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground">Lines</div>
                <div className="mt-1 text-sm font-mono">
                  {finding.location.start_line}–{finding.location.end_line}
                </div>
              </div>
              {finding.gas_saved != null && finding.gas_saved > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground">
                    Gas Savings
                  </div>
                  <div className="mt-1 text-sm font-medium text-green-600">
                    ~{finding.gas_saved.toLocaleString()} gas
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
