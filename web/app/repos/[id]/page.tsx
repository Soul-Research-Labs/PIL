"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getProject, getScans, deleteProject } from "@/lib/api";
import { Header } from "@/components/layout/header";
import { cn, scoreColor, scoreGrade } from "@/lib/utils";
import {
  GitBranch,
  Shield,
  Clock,
  Trash2,
  Play,
  ArrowUpRight,
  Loader2,
  AlertTriangle,
  ExternalLink,
} from "lucide-react";
import Link from "next/link";

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const queryClient = useQueryClient();

  const { data: project, isLoading: projLoading } = useQuery({
    queryKey: ["project", id],
    queryFn: () => getProject(id),
  });

  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ["scans", id],
    queryFn: () => getScans(id),
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteProject(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      router.push("/repos");
    },
  });

  if (projLoading) {
    return (
      <div>
        <Header title="Project" />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  if (!project) {
    return (
      <div>
        <Header title="Project" />
        <div className="flex flex-col items-center justify-center h-64 gap-3">
          <AlertTriangle className="h-8 w-8 text-muted-foreground" />
          <p className="text-muted-foreground">Project not found</p>
          <Link href="/repos" className="text-primary hover:underline text-sm">
            Back to projects
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div>
      <Header title={project.name} />

      <div className="p-6 space-y-6">
        {/* Project Info */}
        <div className="rounded-xl border border-border bg-card p-5">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-lg font-semibold">{project.name}</h2>
              {project.description && (
                <p className="mt-1 text-sm text-muted-foreground">
                  {project.description}
                </p>
              )}
              <div className="mt-3 flex items-center gap-4 text-sm text-muted-foreground">
                <span className="capitalize">
                  {project.source_type.replace("_", " ")}
                </span>
                {project.github_repo_url && (
                  <a
                    href={project.github_repo_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-primary hover:underline"
                  >
                    <GitBranch className="h-3.5 w-3.5" />
                    GitHub
                    <ExternalLink className="h-3 w-3" />
                  </a>
                )}
                {project.chain && (
                  <span className="rounded bg-secondary px-2 py-0.5 text-xs">
                    {project.chain}
                  </span>
                )}
              </div>
            </div>
            <div className="flex gap-2">
              <Link
                href={`/scans?project=${id}`}
                className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition"
              >
                <Play className="h-3.5 w-3.5" />
                New Scan
              </Link>
              <button
                onClick={() => {
                  if (confirm("Delete this project and all its scans?")) {
                    deleteMutation.mutate();
                  }
                }}
                disabled={deleteMutation.isPending}
                className="flex items-center gap-2 rounded-lg border border-red-200 px-3 py-2 text-sm text-red-600 hover:bg-red-50 transition dark:border-red-900/50 dark:text-red-400 dark:hover:bg-red-900/20"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </div>

        {/* Scans */}
        <div className="rounded-xl border border-border bg-card">
          <div className="border-b border-border px-5 py-4">
            <h3 className="text-sm font-semibold">
              Scans{" "}
              {scans && (
                <span className="text-muted-foreground font-normal">
                  ({scans.length})
                </span>
              )}
            </h3>
          </div>
          {scansLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !scans || scans.length === 0 ? (
            <div className="px-5 py-12 text-center text-sm text-muted-foreground">
              No scans yet. Click &ldquo;New Scan&rdquo; to start.
            </div>
          ) : (
            <div className="divide-y divide-border">
              {scans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="flex items-center gap-4 px-5 py-3.5 hover:bg-secondary/50 transition"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">
                        Scan {scan.id.slice(0, 8)}
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
                      {scan.branch && (
                        <code className="rounded bg-secondary px-1.5 py-0.5 text-xs">
                          {scan.branch}
                        </code>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {scan.security_score != null ? (
                      <div
                        className={cn(
                          "text-lg font-bold",
                          scoreColor(scan.security_score),
                        )}
                      >
                        {Math.round(scan.security_score)}
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                    <ArrowUpRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
