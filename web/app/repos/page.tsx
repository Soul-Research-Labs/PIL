"use client";

import { useState } from "react";
import { Header } from "@/components/layout/header";
import { cn, scoreColor } from "@/lib/utils";
import {
  GitBranch,
  Plus,
  ExternalLink,
  Shield,
  Clock,
  Trash2,
  Loader2,
} from "lucide-react";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getProjects, createProject, deleteProject } from "@/lib/api";

export default function ReposPage() {
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [name, setName] = useState("");
  const [githubUrl, setGithubUrl] = useState("");

  const { data: projects, isLoading } = useQuery({
    queryKey: ["projects"],
    queryFn: getProjects,
    refetchInterval: 30_000,
  });

  const addMutation = useMutation({
    mutationFn: () =>
      createProject({
        name: name || githubUrl.split("/").pop() || "Untitled",
        source_type: "github_repo",
        github_url: githubUrl,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      setShowModal(false);
      setName("");
      setGithubUrl("");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteProject(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["projects"] }),
  });

  return (
    <div>
      <Header title="Smart Contract Projects" />

      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            {isLoading
              ? "Loading…"
              : `${projects?.length ?? 0} smart contract projects`}
          </p>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition"
          >
            <Plus className="h-4 w-4" />
            Add Repository
          </button>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : !projects || projects.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <GitBranch className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold">No projects connected</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Connect a GitHub repository with Solidity contracts to start
              automated security scanning.
            </p>
            <button
              onClick={() => setShowModal(true)}
              className="mt-4 flex items-center gap-2 rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition"
            >
              <Plus className="h-4 w-4" />
              Add Repository
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {projects.map((project) => (
              <Link
                key={project.id}
                href={`/repos/${project.id}`}
                className="flex items-center gap-4 rounded-xl border border-border bg-card p-5 hover:border-primary/30 transition"
              >
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-secondary">
                  <GitBranch className="h-5 w-5 text-muted-foreground" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold">{project.name}</h3>
                    <span className="rounded bg-secondary px-2 py-0.5 text-[10px] font-medium text-muted-foreground capitalize">
                      {project.source_type.replace("_", " ")}
                    </span>
                  </div>
                  <div className="mt-0.5 flex items-center gap-3 text-xs text-muted-foreground">
                    {project.github_repo_url && (
                      <span className="flex items-center gap-1">
                        <ExternalLink className="h-3 w-3" />
                        {project.github_repo_url.replace(
                          "https://github.com/",
                          "",
                        )}
                      </span>
                    )}
                    {project.chain && (
                      <span className="flex items-center gap-1">
                        <Shield className="h-3 w-3" />
                        {project.chain}
                      </span>
                    )}
                    {project.created_at && (
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {new Date(project.created_at).toLocaleDateString()}
                      </span>
                    )}
                  </div>
                </div>
                <button
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (confirm("Delete this project?")) {
                      deleteMutation.mutate(project.id);
                    }
                  }}
                  className="rounded-lg p-2 text-muted-foreground hover:bg-secondary hover:text-foreground transition"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </Link>
            ))}
          </div>
        )}

        {/* Add Repository Modal */}
        {showModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-lg space-y-4">
              <h2 className="text-lg font-semibold">Add Repository</h2>
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium">Project Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="My DeFi Protocol"
                    className="mt-1 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">GitHub URL</label>
                  <input
                    type="url"
                    value={githubUrl}
                    onChange={(e) => setGithubUrl(e.target.value)}
                    placeholder="https://github.com/org/repo"
                    required
                    className="mt-1 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setShowModal(false)}
                  className="rounded-lg border border-border px-4 py-2 text-sm hover:bg-secondary transition"
                >
                  Cancel
                </button>
                <button
                  onClick={() => addMutation.mutate()}
                  disabled={!githubUrl || addMutation.isPending}
                  className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition disabled:opacity-50"
                >
                  {addMutation.isPending && (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  )}
                  Add
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
