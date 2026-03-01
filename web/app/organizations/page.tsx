"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { cn } from "@/lib/utils";
import {
  Building2,
  Users,
  Plus,
  Trash2,
  Crown,
  UserPlus,
  Loader2,
  Settings,
  BarChart3,
  ChevronRight,
} from "lucide-react";
import {
  getOrganizations,
  createOrganization,
  deleteOrganization,
  getOrgMembers,
  inviteOrgMember,
  updateMemberRole,
  removeOrgMember,
  getOrgUsage,
} from "@/lib/api";
import type { Organization, OrgMember, OrgRole, OrgUsage } from "@/types";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";

// ── Organization list + detail view ─────────────────────────────────────────

export default function OrganizationsPage() {
  const queryClient = useQueryClient();
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newSlug, setNewSlug] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<OrgRole>("viewer");

  // ── Queries ───────────────────────────────────────────────────────────────

  const { data: orgs = [], isLoading } = useQuery({
    queryKey: ["organizations"],
    queryFn: getOrganizations,
  });

  const { data: members = [], isLoading: membersLoading } = useQuery({
    queryKey: ["org-members", selectedOrg?.slug],
    queryFn: () => getOrgMembers(selectedOrg!.slug),
    enabled: !!selectedOrg,
  });

  const { data: usage } = useQuery<OrgUsage>({
    queryKey: ["org-usage", selectedOrg?.slug],
    queryFn: () => getOrgUsage(selectedOrg!.slug),
    enabled: !!selectedOrg,
  });

  // ── Mutations ─────────────────────────────────────────────────────────────

  const createMut = useMutation({
    mutationFn: () => createOrganization(newName, newSlug),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["organizations"] });
      setCreateOpen(false);
      setNewName("");
      setNewSlug("");
    },
  });

  const deleteMut = useMutation({
    mutationFn: (slug: string) => deleteOrganization(slug),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["organizations"] });
      setSelectedOrg(null);
    },
  });

  const inviteMut = useMutation({
    mutationFn: () =>
      inviteOrgMember(selectedOrg!.slug, {
        email: inviteEmail,
        role: inviteRole,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["org-members", selectedOrg?.slug],
      });
      setInviteOpen(false);
      setInviteEmail("");
      setInviteRole("viewer");
    },
  });

  const updateRoleMut = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: OrgRole }) =>
      updateMemberRole(selectedOrg!.slug, userId, role),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: ["org-members", selectedOrg?.slug],
      }),
  });

  const removeMemberMut = useMutation({
    mutationFn: (userId: string) => removeOrgMember(selectedOrg!.slug, userId),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: ["org-members", selectedOrg?.slug],
      }),
  });

  // ── Loading ───────────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <div>
        <Header title="Organizations" />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  // ── Org detail ────────────────────────────────────────────────────────────

  if (selectedOrg) {
    return (
      <div>
        <Header title={selectedOrg.name} />
        <div className="p-6 max-w-5xl mx-auto space-y-6">
          {/* Back */}
          <button
            onClick={() => setSelectedOrg(null)}
            className="text-sm text-muted-foreground hover:text-foreground transition"
          >
            &larr; All organizations
          </button>

          {/* Usage cards */}
          {usage && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <StatCard
                icon={BarChart3}
                label="Scans used"
                value={`${usage.scans_this_month} / ${usage.limits?.scans ?? "\u221E"}`}
              />
              <StatCard
                icon={Users}
                label="Members"
                value={`${usage.members} / ${usage.limits?.members ?? "\u221E"}`}
              />
              <StatCard
                icon={Settings}
                label="Plan"
                value={(usage.plan ?? "free").toUpperCase()}
              />
            </div>
          )}

          {/* Members table */}
          <div className="rounded-lg border bg-card">
            <div className="flex items-center justify-between p-4 border-b">
              <h3 className="font-semibold flex items-center gap-2">
                <Users className="h-4 w-4" /> Members
              </h3>
              <button
                onClick={() => setInviteOpen(true)}
                className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition"
              >
                <UserPlus className="h-4 w-4" /> Invite
              </button>
            </div>

            {membersLoading ? (
              <div className="flex justify-center p-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="p-3 font-medium">User</th>
                    <th className="p-3 font-medium">Role</th>
                    <th className="p-3 font-medium">Joined</th>
                    <th className="p-3 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {members.map((m: OrgMember) => (
                    <tr
                      key={m.user_id}
                      className="border-b last:border-0 hover:bg-muted/40"
                    >
                      <td className="p-3">{m.email || m.user_id}</td>
                      <td className="p-3">
                        <select
                          value={m.role}
                          onChange={(e) =>
                            updateRoleMut.mutate({
                              userId: m.user_id,
                              role: e.target.value as OrgRole,
                            })
                          }
                          className="rounded border bg-background px-2 py-1 text-sm"
                        >
                          <option value="viewer">Viewer</option>
                          <option value="editor">Editor</option>
                          <option value="admin">Admin</option>
                          <option value="owner">Owner</option>
                        </select>
                      </td>
                      <td className="p-3 text-muted-foreground">
                        {new Date(m.joined_at).toLocaleDateString()}
                      </td>
                      <td className="p-3 text-right">
                        <button
                          onClick={() => removeMemberMut.mutate(m.user_id)}
                          className="text-destructive hover:text-destructive/80 transition"
                          title="Remove member"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Danger zone */}
          <div className="rounded-lg border border-destructive/30 p-4 space-y-3">
            <h3 className="font-semibold text-destructive">Danger Zone</h3>
            <p className="text-sm text-muted-foreground">
              Deleting this organization is irreversible and removes all data.
            </p>
            <button
              onClick={() => {
                if (
                  confirm(
                    `Delete organization "${selectedOrg.name}"? This cannot be undone.`,
                  )
                ) {
                  deleteMut.mutate(selectedOrg.slug);
                }
              }}
              className="inline-flex items-center gap-1.5 rounded-md bg-destructive px-3 py-1.5 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 transition"
            >
              <Trash2 className="h-4 w-4" /> Delete Organization
            </button>
          </div>
        </div>

        {/* Invite dialog */}
        <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Invite Member</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <label className="block text-sm font-medium mb-1">Email</label>
                <input
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="user@example.com"
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Role</label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as OrgRole)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  <option value="viewer">Viewer</option>
                  <option value="editor">Editor</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            </div>
            <DialogFooter>
              <button
                onClick={() => setInviteOpen(false)}
                className="rounded-md border px-4 py-2 text-sm hover:bg-muted transition"
              >
                Cancel
              </button>
              <button
                onClick={() => inviteMut.mutate()}
                disabled={!inviteEmail || inviteMut.isPending}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition"
              >
                {inviteMut.isPending ? "Sending…" : "Send Invite"}
              </button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    );
  }

  // ── Org list ──────────────────────────────────────────────────────────────

  return (
    <div>
      <Header title="Organizations" />
      <div className="p-6 max-w-4xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <p className="text-muted-foreground text-sm">
            Manage your organizations and team members.
          </p>
          <button
            onClick={() => setCreateOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition"
          >
            <Plus className="h-4 w-4" /> New Organization
          </button>
        </div>

        {orgs.length === 0 ? (
          <div className="rounded-lg border bg-card p-12 text-center space-y-2">
            <Building2 className="mx-auto h-12 w-12 text-muted-foreground/40" />
            <p className="text-muted-foreground text-sm">
              No organizations yet. Create one to get started.
            </p>
          </div>
        ) : (
          <div className="grid gap-3">
            {orgs.map((org) => (
              <button
                key={org.id}
                onClick={() => setSelectedOrg(org)}
                className="flex items-center justify-between rounded-lg border bg-card p-4 hover:bg-muted/40 transition text-left w-full"
              >
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-md bg-primary/10 flex items-center justify-center">
                    <Building2 className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <div className="font-medium">{org.name}</div>
                    <div className="text-sm text-muted-foreground">
                      {org.slug} &middot;{" "}
                      <span className="capitalize">{org.tier}</span>
                    </div>
                  </div>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Organization</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <label className="block text-sm font-medium mb-1">Name</label>
              <input
                value={newName}
                onChange={(e) => {
                  setNewName(e.target.value);
                  setNewSlug(
                    e.target.value
                      .toLowerCase()
                      .replace(/[^a-z0-9]+/g, "-")
                      .replace(/(^-|-$)/g, ""),
                  );
                }}
                placeholder="My Team"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Slug</label>
              <input
                value={newSlug}
                onChange={(e) => setNewSlug(e.target.value)}
                placeholder="my-team"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Used in URLs. Only lowercase letters, numbers, and hyphens.
              </p>
            </div>
          </div>
          <DialogFooter>
            <button
              onClick={() => setCreateOpen(false)}
              className="rounded-md border px-4 py-2 text-sm hover:bg-muted transition"
            >
              Cancel
            </button>
            <button
              onClick={() => createMut.mutate()}
              disabled={!newName || !newSlug || createMut.isPending}
              className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition"
            >
              {createMut.isPending ? "Creating…" : "Create"}
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ── Small stat card component ───────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-lg border bg-card p-4 flex items-center gap-3">
      <div className="h-9 w-9 rounded-md bg-primary/10 flex items-center justify-center">
        <Icon className="h-5 w-5 text-primary" />
      </div>
      <div>
        <div className="text-sm text-muted-foreground">{label}</div>
        <div className="font-semibold">{value}</div>
      </div>
    </div>
  );
}
