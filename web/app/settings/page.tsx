"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { cn } from "@/lib/utils";
import {
  User,
  Key,
  Bell,
  Shield,
  Webhook,
  Wallet,
  Plus,
  Trash2,
  Copy,
  Check,
  Loader2,
} from "lucide-react";
import api from "@/lib/api";

type SettingsTab =
  | "profile"
  | "api-keys"
  | "notifications"
  | "security"
  | "webhooks"
  | "wallet";

const tabs: { id: SettingsTab; label: string; icon: React.ElementType }[] = [
  { id: "profile", label: "Profile", icon: User },
  { id: "api-keys", label: "API Keys", icon: Key },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "security", label: "Security", icon: Shield },
  { id: "webhooks", label: "Webhooks", icon: Webhook },
  { id: "wallet", label: "Wallet", icon: Wallet },
];

interface UserProfile {
  id: string;
  username: string;
  email: string | null;
  display_name: string | null;
  avatar_url: string | null;
  is_active: boolean;
}

interface ApiKeyItem {
  id: string;
  name: string;
  key: string | null;
  is_active: boolean;
  created_at: string;
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<SettingsTab>("profile");
  const queryClient = useQueryClient();

  // ── Profile ──
  const { data: profile, isLoading: profileLoading } = useQuery<UserProfile>({
    queryKey: ["profile"],
    queryFn: async () => {
      const { data } = await api.get("/v1/auth/me");
      return data;
    },
  });

  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [profileSaved, setProfileSaved] = useState(false);

  useEffect(() => {
    if (profile) {
      setDisplayName(profile.display_name || profile.username || "");
      setEmail(profile.email || "");
    }
  }, [profile]);

  const profileMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.patch("/v1/auth/me", {
        display_name: displayName,
        email: email || undefined,
      });
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["profile"] });
      setProfileSaved(true);
      setTimeout(() => setProfileSaved(false), 2000);
    },
  });

  // ── API Keys ──
  const { data: apiKeys = [], isLoading: keysLoading } = useQuery<ApiKeyItem[]>(
    {
      queryKey: ["api-keys"],
      queryFn: async () => {
        const { data } = await api.get("/v1/auth/api-keys");
        return data;
      },
    },
  );

  const [newKeyName, setNewKeyName] = useState("");
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  const createKeyMutation = useMutation({
    mutationFn: async (name: string) => {
      const { data } = await api.post("/v1/auth/api-keys", { name });
      return data as ApiKeyItem;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      setNewlyCreatedKey(data.key);
      setNewKeyName("");
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: async (keyId: string) => {
      await api.delete(`/v1/auth/api-keys/${keyId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  return (
    <div>
      <Header title="Settings" />

      <div className="flex p-6 gap-6">
        {/* Settings Sidebar */}
        <nav className="w-48 space-y-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition",
                activeTab === tab.id
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-secondary hover:text-foreground",
              )}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="flex-1 max-w-2xl">
          {activeTab === "profile" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold">Profile</h2>
                <p className="text-sm text-muted-foreground">
                  Manage your account settings
                </p>
              </div>

              {profileLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              ) : (
                <div className="space-y-4 rounded-xl border border-border bg-card p-6">
                  <div>
                    <label className="mb-1.5 block text-sm font-medium">
                      Username
                    </label>
                    <input
                      type="text"
                      value={profile?.username || ""}
                      disabled
                      className="w-full rounded-lg border border-border bg-secondary/50 px-4 py-2.5 text-sm text-muted-foreground outline-none cursor-not-allowed"
                    />
                    <p className="mt-1 text-xs text-muted-foreground">
                      Username cannot be changed
                    </p>
                  </div>
                  <div>
                    <label className="mb-1.5 block text-sm font-medium">
                      Display Name
                    </label>
                    <input
                      type="text"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      className="w-full rounded-lg border border-border bg-background px-4 py-2.5 text-sm outline-none focus:border-primary"
                    />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-sm font-medium">
                      Email
                    </label>
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full rounded-lg border border-border bg-background px-4 py-2.5 text-sm outline-none focus:border-primary"
                    />
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => profileMutation.mutate()}
                      disabled={profileMutation.isPending}
                      className="rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition disabled:opacity-50"
                    >
                      {profileMutation.isPending ? "Saving..." : "Save Changes"}
                    </button>
                    {profileSaved && (
                      <span className="flex items-center gap-1 text-sm text-safe">
                        <Check className="h-4 w-4" /> Saved
                      </span>
                    )}
                    {profileMutation.isError && (
                      <span className="text-sm text-critical">
                        {(profileMutation.error as Error)?.message ||
                          "Failed to save"}
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === "api-keys" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold">API Keys</h2>
                <p className="text-sm text-muted-foreground">
                  Manage API keys for programmatic access
                </p>
              </div>

              {/* Newly created key banner */}
              {newlyCreatedKey && (
                <div className="rounded-xl border border-safe/30 bg-safe/5 p-4">
                  <p className="text-sm font-medium text-safe mb-2">
                    API key created — copy it now. It won&apos;t be shown again.
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 rounded-lg bg-background p-3 text-xs font-mono border border-border break-all">
                      {newlyCreatedKey}
                    </code>
                    <button
                      onClick={() => copyToClipboard(newlyCreatedKey)}
                      className="rounded-lg border border-border p-2.5 hover:bg-secondary transition"
                    >
                      {copiedKey ? (
                        <Check className="h-4 w-4 text-safe" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>
              )}

              <div className="rounded-xl border border-border bg-card p-6 space-y-4">
                {keysLoading ? (
                  <div className="flex justify-center py-8">
                    <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                  </div>
                ) : apiKeys.length === 0 ? (
                  <p className="text-sm text-muted-foreground py-4 text-center">
                    No API keys yet. Create one below.
                  </p>
                ) : (
                  apiKeys.map((k) => (
                    <div
                      key={k.id}
                      className="flex items-center justify-between p-4 rounded-lg border border-border bg-background"
                    >
                      <div>
                        <p className="text-sm font-medium">{k.name}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Created {new Date(k.created_at).toLocaleDateString()}
                          {!k.is_active && (
                            <span className="ml-2 text-critical">
                              (Revoked)
                            </span>
                          )}
                        </p>
                      </div>
                      {k.is_active && (
                        <button
                          onClick={() => revokeKeyMutation.mutate(k.id)}
                          className="rounded-lg p-2 text-muted-foreground hover:text-critical hover:bg-critical/10 transition"
                          title="Revoke key"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  ))
                )}

                {/* Create new key */}
                <div className="flex items-end gap-3 pt-2 border-t border-border">
                  <div className="flex-1">
                    <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
                      Key Name
                    </label>
                    <input
                      type="text"
                      value={newKeyName}
                      onChange={(e) => setNewKeyName(e.target.value)}
                      placeholder="e.g., CI Pipeline"
                      className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary"
                    />
                  </div>
                  <button
                    onClick={() =>
                      newKeyName.trim() &&
                      createKeyMutation.mutate(newKeyName.trim())
                    }
                    disabled={!newKeyName.trim() || createKeyMutation.isPending}
                    className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition disabled:opacity-50"
                  >
                    <Plus className="h-4 w-4" />
                    {createKeyMutation.isPending
                      ? "Creating..."
                      : "Generate Key"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === "security" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold">Security</h2>
                <p className="text-sm text-muted-foreground">
                  Authentication and security settings
                </p>
              </div>

              <div className="rounded-xl border border-border bg-card p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium">GitHub OAuth</p>
                    <p className="text-xs text-muted-foreground">
                      Sign in with your GitHub account
                    </p>
                  </div>
                  {profile?.avatar_url ? (
                    <span className="rounded bg-safe/10 px-2.5 py-0.5 text-xs font-medium text-safe border border-safe/20">
                      Connected
                    </span>
                  ) : (
                    <span className="rounded bg-muted px-2.5 py-0.5 text-xs font-medium text-muted-foreground border border-border">
                      Not connected
                    </span>
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium">
                      Two-Factor Authentication
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Add an extra layer of security
                    </p>
                  </div>
                  <button className="rounded-lg border border-border px-3 py-1.5 text-xs font-medium hover:bg-secondary transition">
                    Enable
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === "wallet" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold">Wallet</h2>
                <p className="text-sm text-muted-foreground">
                  Connect your Web3 wallet for SIWE authentication
                </p>
              </div>

              <div className="rounded-xl border border-border bg-card p-6">
                <div className="text-center py-8">
                  <Wallet className="mx-auto h-10 w-10 text-muted-foreground mb-3" />
                  <p className="text-sm font-medium">No wallet connected</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Connect MetaMask, WalletConnect, or other wallets
                  </p>
                  <button className="mt-4 rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition">
                    Connect Wallet
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === "notifications" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold">Notifications</h2>
                <p className="text-sm text-muted-foreground">
                  Configure how you receive alerts
                </p>
              </div>
              <div className="rounded-xl border border-border bg-card p-6 space-y-4">
                {[
                  {
                    label: "Critical findings",
                    desc: "Get notified when critical vulnerabilities are found",
                    default: true,
                  },
                  {
                    label: "Scan completed",
                    desc: "Notification when a scan finishes",
                    default: true,
                  },
                  {
                    label: "Weekly digest",
                    desc: "Summary of security posture changes",
                    default: false,
                  },
                ].map((item) => (
                  <div
                    key={item.label}
                    className="flex items-center justify-between"
                  >
                    <div>
                      <p className="text-sm font-medium">{item.label}</p>
                      <p className="text-xs text-muted-foreground">
                        {item.desc}
                      </p>
                    </div>
                    <label className="relative inline-flex cursor-pointer items-center">
                      <input
                        type="checkbox"
                        defaultChecked={item.default}
                        className="peer sr-only"
                      />
                      <div className="h-5 w-9 rounded-full bg-secondary peer-checked:bg-primary transition-colors after:absolute after:left-[2px] after:top-[2px] after:h-4 after:w-4 after:rounded-full after:bg-white after:transition-transform peer-checked:after:translate-x-full" />
                    </label>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === "webhooks" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold">Webhooks</h2>
                <p className="text-sm text-muted-foreground">
                  Receive scan results via HTTP callbacks
                </p>
              </div>
              <div className="rounded-xl border border-border bg-card p-6">
                <div className="text-center py-8">
                  <Webhook className="mx-auto h-10 w-10 text-muted-foreground mb-3" />
                  <p className="text-sm font-medium">No webhooks configured</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Webhooks will POST scan results to your URL when scans
                    complete.
                  </p>
                  <button className="mt-4 rounded-lg border border-border px-4 py-2.5 text-sm font-medium hover:bg-secondary transition flex items-center gap-2 mx-auto">
                    <Plus className="h-4 w-4" />
                    Add Webhook
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
