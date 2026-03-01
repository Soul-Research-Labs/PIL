/**
 * Zustand stores — lightweight, shared client-side state.
 *
 * Three stores are exported:
 *  - useAuthStore   — user / token / login / logout
 *  - useScanStore   — active scans cache + refetch helper
 *  - useUIStore     — sidebar collapsed, command palette open, etc.
 */
import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

// ── SSR-safe storage adapter ────────────────────────────────────────────────

const noopStorage: Storage = {
  length: 0,
  clear() {},
  getItem() {
    return null;
  },
  key() {
    return null;
  },
  removeItem() {},
  setItem() {},
};

function safeStorage(): Storage {
  return typeof window !== "undefined" ? localStorage : noopStorage;
}

// ── Types ───────────────────────────────────────────────────────────────────

interface AuthUser {
  id: string;
  username: string;
  email: string | null;
  display_name: string | null;
  avatar_url: string | null;
}

interface AuthState {
  user: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;

  /** Set the token (also persists to localStorage for the axios interceptor). */
  setToken: (token: string) => void;
  /** Set the user profile. */
  setUser: (user: AuthUser) => void;
  /** Login — sets both token and user. */
  login: (token: string, user: AuthUser) => void;
  /** Logout — clears everything and removes the persisted token. */
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      token: null,
      isAuthenticated: false,

      setToken: (token) => {
        // Keep localStorage in sync so the axios interceptor picks it up.
        if (typeof window !== "undefined") {
          localStorage.setItem("zaseon_token", token);
        }
        set({ token, isAuthenticated: true });
      },

      setUser: (user) => set({ user }),

      login: (token, user) => {
        if (typeof window !== "undefined") {
          localStorage.setItem("zaseon_token", token);
        }
        set({ token, user, isAuthenticated: true });
      },

      logout: () => {
        if (typeof window !== "undefined") {
          localStorage.removeItem("zaseon_token");
        }
        set({ token: null, user: null, isAuthenticated: false });
      },
    }),
    {
      name: "zaseon-auth",
      storage: createJSONStorage(() => safeStorage()),
      partialize: (s: AuthState) => ({ token: s.token, user: s.user }),
    },
  ),
);

// ── Scan Store ──────────────────────────────────────────────────────────────

interface ScanSummary {
  id: string;
  project_id: string;
  status: string;
  scan_type: string;
  security_score: number | null;
  findings_count: number;
  created_at: string;
}

interface ScanState {
  scans: ScanSummary[];
  activeIds: string[];
  lastFetched: number | null;

  /** Bulk-set the scan list. */
  setScans: (scans: ScanSummary[]) => void;
  /** Upsert a single scan (used by SSE / polling). */
  upsertScan: (scan: ScanSummary) => void;
  /** Mark a scan as actively running. */
  markActive: (id: string) => void;
  /** Remove a scan from the active set. */
  markInactive: (id: string) => void;
  /** Clear all scans. */
  clear: () => void;
}

export const useScanStore = create<ScanState>()((set) => ({
  scans: [],
  activeIds: [],
  lastFetched: null,

  setScans: (scans) =>
    set({
      scans,
      lastFetched: Date.now(),
      activeIds: scans.filter((s) => s.status === "running").map((s) => s.id),
    }),

  upsertScan: (scan) =>
    set((state) => {
      const idx = state.scans.findIndex((s) => s.id === scan.id);
      const next = [...state.scans];
      if (idx >= 0) {
        next[idx] = scan;
      } else {
        next.unshift(scan);
      }
      return { scans: next };
    }),

  markActive: (id) =>
    set((state) => ({
      activeIds: state.activeIds.includes(id)
        ? state.activeIds
        : [...state.activeIds, id],
    })),

  markInactive: (id) =>
    set((state) => ({
      activeIds: state.activeIds.filter((x) => x !== id),
    })),

  clear: () => set({ scans: [], activeIds: [], lastFetched: null }),
}));

// ── UI Store ────────────────────────────────────────────────────────────────

interface UIState {
  sidebarCollapsed: boolean;
  commandPaletteOpen: boolean;
  toggleSidebar: () => void;
  setCommandPalette: (open: boolean) => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      commandPaletteOpen: false,

      toggleSidebar: () =>
        set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setCommandPalette: (open) => set({ commandPaletteOpen: open }),
    }),
    {
      name: "zaseon-ui",
      storage: createJSONStorage(() => safeStorage()),
      partialize: (s: UIState) => ({ sidebarCollapsed: s.sidebarCollapsed }),
    },
  ),
);
