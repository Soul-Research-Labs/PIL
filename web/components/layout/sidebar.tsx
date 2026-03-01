"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useSession, signOut } from "next-auth/react";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  GitBranch,
  FileCode,
  Zap,
  Search,
  FileText,
  Settings,
  Shield,
  LogOut,
  Building2,
  ScrollText,
  MessageSquare,
  BarChart3,
} from "lucide-react";

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/repos", label: "Repositories", icon: GitBranch },
  { href: "/contracts", label: "Contracts", icon: FileCode },
  { href: "/soul", label: "Soul Fuzzer", icon: Shield },
  { href: "/quickscan", label: "QuickScan", icon: Zap },
  { href: "/scans", label: "Scan History", icon: Search },
  { href: "/organizations", label: "Organizations", icon: Building2 },
  { href: "/audit", label: "Audit & Compliance", icon: ScrollText },
  { href: "/ask", label: "Ask", icon: MessageSquare },
  { href: "/analytics", label: "Analytics", icon: BarChart3 },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { data: session } = useSession();
  const user = session?.user;

  return (
    <aside className="flex h-screen w-64 flex-col border-r border-border bg-card">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-6 py-5 border-b border-border">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-white font-bold">
          Z
        </div>
        <div>
          <div className="text-lg font-bold">ZASEON</div>
          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">
            Security Scanner
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navItems.map((item) => {
          const isActive =
            pathname === item.href || pathname.startsWith(item.href + "/");
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-secondary hover:text-foreground",
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-border p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-secondary text-sm font-medium">
            {user?.image ? (
              <img src={user.image} alt="" className="h-8 w-8 rounded-full" />
            ) : (
              (user?.name?.[0] || "U").toUpperCase()
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium truncate">
              {user?.name || "User"}
            </div>
            <div className="text-xs text-muted-foreground truncate">
              {user?.email || "Sign in to get started"}
            </div>
          </div>
          <button
            onClick={() => signOut({ callbackUrl: "/auth/signin" })}
            className="text-muted-foreground hover:text-foreground"
            title="Sign out"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
