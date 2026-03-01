"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Bell, Search, FileText, FolderGit2, Bug, X } from "lucide-react";
import { getProjects, getScans, getFindings } from "@/lib/api";

interface SearchResult {
  type: "project" | "scan" | "finding";
  id: string;
  title: string;
  subtitle?: string;
  href: string;
}

export function Header({ title }: { title: string }) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const search = useCallback(async (q: string) => {
    if (!q.trim()) {
      setResults([]);
      return;
    }
    setLoading(true);
    try {
      const lower = q.toLowerCase();
      const [projects, scans, findings] = await Promise.all([
        getProjects().catch(() => []),
        getScans().catch(() => []),
        getFindings().catch(() => []),
      ]);

      const matched: SearchResult[] = [];

      for (const p of projects) {
        if (
          p.name.toLowerCase().includes(lower) ||
          p.contract_address?.toLowerCase().includes(lower)
        ) {
          matched.push({
            type: "project",
            id: p.id,
            title: p.name,
            subtitle: p.source_type,
            href: `/repos/${p.id}`,
          });
        }
      }

      for (const s of scans) {
        const label = `${s.scan_type} — ${s.status}`;
        if (
          label.toLowerCase().includes(lower) ||
          s.branch?.toLowerCase().includes(lower)
        ) {
          matched.push({
            type: "scan",
            id: s.id,
            title: `Scan ${s.id.slice(0, 8)}`,
            subtitle: `${s.status} — ${s.findings_count} findings`,
            href: `/scans/${s.id}`,
          });
        }
      }

      for (const f of findings) {
        if (
          f.title.toLowerCase().includes(lower) ||
          f.category?.toLowerCase().includes(lower) ||
          f.cwe_id?.toLowerCase().includes(lower)
        ) {
          matched.push({
            type: "finding",
            id: f.id,
            title: f.title,
            subtitle: `${f.severity} — ${f.category}`,
            href: `/findings/${f.id}`,
          });
        }
      }

      setResults(matched.slice(0, 8));
    } catch {
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // Debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      if (query) search(query);
      else setResults([]);
    }, 300);
    return () => clearTimeout(timer);
  }, [query, search]);

  // Close on click outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const iconForType = (type: string) => {
    switch (type) {
      case "project":
        return <FolderGit2 className="h-4 w-4 text-muted-foreground" />;
      case "scan":
        return <FileText className="h-4 w-4 text-muted-foreground" />;
      case "finding":
        return <Bug className="h-4 w-4 text-muted-foreground" />;
      default:
        return null;
    }
  };

  return (
    <header className="flex items-center justify-between border-b border-border px-6 py-4">
      <h1 className="text-xl font-bold">{title}</h1>
      <div className="flex items-center gap-4">
        <div ref={containerRef} className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setOpen(true);
            }}
            onFocus={() => query && setOpen(true)}
            placeholder="Search scans, findings..."
            className="h-9 w-64 rounded-lg border border-border bg-secondary pl-9 pr-8 text-sm outline-none focus:border-primary focus:ring-1 focus:ring-primary"
          />
          {query && (
            <button
              onClick={() => {
                setQuery("");
                setResults([]);
                setOpen(false);
              }}
              className="absolute right-2.5 top-1/2 -translate-y-1/2"
            >
              <X className="h-3.5 w-3.5 text-muted-foreground hover:text-foreground" />
            </button>
          )}

          {open && (query || results.length > 0) && (
            <div className="absolute right-0 top-full mt-1.5 w-80 rounded-xl border border-border bg-card shadow-lg z-50 overflow-hidden">
              {loading ? (
                <div className="px-4 py-6 text-center text-xs text-muted-foreground">
                  Searching...
                </div>
              ) : results.length === 0 && query ? (
                <div className="px-4 py-6 text-center text-xs text-muted-foreground">
                  No results for &quot;{query}&quot;
                </div>
              ) : (
                <ul className="max-h-72 overflow-y-auto py-1">
                  {results.map((r) => (
                    <li key={`${r.type}-${r.id}`}>
                      <button
                        onClick={() => {
                          router.push(r.href);
                          setOpen(false);
                          setQuery("");
                        }}
                        className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-secondary transition text-sm"
                      >
                        {iconForType(r.type)}
                        <div className="min-w-0 flex-1">
                          <p className="truncate font-medium">{r.title}</p>
                          {r.subtitle && (
                            <p className="truncate text-xs text-muted-foreground">
                              {r.subtitle}
                            </p>
                          )}
                        </div>
                        <span className="shrink-0 rounded bg-secondary px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground uppercase">
                          {r.type}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
        <button className="relative rounded-lg p-2 hover:bg-secondary transition">
          <Bell className="h-4 w-4 text-muted-foreground" />
          <span className="absolute right-1 top-1 h-2 w-2 rounded-full bg-critical" />
        </button>
      </div>
    </header>
  );
}
