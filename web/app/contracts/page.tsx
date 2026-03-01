"use client";

import { Header } from "@/components/layout/header";
import { cn, scoreColor, truncateAddress, CHAINS } from "@/lib/utils";
import {
  FileCode,
  Plus,
  ExternalLink,
  Shield,
  Clock,
  Loader2,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getProjects } from "@/lib/api";
import Link from "next/link";

export default function ContractsPage() {
  const { data: allProjects, isLoading } = useQuery({
    queryKey: ["projects"],
    queryFn: getProjects,
  });

  // Filter to contract_address source_type
  const contracts = (allProjects || []).filter(
    (p) => p.source_type === "contract_address" && p.contract_address,
  );

  return (
    <div>
      <Header title="Smart Contracts" />

      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            {isLoading ? "Loading…" : `${contracts.length} contracts tracked`}
          </p>
          <Link
            href="/quickscan"
            className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition"
          >
            <Plus className="h-4 w-4" />
            Scan Contract
          </Link>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : contracts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <FileCode className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold">No contracts tracked</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Use QuickScan to analyze a contract by address or source code.
            </p>
            <Link
              href="/quickscan"
              className="mt-4 flex items-center gap-2 rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition"
            >
              <Plus className="h-4 w-4" />
              QuickScan
            </Link>
          </div>
        ) : (
          <div className="space-y-3">
            {contracts.map((contract) => {
              const chainInfo = contract.chain
                ? CHAINS[contract.chain]
                : undefined;
              return (
                <Link
                  key={contract.id}
                  href={`/repos/${contract.id}`}
                  className="flex items-center gap-4 rounded-xl border border-border bg-card p-5 hover:border-primary/30 transition"
                >
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-secondary text-lg">
                    {chainInfo?.icon || "⟠"}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold">{contract.name}</h3>
                      {chainInfo && (
                        <span className="rounded bg-secondary px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
                          {chainInfo.name}
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 flex items-center gap-3 text-xs text-muted-foreground">
                      {contract.contract_address && chainInfo && (
                        <span className="flex items-center gap-1 font-mono">
                          <ExternalLink className="h-3 w-3" />
                          {truncateAddress(contract.contract_address)}
                        </span>
                      )}
                      {contract.created_at && (
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {new Date(contract.created_at).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
