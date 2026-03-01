/**
 * React hook for Soul Protocol fuzzer campaign management.
 *
 * Provides campaign CRUD, real-time status polling, and
 * access to all v2 engine reports (bytecode, invariants, gas, exploits).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  createSoulCampaign,
  getSoulCampaignStatus,
  getSoulCampaignFindings,
  getSoulInvariantReport,
  getSoulBytecodeReport,
  getSoulGasProfile,
  getSoulExploitChains,
} from "@/lib/api";
import type {
  SoulCampaignStatus,
  SoulFinding,
  SoulInvariantReport,
  SoulBytecodeReport,
  SoulGasProfile,
  SoulExploitChain,
} from "@/types/soul";

// ── Types ───────────────────────────────────────────────────────────────────

export interface CampaignCreateParams {
  source_type: "file_upload" | "github_repo" | "contract_address";
  contract_source?: string;
  repo_url?: string;
  contract_address?: string;
  chain?: string;
  mode?: "quick" | "standard" | "deep" | "exhaustive";
}

export interface UseSoulFuzzerOptions {
  /** Polling interval in ms (default 3000) */
  pollInterval?: number;
  /** Auto-start polling on campaign creation */
  autoPolling?: boolean;
  /** Stop polling when campaign completes */
  stopOnComplete?: boolean;
}

export interface UseSoulFuzzerReturn {
  // State
  campaignId: string | null;
  status: SoulCampaignStatus | null;
  findings: SoulFinding[];
  isLoading: boolean;
  isPolling: boolean;
  error: string | null;

  // Actions
  createCampaign: (params: CampaignCreateParams) => Promise<string | null>;
  refreshStatus: () => Promise<void>;
  refreshFindings: () => Promise<void>;
  startPolling: () => void;
  stopPolling: () => void;
  reset: () => void;
}

// ── Hook ────────────────────────────────────────────────────────────────────

export function useSoulFuzzer(
  options: UseSoulFuzzerOptions = {},
): UseSoulFuzzerReturn {
  const {
    pollInterval = 3000,
    autoPolling = true,
    stopOnComplete = true,
  } = options;

  const [campaignId, setCampaignId] = useState<string | null>(null);
  const [status, setStatus] = useState<SoulCampaignStatus | null>(null);
  const [findings, setFindings] = useState<SoulFinding[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isPolling, setIsPolling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const campaignIdRef = useRef<string | null>(null);

  // Keep ref in sync
  useEffect(() => {
    campaignIdRef.current = campaignId;
  }, [campaignId]);

  // ── Status Refresh ──────────────────────────────────────────────────

  const refreshStatus = useCallback(async () => {
    const id = campaignIdRef.current;
    if (!id) return;

    try {
      const data = await getSoulCampaignStatus(id);
      setStatus(data);

      // Auto-stop on terminal states
      if (
        stopOnComplete &&
        data &&
        ["completed", "failed", "cancelled"].includes(data.status)
      ) {
        stopPolling();
      }
    } catch (err: any) {
      setError(err.message || "Failed to fetch campaign status");
    }
  }, [stopOnComplete]);

  // ── Findings Refresh ────────────────────────────────────────────────

  const refreshFindings = useCallback(async () => {
    const id = campaignIdRef.current;
    if (!id) return;

    try {
      const data = await getSoulCampaignFindings(id);
      setFindings(data || []);
    } catch (err: any) {
      setError(err.message || "Failed to fetch findings");
    }
  }, []);

  // ── Polling ─────────────────────────────────────────────────────────

  const startPolling = useCallback(() => {
    if (pollingRef.current) return; // already polling

    setIsPolling(true);
    pollingRef.current = setInterval(async () => {
      await refreshStatus();
      await refreshFindings();
    }, pollInterval);
  }, [pollInterval, refreshStatus, refreshFindings]);

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
    setIsPolling(false);
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, []);

  // ── Create Campaign ─────────────────────────────────────────────────

  const createCampaign = useCallback(
    async (params: CampaignCreateParams): Promise<string | null> => {
      setIsLoading(true);
      setError(null);

      try {
        const result = await createSoulCampaign(params);
        const id = result?.campaign_id || result?.id;

        if (id) {
          setCampaignId(id);
          if (autoPolling) {
            // Small delay before starting to poll
            setTimeout(() => startPolling(), 1000);
          }
          return id;
        }

        setError("Campaign creation returned no ID");
        return null;
      } catch (err: any) {
        setError(err.message || "Failed to create campaign");
        return null;
      } finally {
        setIsLoading(false);
      }
    },
    [autoPolling, startPolling],
  );

  // ── Reset ───────────────────────────────────────────────────────────

  const reset = useCallback(() => {
    stopPolling();
    setCampaignId(null);
    setStatus(null);
    setFindings([]);
    setError(null);
    setIsLoading(false);
  }, [stopPolling]);

  return {
    campaignId,
    status,
    findings,
    isLoading,
    isPolling,
    error,
    createCampaign,
    refreshStatus,
    refreshFindings,
    startPolling,
    stopPolling,
    reset,
  };
}

// ── Specialized v2 Engine Hooks ─────────────────────────────────────────────

/**
 * Hook for fetching the invariant synthesis report for a campaign.
 */
export function useSoulInvariantReport(campaignId: string | null) {
  const [data, setData] = useState<SoulInvariantReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    if (!campaignId) return;
    setIsLoading(true);
    setError(null);
    try {
      const report = await getSoulInvariantReport(campaignId);
      setData(report);
    } catch (err: any) {
      setError(err.message || "Failed to fetch invariant report");
    } finally {
      setIsLoading(false);
    }
  }, [campaignId]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { data, isLoading, error, refetch: fetch };
}

/**
 * Hook for fetching the bytecode analysis report.
 */
export function useSoulBytecodeReport(campaignId: string | null) {
  const [data, setData] = useState<SoulBytecodeReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    if (!campaignId) return;
    setIsLoading(true);
    setError(null);
    try {
      const report = await getSoulBytecodeReport(campaignId);
      setData(report);
    } catch (err: any) {
      setError(err.message || "Failed to fetch bytecode report");
    } finally {
      setIsLoading(false);
    }
  }, [campaignId]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { data, isLoading, error, refetch: fetch };
}

/**
 * Hook for fetching the gas profiling report.
 */
export function useSoulGasProfile(campaignId: string | null) {
  const [data, setData] = useState<SoulGasProfile | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    if (!campaignId) return;
    setIsLoading(true);
    setError(null);
    try {
      const report = await getSoulGasProfile(campaignId);
      setData(report);
    } catch (err: any) {
      setError(err.message || "Failed to fetch gas profile");
    } finally {
      setIsLoading(false);
    }
  }, [campaignId]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { data, isLoading, error, refetch: fetch };
}

/**
 * Hook for fetching exploit chain compositions.
 */
export function useSoulExploitChains(campaignId: string | null) {
  const [data, setData] = useState<SoulExploitChain[] | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    if (!campaignId) return;
    setIsLoading(true);
    setError(null);
    try {
      const chains = await getSoulExploitChains(campaignId);
      setData(chains);
    } catch (err: any) {
      setError(err.message || "Failed to fetch exploit chains");
    } finally {
      setIsLoading(false);
    }
  }, [campaignId]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { data, isLoading, error, refetch: fetch };
}
