/**
 * Hook for scan result queries — wraps React Query for
 * scan status, findings list, and report generation.
 */

import { useCallback, useEffect, useState } from "react";

// ── Types ───────────────────────────────────────────────────────────────────

export interface ScanResult {
  id: string;
  status: string;
  security_score: number | null;
  threat_score: number | null;
  findings_count: number;
  total_lines_scanned: number;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanFinding {
  id: string;
  title: string;
  severity: string;
  status: string;
  category: string;
  file_path: string;
  start_line: number;
  end_line: number;
  description: string;
  remediation: string;
}

// ── Hook ────────────────────────────────────────────────────────────────────

export interface UseScanResultsOptions {
  scanId: string | null;
  autoFetch?: boolean;
}

export interface UseScanResultsReturn {
  scan: ScanResult | null;
  findings: ScanFinding[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export function useScanResults({
  scanId,
  autoFetch = true,
}: UseScanResultsOptions): UseScanResultsReturn {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    if (!scanId) return;
    setIsLoading(true);
    setError(null);

    try {
      const [scanRes, findingsRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/scans/${scanId}`),
        fetch(`${API_BASE}/api/v1/scans/${scanId}/findings`),
      ]);

      if (scanRes.ok) {
        setScan(await scanRes.json());
      }
      if (findingsRes.ok) {
        setFindings(await findingsRes.json());
      }
    } catch (err: any) {
      setError(err.message || "Failed to fetch scan results");
    } finally {
      setIsLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    if (autoFetch && scanId) {
      fetchData();
    }
  }, [autoFetch, scanId, fetchData]);

  return { scan, findings, isLoading, error, refetch: fetchData };
}
