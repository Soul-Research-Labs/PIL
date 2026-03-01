import axios from "axios";
import type {
  DashboardStats,
  Finding,
  Project,
  QuickScanRequest,
  QuickScanResult,
  Scan,
} from "@/types";

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api",
  headers: { "Content-Type": "application/json" },
});

// Auto-attach auth token
api.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("zaseon_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// ─── Projects ──────────────────────────────────────────────────
export async function getProjects(): Promise<Project[]> {
  const { data } = await api.get("/v1/projects");
  return data;
}

export async function getProject(id: string): Promise<Project> {
  const { data } = await api.get(`/v1/projects/${id}`);
  return data;
}

export async function createProject(params: {
  name: string;
  source_type: string;
  github_url?: string;
  contract_address?: string;
  chain?: string;
}): Promise<Project> {
  const { data } = await api.post("/v1/projects", params);
  return data;
}

export async function deleteProject(id: string): Promise<void> {
  await api.delete(`/v1/projects/${id}`);
}

// ─── Scans ─────────────────────────────────────────────────────
export async function getScans(projectId?: string): Promise<Scan[]> {
  const params = projectId ? { project_id: projectId } : {};
  const { data } = await api.get("/v1/scans", { params });
  return data;
}

export async function getScan(id: string): Promise<Scan> {
  const { data } = await api.get(`/v1/scans/${id}`);
  return data;
}

export async function createScan(params: {
  project_id: string;
  scan_type: string;
  branch?: string;
}): Promise<Scan> {
  const { data } = await api.post("/v1/scans", params);
  return data;
}

// ─── Findings ──────────────────────────────────────────────────
export async function getFindings(params?: {
  scan_id?: string;
  severity?: string;
  status?: string;
}): Promise<Finding[]> {
  const { data } = await api.get("/v1/findings", { params });
  return data;
}

export async function getFinding(id: string): Promise<Finding> {
  const { data } = await api.get(`/v1/findings/${id}`);
  return data;
}

export async function updateFindingStatus(
  id: string,
  status: string,
): Promise<Finding> {
  const { data } = await api.patch(`/v1/findings/${id}`, { status });
  return data;
}

// ─── QuickScan ─────────────────────────────────────────────────
export async function quickScanAddress(
  address: string,
  chain: string,
): Promise<QuickScanResult> {
  const { data } = await api.post("/v1/quickscan/address", { address, chain });
  return data;
}

export async function quickScanSource(
  source_code: string,
  contract_name?: string,
): Promise<QuickScanResult> {
  const { data } = await api.post("/v1/quickscan/source", {
    source_code,
    contract_name,
  });
  return data;
}

export async function deepScan(params: {
  contract_address?: string;
  chain?: string;
  source_code?: string;
  filename?: string;
}): Promise<QuickScanResult> {
  const { data } = await api.post("/v1/quickscan/deep", params);
  return data;
}

export async function getChains(): Promise<
  Array<{ id: string; name: string }>
> {
  const { data } = await api.get("/v1/quickscan/chains");
  return data;
}

// ─── Reports ───────────────────────────────────────────────────
export async function generateReport(scanId: string): Promise<{ url: string }> {
  const { data } = await api.post("/v1/reports/generate", { scan_id: scanId });
  return data;
}

export async function getPublicReport(slug: string): Promise<unknown> {
  const { data } = await api.get(`/v1/reports/public/${slug}`);
  return data;
}

// ─── Dashboard Stats ───────────────────────────────────────────
export async function getDashboardStats(): Promise<DashboardStats> {
  const { data } = await api.get("/v1/dashboard/stats");
  return data;
}

// ─── Health ────────────────────────────────────────────────────
export async function healthCheck(): Promise<{ status: string }> {
  const { data } = await api.get("/health");
  return data;
}

// ─── Soul Protocol Fuzzer ──────────────────────────────────────
import type {
  SoulFuzzResult,
  SoulStaticScanResult,
  SoulInvariant,
  SoulDetector,
  SoulProtocolModel,
  SoulConcolicResult,
  SoulDifferentialResult,
  SoulSymbolicResult,
  SoulPropertyTestResult,
  SoulForgeStatus,
  SoulMutationType,
  SoulPowerSchedule,
  SoulBytecodeAnalysisResult,
  SoulTaintAnalysisResult,
  SoulGasProfileResult,
  SoulEngineStatus,
  SoulCampaignStatus,
  SoulFinding,
  SoulInvariantReport,
  SoulBytecodeReport,
  SoulGasProfile,
  SoulExploitChain,
} from "@/types/soul";

export async function soulFuzz(params: {
  source_code: string;
  contract_name?: string;
  mode?: string;
  max_duration_sec?: number;
  max_iterations?: number;
  target_functions?: string[];
  target_invariants?: string[];
  enable_llm?: boolean;
  enable_static_scan?: boolean;
  enable_symbolic?: boolean;
  enable_concolic?: boolean;
  enable_forge?: boolean;
  enable_property_testing?: boolean;
  enable_advanced_corpus?: boolean;
  // v2 engine toggles
  enable_bytecode_analysis?: boolean;
  enable_taint_analysis?: boolean;
  enable_gas_profiling?: boolean;
  enable_invariant_synthesis?: boolean;
  enable_state_replay?: boolean;
  enable_exploit_composition?: boolean;
  power_schedule?: string;
  bytecode?: string;
}): Promise<SoulFuzzResult> {
  const { data } = await api.post("/v1/soul/fuzz", params);
  return data;
}

export async function soulQuickFuzz(params: {
  source_code: string;
  contract_name?: string;
}): Promise<SoulFuzzResult> {
  const { data } = await api.post("/v1/soul/quick-fuzz", params);
  return data;
}

export async function soulTargetedFuzz(params: {
  source_code: string;
  contract_name?: string;
  target_function?: string;
  target_invariant?: string;
  max_duration_sec?: number;
}): Promise<SoulFuzzResult> {
  const { data } = await api.post("/v1/soul/targeted-fuzz", params);
  return data;
}

export async function soulConcolic(params: {
  source_code: string;
  contract_name?: string;
  max_duration_sec?: number;
  max_iterations?: number;
  search_strategy?: string;
  enable_forge?: boolean;
}): Promise<SoulConcolicResult> {
  const { data } = await api.post("/v1/soul/concolic", params);
  return data;
}

export async function soulDifferential(params: {
  source_code: string;
  contract_name?: string;
  previous_source: string;
  previous_name?: string;
  max_duration_sec?: number;
  diff_types?: string[];
}): Promise<SoulDifferentialResult> {
  const { data } = await api.post("/v1/soul/differential", params);
  return data;
}

export async function soulSymbolic(params: {
  source_code: string;
  contract_name?: string;
  max_paths?: number;
  timeout_sec?: number;
  target_functions?: string[];
}): Promise<SoulSymbolicResult> {
  const { data } = await api.post("/v1/soul/symbolic", params);
  return data;
}

export async function soulPropertyTest(params: {
  source_code: string;
  contract_name?: string;
  property_types?: string[];
  max_sequences?: number;
  max_seq_length?: number;
}): Promise<SoulPropertyTestResult> {
  const { data } = await api.post("/v1/soul/property-test", params);
  return data;
}

export async function soulStaticScan(params: {
  source_code: string;
  contract_name?: string;
}): Promise<SoulStaticScanResult> {
  const { data } = await api.post("/v1/soul/scan", params);
  return data;
}

export async function getSoulCampaign(
  campaignId: string,
): Promise<SoulFuzzResult> {
  const { data } = await api.get(`/v1/soul/campaign/${campaignId}`);
  return data;
}

export function streamSoulCampaign(
  campaignId: string,
  onUpdate: (data: Record<string, unknown>) => void,
  onDone?: () => void,
): () => void {
  const baseUrl =
    process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";
  const url = `${baseUrl}/v1/soul/campaign/${campaignId}/stream`;

  // Use fetch + ReadableStream instead of EventSource so we can send the
  // Authorization header.  EventSource does not support custom headers.
  const controller = new AbortController();

  const token =
    typeof window !== "undefined" ? localStorage.getItem("zaseon_token") : null;

  (async () => {
    try {
      const res = await fetch(url, {
        headers: {
          Accept: "text/event-stream",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        signal: controller.signal,
      });

      if (!res.ok || !res.body) {
        onDone?.();
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        // Keep the last (possibly incomplete) line in the buffer
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.startsWith("data:")) continue;
          const payload = line.slice(5).trim();
          if (!payload) continue;
          try {
            const parsed = JSON.parse(payload);
            onUpdate(parsed);
            if (parsed.status === "completed" || parsed.status === "failed") {
              controller.abort();
              onDone?.();
              return;
            }
          } catch {
            // skip malformed
          }
        }
      }

      onDone?.();
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      onDone?.();
    }
  })();

  // Return cleanup function
  return () => controller.abort();
}

export async function getSoulInvariants(): Promise<SoulInvariant[]> {
  const { data } = await api.get("/v1/soul/invariants");
  return data;
}

export async function getSoulDetectors(): Promise<SoulDetector[]> {
  const { data } = await api.get("/v1/soul/detectors");
  return data;
}

export async function getSoulMutationTypes(): Promise<SoulMutationType[]> {
  const { data } = await api.get("/v1/soul/mutation-types");
  return data;
}

export async function getSoulPowerSchedules(): Promise<SoulPowerSchedule[]> {
  const { data } = await api.get("/v1/soul/power-schedules");
  return data;
}

export async function getSoulForgeStatus(): Promise<SoulForgeStatus> {
  const { data } = await api.get("/v1/soul/forge-status");
  return data;
}

export async function getSoulProtocolModel(): Promise<SoulProtocolModel> {
  const { data } = await api.get("/v1/soul/protocol-model");
  return data;
}

// ─── Soul Protocol v2 Engine Endpoints ─────────────────────────

export async function soulBytecodeAnalysis(params: {
  bytecode: string;
  contract_name?: string;
}): Promise<SoulBytecodeAnalysisResult> {
  const { data } = await api.post("/v1/soul/bytecode-analysis", params);
  return data;
}

export async function soulTaintAnalysis(params: {
  source_code: string;
  contract_name?: string;
  target_functions?: string[];
}): Promise<SoulTaintAnalysisResult> {
  const { data } = await api.post("/v1/soul/taint-analysis", params);
  return data;
}

export async function soulGasProfile(params: {
  source_code: string;
  contract_name?: string;
  max_iterations?: number;
}): Promise<SoulGasProfileResult> {
  const { data } = await api.post("/v1/soul/gas-profile", params);
  return data;
}

export async function getSoulEngineStatus(): Promise<SoulEngineStatus> {
  const { data } = await api.get("/v1/soul/engine-status");
  return data;
}

// ─── Soul Campaign Management (used by useSoulFuzzer hook) ─────

export async function createSoulCampaign(params: {
  source_type: string;
  contract_source?: string;
  repo_url?: string;
  contract_address?: string;
  chain?: string;
  mode?: string;
}): Promise<{ campaign_id: string; id?: string }> {
  const { data } = await api.post("/v1/soul/fuzz", {
    source_code: params.contract_source || "",
    mode: params.mode || "standard",
  });
  return data;
}

export async function getSoulCampaignStatus(
  campaignId: string,
): Promise<SoulCampaignStatus> {
  const { data } = await api.get(`/v1/soul/campaign/${campaignId}`);
  return data;
}

export async function getSoulCampaignFindings(
  campaignId: string,
): Promise<SoulFinding[]> {
  const { data } = await api.get(`/v1/soul/campaign/${campaignId}`);
  return data.static_findings || data.findings || [];
}

export async function getSoulInvariantReport(
  campaignId: string,
): Promise<SoulInvariantReport> {
  const { data } = await api.get(`/v1/soul/campaign/${campaignId}`);
  return {
    campaign_id: campaignId,
    total_synthesized: data.synthesized_invariants?.length || 0,
    novel_invariants:
      data.synthesized_invariants?.filter(
        (i: { is_novel: boolean }) => i.is_novel,
      ).length || 0,
    invariants: data.synthesized_invariants || [],
    high_confidence:
      data.synthesized_invariants?.filter(
        (i: { confidence: number }) => i.confidence > 0.8,
      ) || [],
  };
}

export async function getSoulBytecodeReport(
  campaignId: string,
): Promise<SoulBytecodeReport> {
  const { data } = await api.get(`/v1/soul/campaign/${campaignId}`);
  return {
    campaign_id: campaignId,
    analysis: data.bytecode_analysis || {},
    soul_patterns_found: data.bytecode_analysis?.soul_patterns?.length || 0,
    delegate_calls_found: data.bytecode_analysis?.delegate_calls?.length || 0,
  };
}

export async function getSoulGasProfile(
  campaignId: string,
): Promise<SoulGasProfile> {
  const { data } = await api.get(`/v1/soul/campaign/${campaignId}`);
  return {
    campaign_id: campaignId,
    profile: data.gas_profile || {},
    dos_vectors: data.dos_vectors || [],
    top_hotspots: data.gas_profile?.hotspots?.slice(0, 10) || [],
  };
}

export async function getSoulExploitChains(
  campaignId: string,
): Promise<SoulExploitChain[]> {
  const { data } = await api.get(`/v1/soul/campaign/${campaignId}`);
  return data.exploit_chains || [];
}

// ── Organizations ───────────────────────────────────────────────────────────

import type {
  Organization,
  OrgMember,
  OrgInvite,
  OrgUsage,
  OrgRole,
  AuditLogEntry,
  AuditSummary,
  ComplianceReport,
  NLQueryRequest,
  NLQueryResult,
  NLQueryExample,
  NotificationConfig,
  ScanDiffResult,
} from "@/types";

export async function getOrganizations(): Promise<Organization[]> {
  const { data } = await api.get("/v1/orgs/");
  return data;
}

export async function getOrganization(slug: string): Promise<Organization> {
  const { data } = await api.get(`/v1/orgs/${slug}`);
  return data;
}

export async function createOrganization(
  name: string,
  slug: string,
): Promise<Organization> {
  const { data } = await api.post("/v1/orgs/", { name, slug });
  return data;
}

export async function updateOrganization(
  slug: string,
  update: { name?: string },
): Promise<Organization> {
  const { data } = await api.patch(`/v1/orgs/${slug}`, update);
  return data;
}

export async function deleteOrganization(slug: string): Promise<void> {
  await api.delete(`/v1/orgs/${slug}`);
}

export async function getOrgMembers(slug: string): Promise<OrgMember[]> {
  const { data } = await api.get(`/v1/orgs/${slug}/members`);
  return data;
}

export async function inviteOrgMember(
  slug: string,
  invite: OrgInvite,
): Promise<OrgMember> {
  const { data } = await api.post(`/v1/orgs/${slug}/members`, invite);
  return data;
}

export async function updateMemberRole(
  slug: string,
  userId: string,
  role: OrgRole,
): Promise<OrgMember> {
  const { data } = await api.patch(`/v1/orgs/${slug}/members/${userId}`, {
    role,
  });
  return data;
}

export async function removeOrgMember(
  slug: string,
  userId: string,
): Promise<void> {
  await api.delete(`/v1/orgs/${slug}/members/${userId}`);
}

export async function getOrgUsage(slug: string): Promise<OrgUsage> {
  const { data } = await api.get(`/v1/orgs/${slug}/usage`);
  return data;
}

// ── Audit Trail ─────────────────────────────────────────────────────────────

export async function getAuditLogs(params?: {
  action?: string;
  severity?: string;
  resource_type?: string;
  actor_id?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}): Promise<AuditLogEntry[]> {
  const { data } = await api.get("/v1/audit/", { params });
  return data;
}

export async function getAuditSummary(params?: {
  since?: string;
  until?: string;
}): Promise<AuditSummary> {
  const { data } = await api.get("/v1/audit/summary", { params });
  return data;
}

export async function getComplianceReport(): Promise<ComplianceReport> {
  const { data } = await api.get("/v1/audit/compliance/report");
  return data;
}

// ── Natural Language Query ──────────────────────────────────────────────────

export async function nlQuery(
  query: string,
  orgId?: string,
): Promise<NLQueryResult> {
  const { data } = await api.post("/v1/query", { query, org_id: orgId });
  return data;
}

export async function nlQueryFollowup(
  query: string,
  previousQuery?: NLQueryResult["structured_query"],
  orgId?: string,
): Promise<NLQueryResult> {
  const { data } = await api.post("/v1/query/followup", {
    query,
    previous_query: previousQuery,
    org_id: orgId,
  });
  return data;
}

export async function nlQueryFeedback(
  originalQuery: string,
  wasCorrect: boolean,
  comment?: string,
): Promise<void> {
  await api.post("/v1/query/feedback", {
    original_query: originalQuery,
    was_correct: wasCorrect,
    comment,
  });
}

export async function getNLQueryExamples(): Promise<NLQueryExample[]> {
  const { data } = await api.get("/v1/query/examples");
  return data.examples;
}

// ── Notifications ───────────────────────────────────────────────────────────

export async function getNotificationConfigs(): Promise<NotificationConfig[]> {
  const { data } = await api.get("/v1/notifications/");
  return data;
}

export async function createNotificationConfig(
  config: Partial<NotificationConfig>,
): Promise<NotificationConfig> {
  const { data } = await api.post("/v1/notifications/", config);
  return data;
}

export async function deleteNotificationConfig(id: string): Promise<void> {
  await api.delete(`/v1/notifications/${id}`);
}

export async function testNotification(id: string): Promise<void> {
  await api.post(`/v1/notifications/${id}/test`);
}

// ── Scan Diff ───────────────────────────────────────────────────────────────

export async function getScanDiff(
  baseScanId: string,
  headScanId: string,
): Promise<ScanDiffResult> {
  const { data } = await api.get(`/v1/findings/diff`, {
    params: { base_scan_id: baseScanId, head_scan_id: headScanId },
  });
  return data;
}

// ── Analytics ───────────────────────────────────────────────────────────────

export interface TimeSeriesPoint {
  timestamp: string;
  value: number;
}

export interface ScoreTrend {
  timestamp: string;
  score: number;
  scan_id: string;
}

export interface AnalyticsSummary {
  total_scans: number;
  total_findings: number;
  avg_security_score: number;
  scans_trend: TimeSeriesPoint[];
  severity_trend: {
    timestamp: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  }[];
  top_categories: { category: string; count: number; trend: number }[];
  score_trend: ScoreTrend[];
  mttr: {
    overall_hours: number;
    by_severity: Record<string, number>;
    sample_size: number;
  };
  period_start: string;
  period_end: string;
}

export async function getAnalyticsSummary(params?: {
  days?: number;
  granularity?: "daily" | "weekly" | "monthly";
  project_id?: string;
}): Promise<AnalyticsSummary> {
  const { data } = await api.get("/v1/analytics/summary", { params });
  return data;
}

export async function getScanVolume(params?: {
  days?: number;
  granularity?: "daily" | "weekly" | "monthly";
}): Promise<TimeSeriesPoint[]> {
  const { data } = await api.get("/v1/analytics/scans/volume", { params });
  return data;
}

export async function getScoreTrend(params?: {
  days?: number;
  project_id?: string;
}): Promise<ScoreTrend[]> {
  const { data } = await api.get("/v1/analytics/scans/scores", { params });
  return data;
}

export async function getCacheStats(): Promise<Record<string, unknown>> {
  const { data } = await api.get("/v1/analytics/cache/stats");
  return data;
}

export default api;
