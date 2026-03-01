export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "GAS";
export type ScanStatus =
  | "PENDING"
  | "CLONING"
  | "COMPILING"
  | "ANALYZING"
  | "VERIFYING"
  | "COMPLETED"
  | "FAILED";
export type ScanType = "SMART_CONTRACT";
export type FindingStatus =
  | "OPEN"
  | "CONFIRMED"
  | "FALSE_POSITIVE"
  | "MITIGATED"
  | "ACCEPTED";
export type Chain =
  | "ethereum"
  | "polygon"
  | "bsc"
  | "avalanche"
  | "arbitrum"
  | "optimism"
  | "base"
  | "zksync"
  | "linea"
  | "fantom"
  | "gnosis"
  | "scroll";

export interface Location {
  file: string;
  start_line: number;
  end_line: number;
  snippet?: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  cwe_id?: string;
  scwe_id?: string;
  location: Location;
  remediation: string;
  proof_of_concept?: string;
  confidence: number;
  status: FindingStatus;
  gas_saved?: number;
  verified?: boolean;
  metadata?: Record<string, unknown>;
}

export interface GasOptimization {
  description: string;
  suggestion: string;
  estimated_gas_saved: number;
  category: string;
  location?: Location;
}

export interface SecurityScore {
  score: number;
  threat_score: number;
  grade: string;
  breakdown: Record<string, number>;
}

export interface Scan {
  id: string;
  project_id: string;
  scan_type: ScanType;
  status: ScanStatus;
  trigger?: string;
  security_score?: number;
  threat_score?: number;
  findings_count: number;
  total_lines_scanned: number;
  commit_sha?: string;
  branch?: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface Project {
  id: string;
  name: string;
  description?: string;
  source_type: string;
  github_repo_url?: string;
  contract_address?: string;
  chain?: Chain;
  auto_scan_on_push?: boolean;
  created_at?: string;
}

export interface QuickScanRequest {
  type: "address" | "source";
  address?: string;
  chain?: Chain;
  source_code?: string;
  contract_name?: string;
}

export interface QuickScanResult {
  scan_id: string;
  security_score: number;
  threat_score: number;
  findings: Finding[];
  gas_optimizations: GasOptimization[];
  lines_of_code: number;
  scan_duration_ms: number;
  contract_name?: string;
  compiler_version?: string;
  contract_address?: string;
  chain?: string;
  findings_count?: number;
  findings_by_severity?: Record<string, number>;
  gas_optimizations_count?: number;
  analysis?: AnalysisMetadata;
}

export interface AnalysisMetadata {
  static_findings_count: number;
  llm_findings_count: number;
  ast_findings_count?: number;
  slither_findings_count?: number;
  total_after_dedup: number;
  llm_overall_risk?: string;
  llm_attack_surface?: string[];
  llm_contract_summary?: string;
  detectors_run: string[];
  findings_by_category: Record<string, number>;
  taint_flows_detected?: number;
  reentrancy_paths_detected?: number;
  call_graph_stats?: CallGraphStats;
  attack_paths_count?: number;
}

export interface CallGraphStats {
  total_functions: number;
  total_call_edges: number;
  entry_points: number;
  unreachable_functions: number;
  external_calls: number;
  delegatecalls: number;
  internal_calls: number;
  eth_transfers: number;
  avg_complexity: number;
}

export interface User {
  id: string;
  email: string;
  name: string;
  avatar_url?: string;
  github_username?: string;
  wallet_address?: string;
}

export interface DashboardStats {
  total_projects: number;
  total_scans: number;
  total_findings: number;
  critical_findings: number;
  avg_security_score: number;
  scans_this_month: number;
  recent_scans: Scan[];
  severity_distribution: Record<Severity, number>;
}

// ── Team Collaboration Types ──────────────────────────────────

export type AssignmentRole = "owner" | "reviewer" | "observer";
export type AssignmentStatus =
  | "assigned"
  | "in_progress"
  | "review"
  | "done"
  | "declined";

export interface FindingComment {
  id: string;
  finding_id: string;
  author_id: string;
  author_name?: string;
  parent_id?: string;
  body: string;
  mentions: string[];
  reactions: Record<string, string[]>;
  created_at: string;
  edited_at?: string;
}

export interface FindingAssignment {
  id: string;
  finding_id: string;
  assignee_id: string;
  assignee_name?: string;
  assigned_by_id: string;
  role: AssignmentRole;
  status: AssignmentStatus;
  due_date?: string;
  completed_at?: string;
  note?: string;
  created_at: string;
}

export interface SLAPolicy {
  id: string;
  name: string;
  is_default: boolean;
  triage_critical_mins: number;
  triage_high_mins: number;
  triage_medium_mins: number;
  triage_low_mins: number;
  remediate_critical_mins: number;
  remediate_high_mins: number;
  remediate_medium_mins: number;
  remediate_low_mins: number;
  escalation_rules: Record<string, unknown>;
  created_at: string;
}

export interface SLAStatus {
  finding_id: string;
  severity: string;
  policy_name: string;
  triage_deadline?: string;
  triaged_at?: string;
  triage_breached: boolean;
  triage_remaining_mins?: number;
  remediation_deadline?: string;
  remediated_at?: string;
  remediation_breached: boolean;
  remediation_remaining_mins?: number;
}

// ── v1.0.0 — Organizations ─────────────────────────────────────────────────

export type OrgRole = "viewer" | "editor" | "admin";
export type OrgTier = "free" | "pro" | "enterprise";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  logo_url?: string;
  created_at?: string;
  updated_at?: string;
  member_count: number;
  project_count: number;
}

export interface OrgMember {
  user_id: string;
  username: string;
  email?: string;
  role: OrgRole;
  joined_at?: string;
}

export interface OrgInvite {
  email: string;
  role: OrgRole;
}

export interface OrgUsage {
  org_id: string;
  slug: string;
  plan: string;
  projects: number;
  scans_this_month: number;
  findings_total: number;
  storage_bytes: number;
  members: number;
  limits: Record<string, number>;
}

// ── v1.0.0 — Audit Trail ───────────────────────────────────────────────────

export type AuditSeverity = "info" | "notice" | "warning" | "critical";

export type AuditAction =
  | "auth.login"
  | "auth.logout"
  | "auth.register"
  | "auth.api_key_created"
  | "auth.api_key_revoked"
  | "org.created"
  | "org.updated"
  | "org.deleted"
  | "org.member_invited"
  | "org.member_removed"
  | "org.member_role_changed"
  | "project.created"
  | "project.updated"
  | "project.deleted"
  | "project.archived"
  | "scan.created"
  | "scan.started"
  | "scan.completed"
  | "scan.failed"
  | "scan.cancelled"
  | "finding.created"
  | "finding.status_changed"
  | "finding.severity_changed"
  | "finding.assigned"
  | "finding.commented"
  | "report.generated"
  | "report.exported"
  | "campaign.started"
  | "campaign.completed"
  | "admin.settings_changed"
  | "admin.user_deactivated"
  | "data.exported";

export interface AuditLogEntry {
  id: string;
  action: string;
  severity: AuditSeverity;
  description: string;
  actor_email?: string;
  actor_ip?: string;
  resource_type: string;
  resource_id?: string;
  resource_name?: string;
  org_id?: string;
  old_value?: Record<string, unknown>;
  new_value?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  request_id?: string;
  endpoint?: string;
  http_method?: string;
  created_at?: string;
}

export interface AuditSummary {
  total_events: number;
  by_action: Record<string, number>;
  by_severity: Record<string, number>;
  by_resource_type: Record<string, number>;
  unique_actors: number;
  time_range: { since?: string; until?: string };
}

// ── v1.0.0 — Compliance ────────────────────────────────────────────────────

export type ControlStatus = "pass" | "fail" | "partial" | "n_a" | "pending";

export interface ComplianceControl {
  id: string;
  name: string;
  category: string;
  status: ControlStatus;
  evidence_count: number;
  remediation?: string;
  details?: string;
  description?: string;
}

export interface ComplianceReport {
  generated_at: string;
  overall_status: ControlStatus;
  compliance_pct: number;
  pass_count: number;
  fail_count: number;
  total_controls: number;
  controls: ComplianceControl[];
}

// ── v1.0.0 — Natural Language Query ─────────────────────────────────────────

export interface NLQueryRequest {
  query: string;
  org_id?: string;
}

export interface StructuredQuery {
  target: "findings" | "scans" | "projects" | "metrics";
  filters: Record<string, unknown>;
  sort_by: string;
  sort_order: "asc" | "desc";
  limit: number;
  aggregation: string;
  group_by: string;
  time_range_start: string;
  time_range_end: string;
}

export interface NLQueryResult {
  structured_query: StructuredQuery;
  data: Record<string, unknown>[];
  total_count: number;
  summary: string;
  execution_time_ms: number;
  markdown_table: string;
  original_query?: string;
}

export interface NLQueryExample {
  query: string;
  description: string;
}

// ── v1.0.0 — Notifications ─────────────────────────────────────────────────

export type NotificationChannel = "slack" | "discord" | "pagerduty" | "email";

export interface NotificationConfig {
  id: string;
  channel: NotificationChannel;
  name: string;
  enabled: boolean;
  webhook_url?: string;
  min_severity: Severity;
  events: string[];
  created_at: string;
}

// ── v1.0.0 — Plugins ───────────────────────────────────────────────────────

export interface Plugin {
  name: string;
  version: string;
  description: string;
  enabled: boolean;
  provides_detectors: boolean;
  provides_mutations: boolean;
  hooks: string[];
  config_schema?: Record<string, unknown>;
}

// ── v1.0.0 — Scan Diff ─────────────────────────────────────────────────────

export type DiffCategory = "new" | "resolved" | "persistent" | "regression";

export interface FindingDiff {
  finding_id: string;
  title: string;
  severity: Severity;
  category: DiffCategory;
  changes: Record<string, { old: string; new: string }>;
}

export interface ScanDiffResult {
  base_scan_id: string;
  head_scan_id: string;
  new_findings: FindingDiff[];
  resolved_findings: FindingDiff[];
  persistent_findings: FindingDiff[];
  regressions: FindingDiff[];
  summary: {
    new_count: number;
    resolved_count: number;
    persistent_count: number;
    regression_count: number;
  };
}
