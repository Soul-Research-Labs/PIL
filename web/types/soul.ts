// Soul Protocol types for the advanced fuzzer UI

// ── Request types ────────────────────────────────────────────────

export interface SoulFuzzRequest {
  source_code: string;
  contract_name: string;
  mode:
    | "quick"
    | "standard"
    | "deep"
    | "targeted"
    | "concolic"
    | "differential"
    | "symbolic"
    | "property";
  max_duration_sec: number;
  max_iterations: number;
  target_functions: string[];
  target_invariants: string[];
  enable_llm: boolean;
  enable_static_scan: boolean;
  enable_symbolic: boolean;
  enable_concolic: boolean;
  enable_forge: boolean;
  enable_property_testing: boolean;
  enable_advanced_corpus: boolean;
  // v2 engine toggles
  enable_bytecode_analysis: boolean;
  enable_taint_analysis: boolean;
  enable_gas_profiling: boolean;
  enable_invariant_synthesis: boolean;
  enable_state_replay: boolean;
  enable_exploit_composition: boolean;
  power_schedule: PowerSchedule;
  additional_sources: Record<string, string>;
  bytecode?: string;
}

export interface SoulConcolicRequest {
  source_code: string;
  contract_name: string;
  max_duration_sec: number;
  max_iterations: number;
  search_strategy: SearchStrategy;
  enable_forge: boolean;
  additional_sources: Record<string, string>;
}

export interface SoulDifferentialRequest {
  source_code: string;
  contract_name: string;
  previous_source: string;
  previous_name: string;
  max_duration_sec: number;
  diff_types: string[];
  additional_sources: Record<string, string>;
}

export interface SoulSymbolicRequest {
  source_code: string;
  contract_name: string;
  max_paths: number;
  timeout_sec: number;
  target_functions: string[];
}

export interface SoulPropertyTestRequest {
  source_code: string;
  contract_name: string;
  property_types: PropertyType[];
  max_sequences: number;
  max_seq_length: number;
  additional_sources: Record<string, string>;
}

// ── Enum / union types ───────────────────────────────────────────

export type PowerSchedule =
  | "fast"
  | "coe"
  | "lin"
  | "quad"
  | "exploit"
  | "explore"
  | "mmopt"
  | "rare";
export type SearchStrategy =
  | "generational"
  | "dfs"
  | "bfs"
  | "random_path"
  | "coverage_opt"
  | "hybrid";
export type PropertyType =
  | "fund_conservation"
  | "nullifier_consistency"
  | "state_lifecycle"
  | "bridge_integrity"
  | "swap_completeness"
  | "privacy_guarantee"
  | "access_transitivity"
  | "composability_safety"
  | "upgrade_safety"
  | "rate_limit_consistency";

// ── Core result types ────────────────────────────────────────────

export interface SoulViolation {
  invariant_id: string;
  invariant_desc: string;
  severity: "critical" | "high" | "medium" | "low";
  mutation: string;
  iteration: number;
  coverage_at_trigger: number;
  minimized: boolean;
  has_poc: boolean;
}

export interface SoulFinding {
  id: string;
  title: string;
  severity: string;
  description: string;
  category: string;
  detector_id: string;
  remediation: string;
  file_path: string;
  start_line: number;
}

// ── Advanced result types ────────────────────────────────────────

export interface DifferentialFinding {
  diff_type: string;
  severity: string;
  function_name: string;
  description: string;
  input: Record<string, unknown>;
  expected_output: unknown;
  actual_output: unknown;
  version_a: string;
  version_b: string;
}

export interface PropertyViolation {
  property_type: PropertyType;
  severity: string;
  description: string;
  sequence: Array<{
    contract: string;
    function: string;
    args: unknown[];
  }>;
  state_before: Record<string, unknown>;
  state_after: Record<string, unknown>;
}

export interface LLMStrategy {
  strategy_name: string;
  description: string;
  target_invariant: string;
  mutation_types: string[];
  confidence: number;
}

export interface AttackHypothesis {
  name: string;
  description: string;
  target_contracts: string[];
  attack_vector: string;
  estimated_severity: string;
  steps: string[];
}

export interface CorpusStats {
  total_seeds: number;
  active_seeds: number;
  favored_seeds: number;
  avg_energy: number;
  schedule: string;
  phase: string;
  coverage_plateau_count: number;
  genetic_crossovers: number;
  seeds_trimmed: number;
}

export interface SymbolicPath {
  function_name: string;
  path_condition: string;
  depth: number;
  feasible: boolean;
  generated_seed: Record<string, unknown> | null;
}

// ── v2 Engine Result Types ───────────────────────────────────────

export interface TaintFlow {
  source: { id: string; type: string; param: string };
  sink: { id: string; type: string; location: string };
  path: string[];
  criticality: "critical" | "high" | "medium" | "low";
}

export interface TaintMutationTarget {
  function: string;
  param: string;
  taint_path: string;
  mutations: string[];
  priority: number;
  seed_values: Record<string, unknown>;
}

export interface DoSVector {
  type: string;
  function: string;
  severity: string;
  description: string;
  estimated_gas: number;
  worst_case_gas: number;
  trigger_input: Record<string, unknown>;
  mitigation: string;
}

export interface SynthesizedInvariant {
  expression: string;
  category: string;
  confidence: number;
  support: number;
  counter_examples: number;
  is_novel: boolean;
  related_invariant: string;
}

export interface ExploitChain {
  goal: string;
  steps: Array<{ action: string; description: string }>;
  primitives: string[];
  feasibility: number;
  impact: string;
  poc_code: string | null;
  related_violations: string[];
  taint_evidence: string[];
}

export interface BytecodeAnalysis {
  contract: string;
  functions: number;
  basic_blocks: number;
  patterns: number;
  soul_patterns: Array<{ type: string; selector: string; confidence: number }>;
  storage_layout: Record<string, unknown>;
  selectors: Record<string, string>;
  delegate_calls: Array<{ offset: number; target: string }>;
  cfg_edges: number;
  coverage_bitmap_size: number;
}

export interface GasProfile {
  contract: string;
  functions: Record<
    string,
    { avg_gas: number; max_gas: number; min_gas: number }
  >;
  hotspots: Array<{ function: string; opcode: string; gas_cost: number }>;
  total_gas_sampled: number;
  anomaly_count: number;
}

// ── Campaign result types ────────────────────────────────────────

export interface SoulFuzzResult {
  campaign_id: string;
  status: string;
  mode: string;
  duration_sec: number;
  total_iterations: number;
  violations: SoulViolation[];
  static_findings: SoulFinding[];
  coverage: Record<string, number>;
  mutation_stats: Record<string, number>;
  corpus_size: number;
  unique_paths: number;
  contracts_fuzzed: string[];
  invariants_checked: string[];
  llm_insights: string[];
  score: number;
  // Advanced fields
  symbolic_paths_explored: number;
  concolic_generations: number;
  concolic_new_coverage_pct: number;
  differential_findings: DifferentialFinding[];
  property_violations: PropertyViolation[];
  forge_executions: number;
  power_schedule: PowerSchedule;
  corpus_stats: CorpusStats;
  llm_strategies: LLMStrategy[];
  attack_hypotheses: AttackHypothesis[];
  total_findings: number;
  // v2 engine fields
  bytecode_analysis: BytecodeAnalysis | null;
  taint_flows: TaintFlow[];
  gas_profile: GasProfile | null;
  dos_vectors: DoSVector[];
  synthesized_invariants: SynthesizedInvariant[];
  state_snapshots: number;
  exploit_chains: ExploitChain[];
  taint_mutation_targets: TaintMutationTarget[];
}

export interface SoulConcolicResult {
  campaign_id: string;
  status: string;
  mode: "concolic";
  duration_sec: number;
  total_iterations: number;
  violations: SoulViolation[];
  coverage: Record<string, number>;
  concolic_generations: number;
  concolic_new_coverage_pct: number;
  symbolic_paths_explored: number;
  corpus_size: number;
  unique_paths: number;
  score: number;
}

export interface SoulDifferentialResult {
  campaign_id: string;
  status: string;
  mode: "differential";
  duration_sec: number;
  total_inputs_tested: number;
  differential_findings: DifferentialFinding[];
  findings_by_type: Record<string, number>;
  findings_by_severity: Record<string, number>;
  inputs_with_divergence_pct: number;
  score: number;
}

export interface SoulSymbolicResult {
  campaign_id: string;
  status: string;
  mode: "symbolic";
  duration_sec: number;
  paths_explored: number;
  constraints_generated: number;
  seeds_generated: number;
  unreachable_branches: number;
  target_coverage: Record<string, number>;
  interesting_paths: SymbolicPath[];
}

export interface SoulPropertyTestResult {
  campaign_id: string;
  status: string;
  mode: "property";
  duration_sec: number;
  sequences_tested: number;
  properties_checked: number;
  property_violations: PropertyViolation[];
  violations_by_type: Record<string, number>;
  violations_by_severity: Record<string, number>;
  all_properties_held: boolean;
  score: number;
}

// ── Info types ───────────────────────────────────────────────────

export interface SoulInvariant {
  id: string;
  description: string;
  severity: string;
  category: string;
  contracts: string[];
}

export interface SoulDetector {
  id: string;
  name: string;
  description: string;
  severity: string;
  category: string;
}

export interface SoulMutationType {
  id: string;
  name: string;
  description: string;
}

export interface SoulPowerSchedule {
  id: PowerSchedule;
  name: string;
  description: string;
}

export interface SoulForgeStatus {
  forge_available: boolean;
  forge_version: string;
  forge_path: string;
  solc_available: boolean;
  solc_version: string;
  capabilities: string[];
}

export interface SoulStaticScanResult {
  contract_name: string;
  findings: SoulFinding[];
  findings_count: number;
  findings_by_severity: Record<string, number>;
  findings_by_category: Record<string, number>;
  detectors_run: number;
  scan_duration_ms: number;
}

export interface SoulProtocolModel {
  contracts: Array<{
    name: string;
    category: string;
    functions: Array<{
      name: string;
      visibility: string;
      mutability: string;
      parameters: string[];
    }>;
    state_variables: Array<{
      name: string;
      type: string;
    }>;
  }>;
  invariants: SoulInvariant[];
  attack_surface: Array<Record<string, unknown>>;
  fuzz_targets: Array<Record<string, unknown>>;
}

// ── Campaign streaming ───────────────────────────────────────────

export interface SoulCampaignUpdate {
  status: string;
  campaign_id: string;
  iterations: number;
  coverage: Record<string, number>;
  violations_count: number;
  current_phase: string;
  corpus_size: number;
  elapsed_sec: number;
  // v2 fields
  taint_flows: number;
  dos_vectors: number;
  synthesized_invariants: number;
  state_snapshots: number;
  exploit_chains: number;
  error?: string;
}

// ── v2 Standalone Request/Response Types ─────────────────────────

export interface SoulBytecodeAnalysisRequest {
  bytecode: string;
  contract_name: string;
}

export interface SoulTaintAnalysisRequest {
  source_code: string;
  contract_name: string;
  target_functions: string[];
}

export interface SoulGasProfileRequest {
  source_code: string;
  contract_name: string;
  max_iterations: number;
}

export interface SoulBytecodeAnalysisResult {
  status: string;
  contract_name: string;
  duration_sec: number;
  functions: number;
  basic_blocks: number;
  cfg_edges: number;
  storage_layout: Record<string, unknown>;
  function_selectors: Record<string, string>;
  delegate_calls: Array<{ offset: number; target: string }>;
  soul_patterns: Array<{ type: string; selector: string; confidence: number }>;
  coverage_bitmap_size: number;
}

export interface SoulTaintAnalysisResult {
  status: string;
  contract_name: string;
  duration_sec: number;
  total_flows: number;
  total_mutation_targets: number;
  flows: TaintFlow[];
  mutation_targets: TaintMutationTarget[];
  critical_flows: TaintFlow[];
}

export interface SoulGasProfileResult {
  status: string;
  contract_name: string;
  duration_sec: number;
  function_profiles: Record<
    string,
    { avg_gas: number; max_gas: number; min_gas: number }
  >;
  hotspots: Array<{ function: string; opcode: string; gas_cost: number }>;
  anomaly_count: number;
  dos_vectors: DoSVector[];
  total_gas_sampled: number;
}

export interface SoulEngineStatus {
  total_engines: number;
  available: number;
  unavailable: number;
  engines: Record<
    string,
    { available: boolean; class?: string; error?: string }
  >;
}

// ── Hook-facing types (campaign management) ──────────────────────

export interface SoulCampaignStatus {
  campaign_id: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  mode: string;
  current_phase: string;
  progress: number;
  iterations: number;
  violations_count: number;
  coverage: Record<string, number>;
  corpus_size: number;
  elapsed_sec: number;
  started_at: string | null;
  completed_at: string | null;
  error?: string;
}

export interface SoulInvariantReport {
  campaign_id: string;
  total_synthesized: number;
  novel_invariants: number;
  invariants: SynthesizedInvariant[];
  high_confidence: SynthesizedInvariant[];
}

export interface SoulBytecodeReport {
  campaign_id: string;
  analysis: BytecodeAnalysis;
  soul_patterns_found: number;
  delegate_calls_found: number;
}

export interface SoulGasProfile {
  campaign_id: string;
  profile: GasProfile;
  dos_vectors: DoSVector[];
  top_hotspots: Array<{ function: string; opcode: string; gas_cost: number }>;
}

export type SoulExploitChain = ExploitChain;
