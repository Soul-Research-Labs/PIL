# Changelog

All notable changes to ZASEON will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] — Unreleased

### Added — Cross-Chain Bridge Detection

- **8 bridge-specific detectors** — `engine/analyzer/web3/detectors/bridge.py` (SCWE-050-001 through 050-008): missing source-chain validation (LayerZero, CCIP, Axelar, Wormhole, Stargate, Celer, Hyperlane), bridge message replay (missing nonce/hash tracking), unvalidated relayer/oracle input, unauthorized mint/unlock, missing emergency pause, incomplete message verification, unvalidated bridge deposits, accounting imbalance detection

### Added — SDK & CI/CD

- **Python SDK** — `sdk/` package (`zaseon-sdk` v0.1.0) with `ZaseonClient` async/sync HTTP client (httpx), `quick_scan()`, `start_scan()`, `wait_for_scan()` (polling), `symbolic_analysis()`, `differential_test()`, `list_findings()`, `get_report()`, `get_analytics()`, `login()`; Pydantic models (`Finding`, `ScanConfig`, `ScanResult`, `CursorPage`); retry logic with exponential backoff, rate limit handling, context manager support
- **GitLab CI template** — `.gitlab-ci.yml` with `.zaseon-scan-template` (Python 3.12, Solidity file discovery, SARIF parsing, severity threshold enforcement), default `zaseon-security-scan` (triggers on MR + default branch), optional `zaseon-deep-scan` (manual, deep mode)
- **PDF report template** — `engine/reports/templates/report_pdf.html` with `@page` CSS headers/footers/page numbers, cover page with grade badge, table of contents, executive summary KPI grid, severity distribution bar, detailed finding cards (code + remediation + PoC), gas optimizations table, methodology section, disclaimer; `generate_pdf()` updated to use PDF-specific template

### Added — Production Hardening

- **k6 load testing suite** — `infra/load-testing/k6-config.js` with 5 scenarios (smoke: 5 VUs/1m, load: 50 VUs/5m, stress: 200 VUs/3m, spike: 300 VUs/1m, soak: 30 VUs/30m), custom metrics (scan duration, findings count, error rate), thresholds (p95 < 500ms, quickscan p95 < 10s, errors < 5%)
- **Alembic migration 005** — `audit_logs` table (action, resource, IP, user agent, JSONB details, 5 indices), `scan_analytics` table (pre-aggregated daily org metrics), `confidence` column on findings/soul_findings, `engine_version` on scans, category/severity/composite indices
- **Grafana dashboards** — `infra/grafana/dashboards/` with 3 production dashboards: Scan Operations (throughput, duration percentiles, queue depth, findings by severity/category, coverage trends), API Performance (request rate, latency p50/p95/p99, HTTP status codes, error rates, rate limiting), Infrastructure (CPU/memory, PostgreSQL connections, Redis hit rate, Celery utilization, disk/network I/O)

### Added — Tests (v2.0.0 features)

- **CLI tests** — `engine/tests/test_cli.py` covering `zaseon scan` with file/directory/address inputs, `--format json|sarif|html`, `--severity` filtering, `--no-llm`/`--no-verify` flags, `zaseon config` display
- **Cache tests** — `engine/tests/test_cache.py` covering `QueryCache` get/set, TTL expiry, pattern invalidation, `@cached` decorator, `flush()`, `stats()`, graceful Redis-down degradation
- **Pagination tests** — `engine/tests/test_pagination.py` covering `CursorPage` model, forward/backward cursor traversal, limit enforcement, base64 opaque cursor encoding, `paginate()` keyset query
- **Analytics tests** — `engine/tests/test_analytics.py` covering `/analytics/summary`, `/analytics/scans/volume`, `/analytics/scans/scores`, `/analytics/cache/stats` endpoints with mock data
- **SCM adapter tests** — `engine/tests/test_scm_adapters.py` covering `GitHubAdapter`, `GitLabAdapter`, `BitbucketAdapter` webhook signature verification, event parsing, status posting, `detect_provider()` auto-detection

### Fixed — Security (22 MEDIUM + 10 LOW)

- **MEDIUM**: Docker Compose ports bound to 127.0.0.1, Docker socket :ro, CORS explicit methods/headers, security headers middleware, OpenAPI docs disabled in production, debug default → False, Fernet HKDF key derivation, HMAC-SHA256 API key hashing, sandbox path traversal protection, webhook secret enforcement, RFC 1918 range fix, Ethereum address validation, Git GIT_ASKPASS auth, repo URL/name sanitization, K8s Redis auth + securityContext + worker probes + Ingress security + pinned images, Terraform RDS/S3/Redis encryption + state locking + scoped egress
- **LOW**: Grafana password required (no default), sandbox network disabled by default, output sanitization, runtime image stripped of dev tools, auth failure audit logging, S3 encryption upgraded to KMS with rotation, Redis transit encryption

## [2.0.0] — Unreleased

### Added — CLI & Local Tooling

- **ZASEON CLI** — `engine/cli/main.py` with `zaseon scan <path>` (Solidity file/directory/contract address), coloured severity-coded table output, `--format json|sarif|html` export, `--severity` filtering, `--no-llm` and `--no-verify` flags, `zaseon config` (redacted settings display), `zaseon report` (stub for stored scans); registered as `[project.scripts] zaseon` entry point in pyproject.toml

### Added — Performance & Scalability

- **Redis query cache** — `engine/core/cache.py` with `QueryCache` (JSON-serialised async Redis cache, configurable TTL, pattern-based invalidation, `flush()`, `stats()`), `@cached(ttl=300, prefix="…")` decorator for transparent function-level caching, singleton `get_cache()`, graceful degradation when Redis unavailable
- **Cursor-based pagination** — `engine/core/pagination.py` with `CursorParams` (FastAPI dependency), `CursorPage[T]` generic response model (items, next/prev cursors, has_more, optional total_count), `paginate()` engine using keyset pagination (WHERE + ORDER BY) for efficient large-table traversal, base64-encoded opaque cursor tokens

### Added — Analytics & Reporting

- **Trend analytics API** — `engine/api/routes/analytics.py` with `GET /v1/analytics/summary` (combined KPIs: total scans, avg score, scan volume trend, score progression, MTTR), `GET /v1/analytics/scans/volume` (time-series scan counts by day/week/month), `GET /v1/analytics/scans/scores` (per-scan score progression), `GET /v1/analytics/cache/stats` (Redis cache hit/miss metrics); all endpoints authenticated and org-scoped
- **Analytics dashboard page** — `web/app/analytics/page.tsx` with time-range selector (7d/30d/90d/1y), granularity picker, 4 KPI cards (total scans, avg score, findings, MTTR), scan volume bar chart with hover tooltips, security score trend SVG area chart with gradient fill and dot markers
- **Dashboard trend charts** — `web/app/dashboard/page.tsx` enhanced with inline 30-day scan volume mini-chart and score trend sparkline powered by analytics API

### Added — IDE & CI/CD Integrations

- **Remix IDE plugin** — `extensions/remix/` with `@remixproject/plugin-webview` integration, one-click scan of active .sol file via ZASEON QuickScan API, severity-grouped expandable findings panel, inline editor annotations, dark-themed UI, configurable API endpoint and key (persisted in localStorage)
- **GitHub Actions action** — `.github/actions/zaseon-scan/action.yml` composite action with Python 3.12 setup, Solidity file discovery, zaseon CLI execution, SARIF generation and upload to GitHub Advanced Security via `github/codeql-action/upload-sarif@v3`, configurable `severity-threshold` and `fail-on` inputs, job summary with grade/score/finding counts, 6 outputs (`scan-id`, `security-score`, `total-findings`, `critical-count`, `high-count`, `sarif-file`)
- **Multi-SCM integration** — `engine/integrations/scm.py` with `SCMAdapter` abstract base (verify_webhook, parse_event, post_status, post_annotations), `GitHubAdapter` (REST v3, Check Runs annotations), `GitLabAdapter` (API v4, commit status, commit comments), `BitbucketAdapter` (Cloud 2.0, Reports + Annotations API), `detect_provider()` auto-detection from webhook headers, `get_adapter()` factory
- **Unified webhook endpoint** — `POST /api/webhooks/incoming` auto-detects GitHub/GitLab/Bitbucket from headers, verifies signature, parses event, dispatches scan for push/PR/MR events

### Changed

- **API version bumped to 2.0.0** in FastAPI metadata
- **pyproject.toml** — CLI entry point `zaseon = "engine.cli.main:main"` replaces stale uvicorn reference
- **OpenAPI tags** — added `analytics` tag for trend analytics endpoints
- **Sidebar navigation** — added Organizations, Audit & Compliance, Ask, and Analytics nav items with appropriate Lucide icons
- **`.env.example`** — comprehensive update with all required env vars (POSTGRES_PASSWORD, MINIO, FLOWER_PASSWORD, NEXTAUTH_SECRET, REDIS_PASSWORD) and optional engine vars documented

### Fixed — Security (v1.1.1 backport)

- **52 vulnerabilities fixed** (4 critical, 16 high) — password complexity validation, server-side GitHub OAuth verification, authentication on 23+ previously unprotected endpoints, webhook secret enforcement, metrics IP restriction, Docker socket read-only mount, Flower/Redis auth, internal-only port binding, Terraform SG VPC restriction, S3 encryption + public access blocks, K8s secret placeholders
- **Frontend type alignment** — 8 TypeScript type interfaces corrected to match backend API schemas (Organization, OrgMember, OrgUsage, AuditLogEntry, AuditSummary, ComplianceControl/Report, NLQueryResult)
- **Frontend page field references** — audit/page.tsx (by_severity dict, created_at, actor_email), organizations/page.tsx (scans_this_month, members, limits, plan), ask/page.tsx (data, total_count)
- **API client parameters** — `getAuditLogs`/`getAuditSummary` params renamed from `start_date`/`end_date` to `since`/`until` to match backend

## [1.1.0] — Unreleased

### Added — Test Coverage

- **ML module tests** — `test_ml_modules.py` covering DatasetLoader (JSONL, annotated Solidity, train/test split), VulnModelInference heuristic fallback, FeatureExtractor (30 signals), TriageClassifier, ConfidenceCalibrator, AutoTriageEngine, CorrectionStore (record/dedup/export/import JSONL), PatternAnalyser (severity/FP patterns), PromptOptimiser, FeedbackLoop cycle, QueryParser (NL heuristic parsing), ResultFormatter, NLQueryEngine
- **Security module tests** — `test_security_modules.py` covering FieldCipher (roundtrip, AAD, key derivation, key rotation, invalid inputs, unicode), BulkEncryptor (multi-field, skip none, double-encrypt prevention), ComplianceChecker (18 controls, categories, statuses), RBAC (36 permissions, viewer/editor/admin role hierarchy), TenantContext, AuditModel enums
- **Multi-chain analyzer tests** — `test_multichain_analyzers.py` covering Anchor parser + 8 Solana detectors (SOL-001–SOL-008) with vulnerable/safe programs, Move parser + 6 Move detectors (MOVE-001–MOVE-006) with vulnerable/safe modules, Aptos/Sui framework variants
- **Plugin loader tests** — `test_plugin_loader.py` covering PluginHook enum (8 hooks), PluginManifest, PluginLoader (discover, manifest parsing, fire_hook, enable/disable, unload), BaseMutationPlugin protocol
- **GitHub App tests** — `test_github_app.py` covering webhook signature verification (valid/invalid/missing prefix), PR/push event parsing, findings_to_annotations, findings_to_summary, determine_conclusion mapping, GitHubAppAuth init
- **v1.0.0 API route tests** — `test_v1_api_routes.py` covering org creation/list, audit log/summary/compliance, NL query/followup/examples/feedback

### Added — Frontend

- **TypeScript types** — Organization, OrgMember, OrgInvite, OrgUsage, OrgRole, OrgTier, AuditLogEntry, AuditSummary, AuditAction (31 actions), AuditSeverity, ComplianceControl, ComplianceReport, NLQueryRequest, StructuredQuery, NLQueryResult, NLQueryExample, NotificationConfig, NotificationChannel, Plugin, FindingDiff, ScanDiffResult, DiffCategory
- **API client functions** — getOrganizations, createOrganization, updateOrganization, deleteOrganization, getOrgMembers, inviteOrgMember, updateMemberRole, removeOrgMember, getOrgUsage, getAuditLogs, getAuditSummary, getComplianceReport, nlQuery, nlQueryFollowup, nlQueryFeedback, getNLQueryExamples, getNotificationConfigs, createNotificationConfig, deleteNotificationConfig, testNotification, getScanDiff
- **Organizations page** — `web/app/organizations/page.tsx` with org list, create dialog (auto-slug), detail view with usage cards, member table with role editing, invite dialog, danger zone delete
- **Audit & Compliance page** — `web/app/audit/page.tsx` with tab switcher (logs/compliance), summary cards, severity/action filters, log table, compliance status banner, controls list
- **Natural Language Query page** — `web/app/ask/page.tsx` with chat-style interface, example queries, result tables (capped at 20 rows), follow-up context, thumbs up/down feedback

### Changed — Infrastructure

- **pyproject.toml** — added `cryptography>=42.0.0`, `prometheus-client>=0.21.0`, `scikit-learn>=1.5.0`, `z3-solver>=4.12.0`, `pyyaml>=6.0.0` to dependencies; `aiosqlite>=0.20.0`, `bandit>=1.7.0`, `safety>=3.0.0` to dev dependencies
- **Docker Compose** — added Celery Beat (periodic tasks), Prometheus (v2.53.0, 30d retention), Grafana (v11.1.0), Mailhog (dev profile); added `promdata`/`grafanadata` volumes
- **Prometheus** — `infra/prometheus/prometheus.yml` scrape config for engine, flower, redis
- **Makefile** — added `test-integration`, `test-e2e`, `security-scan` (bandit + safety), `pre-commit`, `docker-push`, `deploy` (kubectl), `generate-types` (openapi-typescript)

## [1.0.0] — Unreleased

### Added — Platform

- **Multi-tenant SaaS mode** — `engine/api/middleware/tenant.py` with ContextVar org isolation, `resolve_org()` dependency (X-Org-Slug header → JWT → single-org fallback), `require_org_admin()`/`require_org_editor()` role-gating, `TenantQueryHelper` for org-scoped CRUD; `engine/api/routes/orgs.py` with org CRUD, member invite/list/update/remove, usage/billing endpoint with SaaS tier limits (free/pro/enterprise)
- **GitHub App integration** — `engine/integrations/github_app.py` with `GitHubAppAuth` (RS256 JWT, installation token caching), `verify_webhook_signature()` (HMAC-SHA256), `parse_pr_event()`/`parse_push_event()`, `GitHubCheckRunManager` (create/update/complete Check Runs with batched annotations at 50/request), `findings_to_annotations()`/`findings_to_summary()`, severity → conclusion mapping
- **VS Code inline fixes** — `extensions/vscode/src/inlineFix.ts` with `ZaseonCodeActionProvider` for .sol/.vy files, "Apply ZASEON Fix" (preferred) and "Explain Finding" code actions, unified diff patch application via workspace edits, webview explanation panel; `client.ts` extended with `getRemediation()` and `explainFinding()` methods
- **Solana/Move chain support** — `engine/analyzer/solana/anchor_analyzer.py` with Anchor program parser and 8 detectors (SOL-001 through SOL-008: missing signer, missing owner, integer overflow, unchecked PDA bump, arbitrary CPI, reinitialization, rent-exempt, duplicate mutable); `engine/analyzer/move/move_analyzer.py` with Move module parser (Aptos/Sui) and 6 detectors (MOVE-001 through MOVE-006: missing acquires, unchecked signer, resource leak, flash loan, unprotected init, phantom type confusion)
- **Plugin system** — `engine/plugins/loader.py` with `PluginHook` enum (8 lifecycle hooks), `MutationStrategy` protocol, `BaseMutationPlugin`, `PluginManifest` (parsed from plugin.yaml), `PluginLoader` (discover/load/unload/enable/disable plugins, `fire_hook()` chains context through handlers, auto-discovers `BaseDetector` and `BaseMutationPlugin` subclasses)

### Added — Security

- **SOC 2 Type II compliance** — `engine/core/compliance.py` with `ComplianceChecker` running 18 automated control checks across CC6 (logical access), CC7 (system ops), CC8 (change management), C1 (confidentiality), A1 (availability), PI1 (processing integrity); `ComplianceReport` with compliance percentage
- **Audit trail** — `engine/models/audit.py` with `AuditLog` model (31 action types, 4 severity levels, actor/resource/org tracking, JSONB old/new values, 5 indexes), `record_audit_event()`/`record_audit_event_sync()` helpers; `engine/api/routes/audit.py` with filtered/paginated query, summary aggregation, and compliance report endpoints
- **RBAC** — `engine/api/middleware/rbac.py` with `Permission` enum (36 fine-grained permissions), `ROLE_PERMISSIONS` mapping (viewer: 8, editor: 28, admin: 36), `RequirePermission` dependency, `check_project_access()` for project-level role overrides
- **Encrypted finding storage** — `engine/core/encryption.py` with `FieldCipher` (AES-256-GCM, HKDF key derivation, versioned nonce format), `BulkEncryptor` for multi-field in-place encrypt/decrypt, `encrypt_finding()`/`decrypt_finding()` helpers, `rotate_encryption_key()` batch re-encryption

### Added — AI/ML

- **Fine-tuned vulnerability detection model** — `engine/ml/vuln_model.py` with `DatasetLoader` (JSONL + annotated Solidity), `VulnModelTrainer` (HuggingFace Trainer, CodeBERT/StarCoder2 backends, multi-label classification), `VulnModelInference` (production inference with heuristic fallback), 30+ feature extraction signals from source structure
- **Auto-triage ML severity scoring** — `engine/ml/auto_triage.py` with `FeatureExtractor` (30 numeric signals), `TriageClassifier` (HistGradientBoosting with heuristic fallback), `ConfidenceCalibrator` (Platt scaling), `AutoTriageEngine` (extract → classify → calibrate → rank with risk scoring and exploit likelihood estimation)
- **Feedback loop for LLM prompts** — `engine/ml/feedback.py` with `CorrectionStore` (7 correction types, dedup, JSONL import/export), `PatternAnalyser` (severity bias, FP hotspots, category confusion, description quality patterns), `PromptOptimiser` (auto-generates prompt patches from patterns), `FeedbackLoop` orchestrator (collect → analyse → optimise cycle)
- **Natural language scan querying** — `engine/ml/nl_query.py` with `QueryParser` (LLM-based + heuristic fallback NL→structured query), `QueryExecutor` (SQLAlchemy async with org scoping), `NLQueryEngine` (follow-up query merging); `engine/api/routes/nl_query.py` with query/followup/feedback/examples endpoints

### Changed

- Bumped API version to `1.0.0` in FastAPI metadata
- Registered 3 new route groups in `engine/api/main.py`: organizations (`/api/v1/orgs`), audit (`/api/v1/audit`), NL query (`/api/v1/query`)
- Added 3 new OpenAPI tags: organizations, audit, nl-query

---

## [0.3.0] — Unreleased

### Added

- **EIP-1153 transient storage detectors** — 4 new detectors (`EIP1153-001` through `EIP1153-004`) in `engine/analyzer/web3/detectors/transient_storage.py` covering persistence across calls, missing reentrancy guards, slot collisions with sstore, and unvalidated tload
- **Cross-contract taint analysis** — `engine/core/cross_contract_taint.py` with 6-phase analyzer: proxy pair identification (ERC-1967, UUPS, Beacon, Diamond, Minimal Proxy), intra-contract taint via CFGBuilder, taint propagation across delegatecall boundaries, and cross-contract reentrancy detection
- **Custom invariant DSL** — `engine/fuzzer/invariant_dsl.py` with full lexer → parser → AST → Solidity compiler pipeline; supports `forall`/`exists` quantifiers, member access, function calls, arithmetic and logical operators; emits Forge-compatible test contracts
- **Stateful fuzzing engine** — `engine/fuzzer/stateful.py` with 4-phase campaign (exploration → targeted → minimization), persistent EVM state snapshots, configurable invariant check intervals, and Forge harness generation
- **Multi-tx sequence mutation** — `SequenceMutationEngine` in `engine/fuzzer/mutation_engine.py` with 12 mutation operators (insert/delete/swap/duplicate/splice/interleave/reverse/trim/change-sender/approve-injection/setup-tx/single-tx-mutate), weighted operator selection, and `TxCall`/`TxSequence` data types
- **Webhook integrations** — `engine/api/services/notifications.py` with Slack (Block Kit), Discord (embeds), and PagerDuty (Events API v2) notifiers; `engine/api/routes/notifications.py` with CRUD endpoints and test-send
- **Finding diff view API** — `engine/api/routes/diff.py` with fingerprint-based finding comparison between scan versions; categorises findings as NEW/RESOLVED/PERSISTENT/REGRESSION with change detection for severity, confidence, line, and description
- **External Secrets Operator** — `infra/k8s/external-secrets.yml` with ClusterSecretStore (AWS Secrets Manager), ExternalSecret mapping all 11 production secrets, and IRSA-enabled ServiceAccount
- **Grafana dashboards** — `infra/k8s/monitoring.yml` with Prometheus ServiceMonitor (15s scrape) and 9-panel Grafana dashboard (request rate, p95 latency, active requests, scans, campaigns, severity distribution, throughput, campaign modes, error rate)
- **Vyper support** — `engine/ingestion/vyper_compiler.py` with `VyperCompiler` (Python library + CLI fallback), `CompilationResult` reuse from Solidity pipeline, and 6 built-in Vyper detectors: unchecked raw_call return (`VYP-001`), missing @nonreentrant (`VYP-002`), selfdestruct usage (`VYP-003`), delegatecall via raw_call (`VYP-004`), non-static raw_call (`VYP-005`), unprotected initializer (`VYP-006`)
- **Formal verification integration** — `engine/verifier/formal.py` with `HalmosRunner` (symbolic test runner), `CertoraRunner` (CVL prover), auto-generated Halmos harnesses and Certora specs from ABI + invariants, unified `run_formal_verification()` entry point, structured `VerificationReport` with counterexamples
- **Gas-optimized test generation** — `engine/fuzzer/gas_optimized_tests.py` with `GasOptimizedTestGenerator` (tight-type declarations, batched multi-call sequences, ABI gas snapshot harness), `parse_gas_report()` for `forge test --gas-report` output, type inference via `optimal_solidity_type()`
- **Parallel fuzzing** — `engine/fuzzer/parallel.py` with `ParallelFuzzer` spawning N independent `ForgeExecutor` workers, round-robin seed partitioning, periodic coverage bitmap merge (union or weighted strategy), per-worker state tracking, and merged `ParallelFuzzResult`
- **Real-time fuzzing visualization** — `web/app/soul/live/page.tsx` with SSE-powered live dashboard: coverage heatmap bars, corpus growth + violation SVG graph, coverage sparkline, 10 stat cards (iterations, paths, corpus, violations, taint flows, DoS vectors, invariants, snapshots, exploit chains, elapsed time), campaign phase indicator
- **Team collaboration** — `engine/models/collaboration.py` with `FindingComment` (threaded, mentions, reactions), `FindingAssignment` (role-based with status tracking), `SLAPolicy` (per-severity triage/remediation deadlines), `SLATracker` (per-finding breach detection); `engine/api/routes/collaboration.py` with CRUD endpoints for comments, assignments, SLA policies, and real-time SLA status; `web/types/index.ts` extended with `FindingComment`, `FindingAssignment`, `SLAPolicy`, `SLAStatus` TypeScript types
- **Multi-region deployment** — `infra/terraform/multi_region.tf` with Aurora Global Database (read replica cluster), ElastiCache Global Datastore, secondary VPC/ECS/RDS, S3 cross-region replication, Route 53 latency-based routing with health checks, AWS Global Accelerator; gated behind `enable_multi_region` variable

### Changed

- **API version bumped to 0.3.0** in FastAPI metadata
- **OpenAPI tags** — added `notifications` and `collaboration` tags
- **Findings router** — `/api/v1/findings/diff` endpoint added alongside existing findings CRUD
- **Collaboration router** — `/api/v1/collaboration` prefix with comments, assignments, and SLA sub-routes
- **Delegatecall-in-loop detector rewritten** — replaced simplistic brace-counting with full `_ScopeTracker` class that handles string/comment stripping, nested struct/enum scopes, assembly blocks, `do...while` loops, and multi-line brace expressions

---

## [0.2.0] — Unreleased

### Added

- **`make check` target** — composite `lint` + `test` + `typecheck` quality gate
- **`make test-web` target** — runs frontend tests via `npx vitest run`
- **`make test-engine` target** — extracted engine-only test runner
- **Frontend test CI job** (`test-web`) in GitHub Actions running vitest
- **`ROADMAP.md`** — structured roadmap with near-term, mid-term, and long-term milestones
- **Exploit PoC goal-specific assertions** — 12 exploit goals now generate concrete Solidity assertions instead of `assertTrue(true)` stubs
- **Pattern-matched invariant checks** in Forge invariant harness — nullifier, pool balance, proof verification, and bridge invariants generate real assertions
- **PoC contract call wiring** — Soul fuzzer generates actual `target.function()` calls from `tx_sequence` data in PoC tests
- **ABI-driven invariant generation** — `ForgeTestGenerator.generate_abi_invariant_checks()` inspects ABI getters to produce concrete Solidity property checks (supply cap, owner non-zero, pool solvency, nullifier monotonicity, merkle root, rate limits)
- **tx_sequence replay PoC** — `PoCGenerator.generate_tx_sequence_poc()` generates deterministic Foundry tests from concrete fuzzing sequences without an LLM call; `VerificationEngine.verify_finding()` auto-selects replay when `finding.metadata["tx_sequence"]` is present
- **6 new exploit primitives** — `SANDWICH_FRONT`, `SANDWICH_BACK`, `ROLE_MANIPULATION`, `SLOT_OVERWRITE`, `FINALITY_RACE`, `BACK_RUN` registered in exploit composer; all 37 enum values now have library entries
- **Z3 array theory for mappings** — `BinOp.SELECT`/`STORE` ops, `z3.Array(BV256, BV256)` in `ConstraintSolver._to_z3()`, and `SymbolicVM._parse_value()` mapping-access pattern recognition enable concolic solving of `mapping[key]` branch conditions
- **>80% code coverage CI gate** — `--cov-fail-under=80` added to pytest in `ci.yml`
- **Playwright E2E tests** — `web/e2e/dashboard.spec.ts` covering home page, dashboard, scans, findings, quickscan, soul fuzzer, navigation, and 404 pages; `web/playwright.config.ts`, `@playwright/test` dependency, Playwright CI job with artifact upload
- **Contributor guide** — 12 "Good First Issues" table added to `CONTRIBUTING.md`
- **Architecture Decision Records** — `docs/adr/` with 3 ADRs: Forge-backed execution, pure-Python fuzzer, Z3 array theory

### Changed

- **README rewritten** — removed inaccurate AFL++ fork branding; README now accurately describes PIL++ as a Python-based, Forge-backed, coverage-guided smart contract fuzzer with semantic ABI-aware mutations
- **AFL++ references cleaned** — all code docstrings/comments updated to credit the AFL++ paper as academic inspiration rather than claiming to be a fork
- **Structured error responses** — new `engine/api/errors.py` with `ErrorCode` enum (17 codes), `ErrorEnvelope`/`ErrorResponse` Pydantic models, and exception handlers for validation, HTTP, domain, and unhandled errors; wired into `engine/api/main.py`
- **Retry logic for transient failures** — `engine/pipeline/orchestrator.py` now wraps S3 `put_object` and DB `session.commit()` calls in exponential-backoff retry helpers (`_retry_async`, `_retry_sync`) with 12 transient-error patterns
- **Enhanced OpenAPI metadata** — FastAPI app now includes full description, ReDoc endpoint, 10 tagged route groups, license info, and contact details
- **OpenAPI export script** — new `engine/scripts/export_openapi.py` CLI tool (supports `--yaml`, `-o` path); new `make export-api-docs` target
- **LLM oracle placeholder fixed** — `SOUL-INV-XXX` in `engine/fuzzer/llm_oracle.py` explain-violations prompt replaced with dynamic invariant ID instruction
- **Exploit composer target_function coverage** — 15 existing primitives that lacked a `target_function` (emitting generic `address(target).call("")`) now have concrete function selectors (`withdraw`, `grantRole`, `castVote`, `relayMessage`, `deposit`, `upgradeTo`, `destroy`, `setUp`, `swap`, `unlock`, `transfer`, `getPrice`, `verifyProof`)
- **MyPy type checking enforced** in CI — removed `continue-on-error` from lint-python job
- **Safety dependency audit enforced** in CI — removed `continue-on-error` from security job
- **`make test`** now runs both engine (pytest) and web (vitest) tests
- **CI `build-web`** job now depends on `[lint-web, test-web]`
- **Delegatecall-in-loop detector** — replaced simplified brace tracking with proper stack-based scope analysis using `loop_brace_depths`
- **Exploit composer fallback** — primitives without a `target_function` now emit low-level `address(target).call()` with value support instead of `// TODO` comments
- **Forge invariant harness** — `_generate_default_invariant_check()` maps invariant IDs to concrete Solidity property checks, supports user-supplied `check_expression`

### Fixed

- **17 silent `except: pass` blocks** replaced with proper `logger.warning()` / `logger.debug()` calls across `soul.py`, `orchestrator.py`, `feedback_loop.py`, `github.py`, `patch_generator.py`
- **README** `make db-downgrade` → corrected to `make db-rollback`
- **README** `make test` description updated to reflect engine + web tests
- **Orchestrator** now imports `logging` at module level instead of inline imports in exception handlers

### Added (previous)

- **Auth enforcement** on all API routes — dashboard, quickscan, soul fuzzer POST endpoints now require JWT/API key authentication
- **GitHub OAuth token encryption at rest** using Fernet symmetric encryption derived from `SECRET_KEY`
- **PATCH /api/v1/auth/me** endpoint for profile updates (display name, email)
- **Settings page** fully wired to real API — profile save, API key management (create/list/revoke), notification preferences UI
- **Global search** in header — debounced search across projects, scans, and findings with navigation
- **Next.js error handling** — `not-found.tsx` (custom 404), `error.tsx` (error boundary with retry), `loading.tsx` (global loading spinner)
- **Dynamic route pages** — `/scans/[id]`, `/findings/[id]`, `/repos/[id]` with live polling and real data
- **Auth pages** — `/auth/signin` (GitHub OAuth + credentials) and `/auth/register`
- **Soul layout** wrapper for sidebar navigation
- **Dev seed script** (`make db-seed`) with realistic Solidity security findings
- **CHANGELOG.md** (this file)
- **Alembic migration 004** reconciling `soul_campaigns` / `soul_findings` table schemas to match ORM models
- **Integration test fixtures** (`conftest_integration.py`) with SQLite-async session, authenticated `httpx.AsyncClient`, and test user factory
- **Integration tests** (`test_integration.py`) verifying auth enforcement, CRUD, and profile routes
- **GitHub PR creation** in remediation engine — creates branch, commits patches, opens PR via GitHub REST API
- **Zustand stores** (`web/lib/store.ts`) — `useAuthStore` (token + user), `useScanStore` (scan cache), `useUIStore` (sidebar, command palette)
- **Bulk findings operations** — `PATCH /v1/findings/bulk/status` for batch status updates, `DELETE /v1/findings/{id}` for dismissals
- **Docker web healthcheck** — `wget --spider` against port 3000 with auto-restart
- **`web/.env.example`** with standard naming alongside `.env.local.example`
- WeasyPrint system dependencies in engine Dockerfile
- Production startup guard requiring explicit `ZASEON_SECRET_KEY` environment variable

### Changed

- **Lazy database initialization** — SQLAlchemy engine is created on first access, not at import time, improving testability
- **Random default `secret_key`** in development — each dev instance generates a unique JWT signing key via `secrets.token_urlsafe(64)`
- **CI pipeline** — ESLint, TypeScript check, and Bandit SAST scan are now blocking quality gates (removed `continue-on-error`)
- **K8s secrets** — separated `POSTGRES_PASSWORD` from `SECRET_KEY`, replaced default MinIO credentials with placeholder
- **Celery** `-A` flag fixed to `engine.pipeline:celery_app` in docker-compose, Makefile
- **SSE stream** (`streamSoulCampaign`) rewritten to use `fetch()` + `ReadableStream` with Authorization header (EventSource cannot send custom headers)
- Repos and Contracts pages rewritten from hardcoded demo data to real API via React Query
- QuickScan type alignment (`lines_of_code`, `scan_duration_ms`) between frontend and backend
- Alembic uses env.py override instead of hardcoded connection string

### Fixed

- **Alembic revision chain** — migration 003 `down_revision` corrected from `"002"` to `"002_soul_campaigns"`
- **SoulCampaign ORM ↔ DB drift** — 15+ column mismatches reconciled via migration 004 (renames, adds, drops)
- **Report template CSS** — `.informational` severity class now renders correctly (was `.info` only)
- Dashboard `sevDist.reduce()` TypeScript type error
- Circular model imports between `user.py` and `scan.py`
- Deploy workflow placeholder kubectl commands documented

### Security

- GitHub OAuth tokens encrypted at rest (Fernet/AES)
- All mutation endpoints require authentication
- **`publish_report` endpoint** now requires authentication (was unauthenticated)
- Dashboard stats endpoint no longer leaks aggregate data to unauthenticated users
- K8s Postgres password no longer shares value with JWT secret

## [0.1.0] - 2026-02-01

### Added

- Initial release
- 13 fuzzer engines with 18-phase pipeline
- 45+ mutation strategies
- 24 Soul Protocol detectors across 6 categories
- 25 invariant checks
- Next.js 14 dashboard with shadcn/ui components
- FastAPI backend with async SQLAlchemy 2.0
- Celery task queue with Redis broker
- Docker multi-stage builds
- Kubernetes manifests and Terraform (AWS)
- GitHub Actions CI/CD
- PDF/HTML/JSON/SARIF report generation
- Auto-remediation engine with 14 fix templates
