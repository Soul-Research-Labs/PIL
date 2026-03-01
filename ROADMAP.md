# ZASEON Roadmap

Planned features, improvements, and technical debt for the ZASEON smart contract security platform.

---

## Near-Term (v0.2.0)

### Fuzzer Improvements

- [x] Concrete invariant check generation — ABI-aware `generate_abi_invariant_checks()` produces contract-specific Solidity assertions from getter signatures
- [x] Wire PoC contract calls from `tx_sequence` data — `PoCGenerator.generate_tx_sequence_poc()` produces deterministic Foundry replay tests
- [x] Expand exploit composer primitives — all 37 enum values registered (was 32); 15 primitives gained `target_function`; 6 new primitives added
- [x] Concolic engine: Z3 array theory for Solidity mappings via `BinOp.SELECT`/`STORE` and `z3.Array(BV256, BV256)`
- [x] Resolve placeholder invariant ID `SOUL-INV-XXX` in LLM oracle

### CI/CD Hardening

- [x] Enforce MyPy type checking as blocking CI gate
- [x] Enforce Safety dependency audit as blocking CI gate
- [x] Add frontend test job (vitest) to CI pipeline
- [x] Add `make check` composite target (lint + test + typecheck)
- [x] Add `make test-web` target for frontend tests
- [x] Achieve >80% code coverage gating in CI (`--cov-fail-under=80`)
- [x] Add E2E tests (Playwright) for critical dashboard flows

### Error Handling

- [x] Replace silent `except: pass` blocks with proper logging
- [x] Add structured error responses for all API endpoints
- [x] Implement retry logic for transient S3/DB failures in pipeline orchestrator

### Documentation

- [x] Fix `make db-downgrade` → `db-rollback` reference in README
- [x] Create ROADMAP.md (this file)
- [x] Add API reference docs (OpenAPI/Swagger export)
- [x] Rewrite README to accurately describe PIL++ architecture (remove AFL++ fork branding)
- [x] Add contributor guide with "Good First Issues" list (12 tasks in CONTRIBUTING.md)
- [x] Add architecture decision records (ADRs) — `docs/adr/` with 3 initial ADRs

---

## Mid-Term (v0.3.0)

### Analysis Engine

- [x] Formal verification integration (Certora / Halmos)
- [x] Cross-contract taint analysis across proxy/implementation pairs
- [x] Support Vyper contracts (compilation + detection)
- [x] Solidity 0.8.25+ transient storage (EIP-1153) detector support
- [x] Improved delegatecall-in-loop detector with full brace/scope tracking

### Fuzzer v3

- [x] Stateful fuzzing with persistent EVM state across campaigns
- [x] Multi-transaction sequence mutation (beyond single-tx mutations)
- [x] Gas-optimized test generation (minimize forge test gas usage)
- [x] Parallel fuzzing across multiple Forge instances
- [x] Custom invariant DSL for user-defined protocol properties

### Dashboard

- [x] Real-time fuzzing visualization (coverage heatmap, mutation graph)
- [x] Finding diff view between scan versions
- [x] Team collaboration features (comments, assignments, SLA tracking)
- [x] Webhook integrations (Slack, Discord, PagerDuty)

### Infrastructure

- [x] Replace `CHANGE-ME-IN-PRODUCTION` K8s secrets with external secrets operator (AWS Secrets Manager / Vault)
- [x] Add Prometheus metrics endpoint for engine + worker
- [x] Grafana dashboards for scan throughput, queue depth, coverage trends
- [x] Multi-region deployment support

---

## Long-Term (v1.0.0)

### Platform

- [x] Multi-tenant SaaS mode with org-level isolation
- [x] GitHub App integration (auto-scan on PR, status checks)
- [x] VS Code extension: inline fix suggestions powered by LLM remediation
- [x] Support additional chains: Solana (Anchor), Move (Aptos/Sui)
- [x] Plugin system for custom detectors and mutation strategies

### Security

- [x] SOC 2 Type II compliance
- [x] Audit trail for all scan/finding operations
- [x] RBAC with fine-grained permissions per project
- [x] Encrypted finding storage at rest

### AI/ML

- [x] Fine-tuned vulnerability detection model on labeled audit datasets
- [x] Auto-triage: ML severity confidence scoring
- [x] Feedback loop: human audit corrections improve LLM prompts
- [x] Natural language querying of scan results

---

## Production Hardening (v1.1.0)

### Security Hardening (v1.1.1)

- [x] Fix 52 security vulnerabilities (4 critical, 16 high, 22 medium, 10 low)
- [x] Replace all hardcoded secrets with required env vars in docker-compose
- [x] Add password complexity validation (min 8 chars, uppercase, digit)
- [x] Server-side GitHub OAuth token validation
- [x] Authentication on all collaboration, notification, NL query, and audit endpoints
- [x] Webhook verification rejects when no secret configured
- [x] Metrics endpoint restricted to internal networks
- [x] Read-only Docker socket mount, Flower auth, Redis auth, port binding
- [x] Terraform: ECS SG restricted to VPC CIDR, S3 encryption + public access blocks
- [x] Kubernetes secrets use REPLACE-ME placeholders with External Secrets Operator annotations
- [x] Frontend type alignment with all backend API schemas
- [x] `.env.example` updated with all required variables documented

### Test Coverage

- [x] ML modules — DatasetLoader, VulnModelInference, FeatureExtractor, TriageClassifier, AutoTriageEngine, CorrectionStore, PatternAnalyser, PromptOptimiser, FeedbackLoop, QueryParser, ResultFormatter, NLQueryEngine
- [x] Security modules — FieldCipher (roundtrip, AAD, key rotation), BulkEncryptor, ComplianceChecker, RBAC permissions, tenant context, AuditModel
- [x] Multi-chain analyzers — Anchor parser + 8 Solana detectors, Move parser + 6 Move detectors, Aptos/Sui variants
- [x] Plugin loader — PluginHook, PluginManifest, discovery, fire_hook, enable/disable, BaseMutationPlugin protocol
- [x] GitHub App — webhook signature verification, PR/push event parsing, annotations, conclusion mapping, auth
- [x] v1.0.0 API routes — org CRUD, audit log/summary/compliance, NL query/followup/feedback/examples

### Full-Stack Wiring

- [x] TypeScript types for all v1.0.0 features (Organization, AuditLogEntry, ComplianceReport, NLQueryResult, NotificationConfig, ScanDiffResult, etc.)
- [x] API client functions for orgs, audit, NL query, notifications, scan diff
- [x] Organizations management page (list, create, members, usage, invite, roles, delete)
- [x] Audit & compliance page (log viewer with filters, summary cards, compliance controls)
- [x] Natural language query page (chat interface, examples, feedback, result tables)

### Infrastructure

- [x] pyproject.toml — cryptography, prometheus-client, scikit-learn, z3-solver, pyyaml, aiosqlite/bandit/safety (dev)
- [x] Docker Compose — Celery Beat, Prometheus, Grafana, Mailhog (dev profile)
- [x] Prometheus scrape config for engine, flower, redis
- [x] Makefile — test-integration, test-e2e, security-scan, pre-commit, docker-push, deploy, generate-types

---

## Developer Experience & Ecosystem (v2.0.0)

### CLI & Local Tooling

- [x] `zaseon` CLI tool — scan Solidity files/directories from the command line with coloured output, JSON/SARIF/HTML export, severity filtering
- [x] CLI entry point registered in `pyproject.toml` (`zaseon scan`, `zaseon config`, `zaseon report`)

### Performance & Scalability

- [x] Redis-backed query cache (`engine/core/cache.py`) — transparent caching with TTL, pattern invalidation, `@cached` decorator
- [x] Cursor-based pagination (`engine/core/pagination.py`) — keyset pagination for efficient large-table traversal, replaces OFFSET-based approach

### Analytics & Reporting

- [x] Trend analytics API (`/api/v1/analytics/`) — scan volume, security score progression, cache stats
- [x] Analytics dashboard page (`web/app/analytics/page.tsx`) — KPI cards, scan volume bar chart, score trend SVG line chart, time range selector
- [x] Dashboard trend charts — inline scan volume and score trend visualizations

### IDE & CI/CD Integrations

- [x] Remix IDE plugin (`extensions/remix/`) — one-click scan from Remix editor with findings panel, inline annotations, settings
- [x] GitHub Actions action (`.github/actions/zaseon-scan/`) — composite action with SARIF upload, severity thresholds, job summary, multi-step CI integration
- [x] GitLab & Bitbucket webhook support (`engine/integrations/scm.py`) — unified SCM adapter with event parsing, status posting, code annotations
- [x] Unified `/api/webhooks/incoming` endpoint — auto-detects SCM provider from headers

### Full-Stack Wiring

- [x] Analytics API client functions (`getAnalyticsSummary`, `getScanVolume`, `getScoreTrend`, `getCacheStats`)
- [x] Analytics registered in FastAPI main app with OpenAPI tag
- [x] Sidebar navigation for Organizations, Audit, Ask, and Analytics pages

---

## Security & Features (v2.1.0)

### Security Hardening (MEDIUM/LOW)

- [x] Bind all Docker Compose ports to `127.0.0.1` (engine, web, Prometheus, Grafana, Mailhog)
- [x] CORS `allow_methods`/`allow_headers` — explicit lists instead of wildcard `*`
- [x] Security headers middleware (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, HSTS/CSP in production)
- [x] Disable OpenAPI docs in production (docs_url, redoc_url, openapi_url = None)
- [x] Debug mode default changed to `False`
- [x] Fernet key derivation upgraded to HKDF with salt (replaces raw SHA-256)
- [x] API key hashing upgraded to HMAC-SHA256 with server secret
- [x] Auth failure audit logging (expired/invalid tokens)
- [x] Path traversal protection in sandbox file uploads
- [x] Sandbox network disabled by default for Solidity execution
- [x] Output sanitization (HTML/script tag stripping) in sandbox results
- [x] Unified webhook rejects when no secret configured (503)
- [x] RFC 1918 range check fixed (172.16–31 instead of 172.\*)
- [x] Ethereum address validation regex before Etherscan API calls
- [x] Git clone uses `GIT_ASKPASS` instead of token-in-URL for authentication
- [x] Repository URL and name sanitization (HTTPS-only, regex validation)
- [x] Runtime Docker image stripped of git/curl/docker.io
- [x] K8s: Redis auth (`--requirepass`), pod `securityContext` (runAsNonRoot, drop ALL), worker probes, Ingress rate limiting + headers, pinned image tags
- [x] Terraform: RDS storage encryption, S3 state backend + DynamoDB lock, Redis transit encryption, ECS egress scoped to VPC + HTTPS-only, S3 encryption upgraded to KMS with key rotation

### Cross-Chain Bridge Detection

- [x] 8 bridge-specific detectors (SCWE-050-001 through SCWE-050-008)
- [x] Missing source-chain validation in message receivers (LayerZero, CCIP, Axelar, Wormhole, Stargate, Celer, Hyperlane)
- [x] Bridge message replay detection (missing nonce/hash tracking)
- [x] Unvalidated relayer/oracle input detection
- [x] Unauthorized mint/unlock after bridging
- [x] Missing emergency pause mechanism
- [x] Incomplete message verification (no signature/proof)
- [x] Bridge deposit without amount/token validation
- [x] Bridge accounting imbalance (missing on-chain ledger)

### SDK & CI/CD

- [x] Python SDK (`zaseon-sdk`) — async/sync client with retry logic, rate limit handling, all API methods
- [x] GitLab CI template (`.gitlab-ci.yml`) — scan template, default + optional deep scan jobs
- [x] PDF report improvements — dedicated template with cover page, TOC, KPI grid, severity distribution, methodology section

### Production Hardening

- [x] k6 load testing suite — smoke/load/stress/spike/soak scenarios with severity thresholds
- [x] Alembic migration 005 — audit_logs table, scan_analytics table, finding confidence/category indices
- [x] Grafana dashboards — Scan Operations, API Performance, Infrastructure (3 JSON dashboards)

### Test Coverage (v2.0.0 features)

- [x] CLI tool tests — config display, scan execution, format options
- [x] Redis cache tests — get/set, TTL, pattern invalidation, decorator, graceful degradation
- [x] Cursor pagination tests — forward/backward, limit, base64 cursors
- [x] Analytics endpoint tests — summary, volume, score trend, cache stats
- [x] SCM adapter tests — GitHub/GitLab/Bitbucket webhook parsing, provider detection

---

## Future (v3.0.0)

### Analysis

- [ ] Formal verification of bridge invariants (Certora specs for cross-chain message integrity)
- [ ] AI-powered exploit chain synthesis (multi-step attack path generation)
- [ ] Zero-knowledge proof verification support (Circom/Noir/Halo2)
- [ ] Account abstraction (ERC-4337) detector suite

### Platform

- [ ] Self-hosted on-prem deployment mode (Helm chart + offline artifacts)
- [ ] Real-time collaborative audit workspace (multiplayer findings review)
- [ ] Automated regulatory compliance mapping (NIST, ISO 27001)
- [ ] Custom detector SDK with WASM sandbox

### Infrastructure

- [ ] Multi-cluster federation for geo-distributed scanning
- [ ] GPU-accelerated symbolic execution
- [ ] Streaming scan results via WebSocket/SSE

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup. Roadmap items marked with `[ ]` are open for contribution — check GitHub Issues for corresponding tickets.
