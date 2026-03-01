<div align="center">

# PIL++

**Smart Contract Security Platform**

Coverage-guided fuzzing, static analysis, and AI-powered vulnerability detection for EVM smart contracts.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12+-3776AB.svg)](https://python.org)
[![Foundry](https://img.shields.io/badge/evm-foundry--forge-orange.svg)](https://book.getfoundry.sh/)
[![Next.js](https://img.shields.io/badge/frontend-Next.js%2014-black.svg)](https://nextjs.org/)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](CHANGELOG.md)

</div>

---

## What is PIL++?

PIL++ is an end-to-end smart contract security platform that combines **coverage-guided fuzzing**, **13 specialized analysis engines**, and **LLM-powered intelligence** to find vulnerabilities in Solidity contracts. It executes mutated inputs on a real EVM via Foundry Forge, tracks multi-level coverage, and synthesizes proof-of-concept exploits for confirmed findings.

**Core differentiators:**

- **Semantic ABI-aware mutations** — 45+ strategies that understand Solidity types, ZK proof structures, and DeFi patterns
- **13 analysis engines** — symbolic execution, concolic exploration, taint analysis, bytecode disassembly, gas profiling, invariant synthesis, exploit composition, state replay, differential testing, and more
- **94+ vulnerability detectors** — 70+ general Solidity detectors across 19 categories + 24 Soul Protocol-specific detectors
- **Auto-remediation** — template-based patch generation with compilation validation and optional auto-PR
- **Full platform** — CLI, REST API, web dashboard, VS Code extension, Remix IDE plugin, GitHub Action, and multi-SCM webhooks

---

## Quick Start

### CLI

```bash
pip install -e "./engine[dev]"

zaseon scan ./contracts/                                       # Scan a directory
zaseon scan ./contracts/Token.sol --severity high -f sarif     # SARIF output
zaseon scan --address 0x1234...abcd --chain ethereum           # On-chain contract
zaseon config                                                  # Show configuration
```

### Docker Compose

```bash
cp .env.example .env         # Configure required secrets
docker compose up -d          # PostgreSQL, Redis, MinIO, Engine, Worker, Web
```

| Service  | Port | Description              |
| -------- | ---- | ------------------------ |
| engine   | 8000 | FastAPI REST API         |
| web      | 3000 | Next.js dashboard        |
| postgres | 5432 | PostgreSQL 16 (pgvector) |
| redis    | 6379 | Cache + Celery broker    |
| minio    | 9000 | S3-compatible storage    |

### API

```bash
# Quick scan (60s)
curl -X POST http://localhost:8000/api/v1/soul/quick-fuzz \
  -H "Content-Type: application/json" \
  -d '{"source_code": "...", "contract_name": "MyContract"}'

# Full 18-phase pipeline
curl -X POST http://localhost:8000/api/v1/soul/fuzz \
  -d '{"source_code": "...", "mode": "deep", "enable_symbolic": true}'
```

### Web Dashboard

```bash
cd web && pnpm install && pnpm dev   # http://localhost:3000
```

---

## Architecture

```
engine/                              Python 3.12+ analysis engine
├── fuzzer/                          13 specialized fuzzing/analysis engines
├── analyzer/soul/                   Soul Protocol model + 24 detectors
├── analyzer/web3/                   70+ general Solidity detectors
├── api/                             FastAPI REST API + WebSocket streaming
├── core/                            AST, CFG, taint, cache, pagination, config
├── integrations/                    GitHub, GitLab, Bitbucket SCM adapters
├── pipeline/                        Celery task orchestration
├── remediator/                      14-template auto-patch engine
├── reports/                         HTML / PDF / JSON / SARIF generation
├── cli/                             zaseon command-line tool
└── tests/                           pytest suite (100+ cases)

web/                                 Next.js 14 dashboard
extensions/vscode/                   VS Code extension
extensions/remix/                    Remix IDE plugin
.github/actions/zaseon-scan/         GitHub Actions composite action
infra/                               Kubernetes + Terraform (AWS)
```

---

## Analysis Pipeline

ZASEON runs an **18-phase pipeline** combining static analysis, coverage-guided fuzzing, and multi-engine post-analysis:

| Phase | Stage               | Description                                                                        |
| ----- | ------------------- | ---------------------------------------------------------------------------------- |
| 1-3   | **Pre-analysis**    | Static detectors + bytecode disassembly + target identification                    |
| 4-7   | **Seed generation** | Symbolic constraint solving + taint analysis + LLM oracle + ABI encoding           |
| 8     | **Fuzz loop**       | Mutate > Forge EVM execute > coverage feedback > corpus evolution > repeat         |
| 9-12  | **Supplementary**   | Concolic boost + property testing + gas profiling + invariant synthesis            |
| 13-16 | **Post-analysis**   | State replay + exploit composition + violation minimization + differential testing |
| 17-18 | **Output**          | PoC generation (Foundry tests) + report generation (HTML/PDF/JSON/SARIF)           |

**Power schedules** (FAST, COE, LIN, QUAD, EXPLOIT, EXPLORE, MMOPT, RARE) control seed energy allocation, inspired by the AFL++ paper.

---

## API Reference

| Endpoint                                | Description                                   |
| --------------------------------------- | --------------------------------------------- |
| `POST /api/v1/soul/fuzz`                | Full 18-phase fuzzing campaign                |
| `POST /api/v1/soul/quick-fuzz`          | 60-second quick fuzz                          |
| `POST /api/v1/soul/targeted-fuzz`       | Targeted function/invariant fuzz              |
| `POST /api/v1/soul/differential`        | Cross-version differential testing            |
| `POST /api/v1/soul/symbolic`            | Symbolic execution analysis                   |
| `POST /api/v1/quickscan/address`        | Scan by on-chain address                      |
| `POST /api/v1/quickscan/source`         | Scan by source code                           |
| `GET /api/v1/soul/campaign/{id}/stream` | SSE live campaign stats                       |
| `GET /api/v1/analytics/summary`         | Trend analytics dashboard data                |
| `POST /api/webhooks/incoming`           | Unified SCM webhook (GitHub/GitLab/Bitbucket) |

Full OpenAPI docs at `http://localhost:8000/docs`.

---

## Integrations

| Integration       | Description                                                                            |
| ----------------- | -------------------------------------------------------------------------------------- |
| **CLI**           | `zaseon scan` / `zaseon report` / `zaseon config` with table, JSON, SARIF, HTML output |
| **GitHub Action** | `.github/actions/zaseon-scan` with SARIF upload, severity thresholds, job summary      |
| **VS Code**       | Scan on save, inline diagnostics, findings sidebar                                     |
| **Remix IDE**     | In-browser scanning with inline annotations                                            |
| **Webhooks**      | Auto-scan on push/PR from GitHub, GitLab, or Bitbucket                                 |

---

## Configuration

```bash
# Required
ZASEON_SECRET_KEY=<random-64-char-string>
ZASEON_DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/zaseon
ZASEON_REDIS_URL=redis://localhost:6379/0

# LLM (optional, enables AI-powered analysis)
ZASEON_ANTHROPIC_API_KEY=<key>
ZASEON_OPENAI_API_KEY=<key>

# SCM
ZASEON_GITHUB_TOKEN=<pat>
ZASEON_GITHUB_WEBHOOK_SECRET=<secret>

# Fuzzer
ZASEON_SOUL_FUZZ_DEFAULT_MODE=standard    # quick | standard | deep
ZASEON_SOUL_FUZZ_MAX_DURATION=300         # seconds
ZASEON_SOUL_FUZZ_PARALLEL_WORKERS=4
```

See [.env.example](.env.example) for the complete list.

---

## Development

```bash
make setup          # Install all dependencies
make dev            # Start engine + web in dev mode
make test           # pytest + vitest
make test-cov       # With coverage report
make lint           # ruff + mypy + eslint
make format         # Auto-format (ruff + prettier)
make db-migrate     # Run Alembic migrations
make check          # Full CI check (lint + test + typecheck)
```

---

## Deployment

### Kubernetes

```bash
kubectl apply -f infra/k8s/base.yml
```

HPA-enabled (engine 2-8 replicas, workers 2-16), Ingress with TLS, PVC-backed PostgreSQL.

### Terraform (AWS)

```bash
cd infra/terraform && terraform init && terraform apply
```

Aurora PostgreSQL Serverless v2, ElastiCache Redis, ECS Fargate, S3, VPC with private subnets.

---

## Tech Stack

| Layer    | Technology                                                 |
| -------- | ---------------------------------------------------------- |
| Engine   | Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.0 (async) |
| EVM      | Foundry (forge)                                            |
| Frontend | Next.js 14, TypeScript, Tailwind CSS, React Query, Zustand |
| Database | PostgreSQL 16 (pgvector)                                   |
| Queue    | Redis + Celery                                             |
| Storage  | MinIO / S3                                                 |
| AI       | Anthropic Claude, OpenAI GPT-4o                            |
| Infra    | Docker Compose, Kubernetes, Terraform (AWS)                |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE)
