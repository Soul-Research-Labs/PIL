# Contributing to ZASEON

Thank you for your interest in contributing to ZASEON! This guide will help you get started.

## Getting Started

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker & Docker Compose
- Foundry (for smart contract execution)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/zaseon.git
cd zaseon

# Start infrastructure
docker compose up -d postgres redis minio minio-init

# Install engine dependencies
cd engine && pip install -e ".[dev]" && cd ..

# Install web dependencies
cd web && pnpm install && cd ..

# Run database migrations
cd engine && alembic upgrade head && cd ..

# Start development servers
make dev
```

## Development Workflow

### Branch Naming

- `feat/description` — New features
- `fix/description` — Bug fixes
- `refactor/description` — Code refactoring
- `docs/description` — Documentation updates
- `test/description` — Test additions/changes

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(fuzzer): add taint-guided mutation engine
fix(api): correct campaign status polling race condition
docs(readme): update architecture diagram
test(soul): add invariant synthesizer unit tests
```

### Code Quality

Before submitting a PR, ensure:

```bash
# Run all checks
make check

# Individual checks
make lint        # ruff + mypy + eslint
make test        # pytest with coverage
make format      # auto-format code
```

### Pull Request Process

1. Fork the repository and create your branch from `main`
2. Make your changes with clear, descriptive commits
3. Add/update tests for any new functionality
4. Ensure all CI checks pass (`make check`)
5. Update documentation if needed
6. Open a PR with a clear title and description
7. Link related issues

## Architecture Overview

- **`engine/`** — Python FastAPI backend
  - `core/` — Config, database, AST/CFG analyzers, types
  - `analyzer/` — 70+ detectors + 24 Soul detectors + LLM analyzer
  - `fuzzer/` — 13-engine fuzzing system with 18-phase pipeline
  - `api/` — REST API routes
  - `pipeline/` — Celery task orchestration
  - `remediator/` — Auto-remediation engine
- **`web/`** — Next.js 14 TypeScript frontend
- **`infra/`** — Kubernetes + Terraform IaC
- **`extensions/`** — VS Code extension

## Reporting Issues

- Use GitHub Issues
- Include reproduction steps, expected vs actual behavior
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## Good First Issues

Looking for a place to start? These are self-contained tasks ideal for new contributors:

| #   | Area      | Task                                                                             | Difficulty |
| --- | --------- | -------------------------------------------------------------------------------- | ---------- |
| 1   | Docs      | Add docstrings to all public classes in `engine/fuzzer/`                         | Easy       |
| 2   | Tests     | Write unit tests for `engine/fuzzer/gas_profiler.py`                             | Easy       |
| 3   | Tests     | Add pytest parametrize cases for `engine/core/types.py` edge cases               | Easy       |
| 4   | Detectors | Create a new Solidity detector for EIP-1153 transient storage misuse             | Medium     |
| 5   | Frontend  | Add dark/light theme toggle using Tailwind `dark:` classes                       | Easy       |
| 6   | Frontend  | Improve accessibility: add `aria-label` to all icon-only buttons                 | Easy       |
| 7   | API       | Add pagination to `/api/v1/findings` response                                    | Medium     |
| 8   | Fuzzer    | Implement a new mutation strategy for `bytes` ABI type boundary values           | Medium     |
| 9   | CI        | Add a spell-check GitHub Action for `.md` files                                  | Easy       |
| 10  | Infra     | Add health check endpoint (`/healthz`) to the Next.js frontend container         | Easy       |
| 11  | Reports   | Add CSV export option alongside the existing PDF report                          | Medium     |
| 12  | Docs      | Write an Architecture Decision Record (ADR) for the Forge-backed execution model | Easy       |

Search GitHub Issues for the `good-first-issue` label for the latest list.
