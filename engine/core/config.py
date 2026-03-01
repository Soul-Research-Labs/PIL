"""Core configuration for the ZASEON engine."""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ZASEON_",
        case_sensitive=False,
    )

    # ── App ──────────────────────────────────────────────────────────────
    app_name: str = "ZASEON Engine"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:3001"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 30

    # ── Database ─────────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://zaseon:zaseon@localhost:5432/zaseon"
    database_echo: bool = False

    # ── Redis ────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # ── S3 / MinIO ───────────────────────────────────────────────────────
    s3_endpoint: str = "http://localhost:9000"
    s3_access_key: str = ""  # REQUIRED — set ZASEON_S3_ACCESS_KEY
    s3_secret_key: str = ""  # REQUIRED — set ZASEON_S3_SECRET_KEY
    s3_bucket_repos: str = "zaseon-repos"
    s3_bucket_reports: str = "zaseon-reports"
    s3_bucket_artifacts: str = "zaseon-artifacts"

    # ── GitHub App ───────────────────────────────────────────────────────
    github_app_id: str = ""
    github_app_private_key: str = ""
    github_webhook_secret: str = ""
    github_token: str = ""  # Personal access token for repo cloning

    # ── LLM ──────────────────────────────────────────────────────────────
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    primary_llm_model: str = "claude-sonnet-4-20250514"
    fallback_llm_model: str = "gpt-4o"
    llm_fast_model: str = "claude-haiku-4-20250514"
    llm_max_tokens: int = 8192
    llm_temperature: float = 0.1
    llm_max_retries: int = 3
    llm_retry_base_delay: float = 1.0

    # ── Blockchain / Web3 ────────────────────────────────────────────────
    etherscan_api_key: str = ""
    bscscan_api_key: str = ""
    polygonscan_api_key: str = ""
    alchemy_api_key: str = ""
    infura_api_key: str = ""

    # ── Docker sandbox ───────────────────────────────────────────────────
    docker_host: str = "unix:///var/run/docker.sock"
    sandbox_timeout_seconds: int = 120
    sandbox_memory_limit: str = "512m"
    sandbox_cpu_limit: float = 1.0

    # ── Foundry ──────────────────────────────────────────────────────────
    foundry_bin_path: str = "/usr/local/bin"

    # ── Soul Protocol Fuzzer ─────────────────────────────────────────────
    soul_repo_url: str = "https://github.com/Soul-Research-Labs/SOUL.git"
    soul_repo_branch: str = "main"
    soul_cache_dir: str = "/tmp/zaseon_soul"
    soul_fuzz_default_mode: str = "standard"
    soul_fuzz_max_duration: int = 300
    soul_fuzz_max_iterations: int = 50_000
    soul_fuzz_parallel_workers: int = 4
    soul_fuzz_enable_llm: bool = True
    soul_fuzz_save_corpus: bool = True
    soul_fuzz_corpus_dir: str = "/tmp/zaseon_soul_corpus"

    # ── v2 Engine Toggles ────────────────────────────────────────────────
    soul_fuzz_enable_bytecode: bool = True
    soul_fuzz_enable_taint: bool = True
    soul_fuzz_enable_gas_profiling: bool = True
    soul_fuzz_enable_invariant_synth: bool = True
    soul_fuzz_enable_state_replay: bool = True
    soul_fuzz_enable_exploit_composer: bool = True

    # ── Bytecode Analyzer ────────────────────────────────────────────────
    bytecode_max_instructions: int = 100_000
    bytecode_enable_cfg: bool = True
    bytecode_enable_storage_layout: bool = True

    # ── Taint Mutator ────────────────────────────────────────────────────
    taint_max_propagation_depth: int = 50
    taint_source_types: int = 17
    taint_sink_types: int = 15

    # ── Gas Profiler ─────────────────────────────────────────────────────
    gas_profiler_evm_version: str = "shanghai"
    gas_profiler_anomaly_threshold: float = 2.0
    gas_profiler_max_traces: int = 10_000

    # ── Invariant Synthesizer ────────────────────────────────────────────
    invariant_min_confidence: float = 0.7
    invariant_max_templates: int = 30
    invariant_wilson_alpha: float = 0.05

    # ── State Replay ─────────────────────────────────────────────────────
    state_replay_max_snapshots: int = 1_000
    state_replay_bisection_depth: int = 20
    state_replay_modes: int = 6

    # ── Exploit Composer ─────────────────────────────────────────────────
    exploit_max_chain_length: int = 10
    exploit_attack_primitives: int = 34
    exploit_enable_flash_loan: bool = True

    # ── Auto-Remediation ─────────────────────────────────────────────────
    remediation_enabled: bool = False
    remediation_auto_pr: bool = False
    remediation_min_confidence: float = 0.85
    remediation_max_patch_attempts: int = 3


@lru_cache
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()
