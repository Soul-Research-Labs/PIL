"""Tests for engine.core.config — settings loading and validation."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from engine.core.config import Settings, get_settings


class TestSettings:
    """Verify settings defaults and environment overrides."""

    def test_default_app_env(self):
        s = Settings()
        assert s.app_env == "development"

    def test_default_debug(self):
        s = Settings()
        assert s.debug is True

    def test_default_database_url(self):
        s = Settings()
        assert "postgresql+asyncpg" in s.database_url
        assert "zaseon" in s.database_url

    def test_default_redis_url(self):
        s = Settings()
        assert s.redis_url.startswith("redis://")

    def test_llm_defaults(self):
        s = Settings()
        assert "claude" in s.primary_llm_model
        assert s.fallback_llm_model == "gpt-4o"
        assert s.llm_max_tokens == 8192
        assert s.llm_temperature == 0.1

    def test_soul_fuzzer_defaults(self):
        s = Settings()
        assert s.soul_fuzz_default_mode == "standard"
        assert s.soul_fuzz_max_iterations == 50_000
        assert s.soul_fuzz_max_duration == 300
        assert s.soul_fuzz_parallel_workers == 4
        assert s.soul_fuzz_enable_llm is True
        assert s.soul_fuzz_save_corpus is True

    def test_sandbox_defaults(self):
        s = Settings()
        assert s.sandbox_timeout_seconds == 120
        assert s.sandbox_memory_limit == "512m"
        assert s.sandbox_cpu_limit == 1.0

    def test_s3_defaults(self):
        s = Settings()
        assert "minio" in s.s3_endpoint or "localhost" in s.s3_endpoint
        assert s.s3_bucket_repos == "zaseon-repos"
        assert s.s3_bucket_reports == "zaseon-reports"
        assert s.s3_bucket_artifacts == "zaseon-artifacts"

    @patch.dict(os.environ, {"ZASEON_APP_ENV": "production", "ZASEON_DEBUG": "false"})
    def test_env_override(self):
        """Environment variables with ZASEON_ prefix override defaults."""
        # Clear the lru_cache to pick up new env
        s = Settings()
        assert s.app_env == "production"
        assert s.debug is False

    def test_get_settings_returns_same_instance(self):
        """get_settings is cached — same object each call."""
        get_settings.cache_clear()
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2

    def test_chain_env_keys(self):
        s = Settings()
        assert hasattr(s, "etherscan_api_key")
        assert hasattr(s, "alchemy_api_key")
        assert hasattr(s, "infura_api_key")

    def test_foundry_bin_path(self):
        s = Settings()
        assert s.foundry_bin_path == "/usr/local/bin"
