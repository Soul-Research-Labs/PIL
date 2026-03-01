"""GitHub repository ingestion with Solidity-aware file discovery.

Supports:
  - Shallow + full clones with token auth
  - Incremental (PR diff) scanning
  - Solidity import resolution
  - Hardhat / Foundry / Truffle project detection
  - Multi-file source aggregation for compilation
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import git

from engine.core.config import get_settings

logger = logging.getLogger(__name__)

# ── Import resolution regex ──────────────────────────────────────────────────
_IMPORT_RE = re.compile(
    r"""import\s+(?:"""
    r""""([^"]+)"|"""
    r"""'([^']+)'|"""
    r"""\{[^}]+\}\s+from\s+["']([^"']+)["']"""
    r""");""",
    re.MULTILINE,
)

# Known Solidity frameworks
_FRAMEWORK_MARKERS = {
    "foundry.toml": "foundry",
    "hardhat.config.js": "hardhat",
    "hardhat.config.ts": "hardhat",
    "truffle-config.js": "truffle",
    "brownie-config.yaml": "brownie",
    "ape-config.yaml": "ape",
}

# Common dependency paths
_REMAPPING_DIRS = [
    "node_modules",
    "lib",
    ".deps",
]


class GitHubIngester:
    """Clone and manage GitHub repositories for Solidity scanning."""

    def __init__(self, work_dir: str | None = None) -> None:
        self.settings = get_settings()
        self.work_dir = Path(work_dir or tempfile.mkdtemp(prefix="zaseon-"))

    # ── Cloning ──────────────────────────────────────────────────────

    async def clone_repo(
        self,
        repo_url: str,
        branch: str | None = None,
        commit_sha: str | None = None,
        shallow: bool = True,
    ) -> Path:
        """Clone a GitHub repository to a local temp directory.

        Runs git clone in a thread pool to stay async-friendly.
        """
        return await asyncio.to_thread(
            self._clone_sync, repo_url, branch, commit_sha, shallow
        )

    def _clone_sync(
        self,
        repo_url: str,
        branch: str | None,
        commit_sha: str | None,
        shallow: bool,
    ) -> Path:
        # Validate URL scheme to prevent SSRF (only https allowed)
        if not repo_url.startswith("https://"):
            raise ValueError(f"Only HTTPS repository URLs are allowed, got: {repo_url}")

        # Sanitize repo name to prevent directory traversal
        raw_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        repo_name = re.sub(r'[^a-zA-Z0-9._-]', '_', raw_name)
        if not repo_name:
            repo_name = "repo"
        clone_path = self.work_dir / repo_name

        if clone_path.exists():
            shutil.rmtree(clone_path)

        # Inject token if configured (via env var, not in URL)
        env = os.environ.copy()
        token = self.settings.github_token
        if token:
            # Use GIT_ASKPASS to avoid leaking token in URL/logs/process list
            askpass_script = self.work_dir / ".git-askpass.sh"
            askpass_script.write_text(f"#!/bin/sh\necho {token}\n")
            askpass_script.chmod(0o700)
            env["GIT_ASKPASS"] = str(askpass_script)
            env["GIT_TERMINAL_PROMPT"] = "0"

        clone_kwargs: dict[str, Any] = {"url": repo_url, "to_path": str(clone_path)}

        if shallow and not commit_sha:
            clone_kwargs["depth"] = 1

        if branch:
            clone_kwargs["branch"] = branch

        logger.info("Cloning %s (branch=%s, shallow=%s)", repo_url, branch, shallow)
        repo = git.Repo.clone_from(env=env, **clone_kwargs)

        if commit_sha:
            repo.git.checkout(commit_sha)

        logger.info("Cloned to %s", clone_path)

        # Clean up askpass script
        askpass = self.work_dir / ".git-askpass.sh"
        if askpass.exists():
            askpass.unlink()

        return clone_path

    def _authenticated_url(self, url: str) -> str:
        """Inject GitHub token into HTTPS URL for private repo access.

        DEPRECATED: Use GIT_ASKPASS instead. Kept for backward compatibility.
        """
        token = self.settings.github_token
        if not token:
            return url
        if url.startswith("https://github.com/"):
            return url.replace("https://github.com/", f"https://x-access-token:{token}@github.com/")
        return url

    # ── File Discovery ───────────────────────────────────────────────

    def get_changed_files(
        self,
        repo_path: Path,
        base_sha: str,
        head_sha: str,
    ) -> list[str]:
        """Get files changed between two commits for incremental scanning."""
        repo = git.Repo(str(repo_path))
        diff = repo.git.diff("--name-only", base_sha, head_sha)
        return [f for f in diff.strip().split("\n") if f]

    def get_file_tree(
        self,
        repo_path: Path,
        extensions: set[str] | None = None,
    ) -> list[Path]:
        """Walk the repository and return all relevant source files."""
        if extensions is None:
            extensions = {".sol", ".vy"}

        files: list[Path] = []
        skip_dirs = {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            "dist", "build", "artifacts", "cache", "out", "typechain-types",
        }

        for path in repo_path.rglob("*"):
            if any(part in skip_dirs for part in path.parts):
                continue
            if path.is_file() and path.suffix in extensions:
                files.append(path)

        return files

    def detect_framework(self, repo_path: Path) -> str | None:
        """Detect the Solidity development framework used."""
        for marker, framework in _FRAMEWORK_MARKERS.items():
            if (repo_path / marker).exists():
                logger.info("Detected framework: %s (marker: %s)", framework, marker)
                return framework
        return None

    def get_solidity_sources(self, repo_path: Path) -> dict[str, str]:
        """Collect all Solidity source files as {relative_path: source_code}.

        Skips test files, scripts, and mock contracts.
        """
        sources: dict[str, str] = {}
        skip_patterns = {"test", "tests", "script", "scripts", "mock", "mocks"}

        sol_files = self.get_file_tree(repo_path, extensions={".sol"})

        for fpath in sol_files:
            rel = fpath.relative_to(repo_path)
            # Skip test/mock directories
            if any(part.lower() in skip_patterns for part in rel.parts):
                continue
            try:
                sources[str(rel)] = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                logger.warning("Failed to read %s: %s", rel, exc)

        logger.info("Found %d Solidity source files in %s", len(sources), repo_path)
        return sources

    def resolve_imports(
        self,
        source_code: str,
        file_path: Path,
        repo_path: Path,
    ) -> dict[str, str]:
        """Resolve import paths for a single Solidity file.

        Returns a mapping of import path → resolved source code.
        Handles: relative imports, remappings (lib/), node_modules, @openzeppelin.
        """
        resolved: dict[str, str] = {}

        for match in _IMPORT_RE.finditer(source_code):
            import_path = match.group(1) or match.group(2) or match.group(3)
            if not import_path:
                continue

            real_path = self._resolve_single_import(import_path, file_path, repo_path)
            if real_path and real_path.exists():
                try:
                    resolved[import_path] = real_path.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    logger.debug("Failed to read import %s: %s", import_path, e)

        return resolved

    def _resolve_single_import(
        self,
        import_path: str,
        current_file: Path,
        repo_root: Path,
    ) -> Path | None:
        """Resolve a single import statement to a filesystem path."""
        # Relative import
        if import_path.startswith("."):
            candidate = (current_file.parent / import_path).resolve()
            if candidate.exists():
                return candidate

        # Absolute from repo root (src/ convention)
        for prefix in ["src", "contracts", ""]:
            candidate = repo_root / prefix / import_path
            if candidate.exists():
                return candidate

        # Remapping dirs (lib/, node_modules/)
        for rdir in _REMAPPING_DIRS:
            # Try: lib/@openzeppelin/contracts/token/ERC20/ERC20.sol
            candidate = repo_root / rdir / import_path
            if candidate.exists():
                return candidate

            # Foundry-style: lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol
            parts = import_path.split("/")
            if len(parts) >= 2 and parts[0].startswith("@"):
                # @openzeppelin/contracts/... → openzeppelin-contracts/contracts/...
                alt_name = parts[0].lstrip("@") + "-" + parts[1]
                alt_path = "/".join([alt_name] + parts[2:])
                candidate = repo_root / rdir / alt_path
                if candidate.exists():
                    return candidate

        return None

    def get_foundry_remappings(self, repo_path: Path) -> dict[str, str]:
        """Parse foundry.toml or remappings.txt for import remappings."""
        remappings: dict[str, str] = {}

        # remappings.txt
        remap_file = repo_path / "remappings.txt"
        if remap_file.exists():
            for line in remap_file.read_text().strip().splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, val = line.split("=", 1)
                    remappings[key.strip()] = val.strip()

        return remappings

    # ── Cleanup ──────────────────────────────────────────────────────

    def cleanup(self) -> None:
        """Remove temporary working directory."""
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)
