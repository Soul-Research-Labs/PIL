"""Soul Protocol contract fetcher.

Fetches Soul Protocol contracts from GitHub for analysis:
  - Clone / update the Soul repo
  - Index all Solidity files by category
  - Resolve import dependencies
  - Detect framework (Foundry)
  - Provide contract source to the fuzzer

Supports:
  - Full repo fetch (all contracts)
  - Category-based fetch (e.g., only bridge or privacy)
  - Single contract fetch by name
  - Version tracking (git tag / commit)
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

SOUL_REPO = "https://github.com/Soul-Research-Labs/SOUL.git"
SOUL_REPO_API = "https://api.github.com/repos/Soul-Research-Labs/SOUL"
SOUL_CONTRACTS_ROOT = "contracts"


class SoulContractDir(str, Enum):
    """Directories in the Soul Protocol contracts/ folder."""
    CORE = "core"
    PRIMITIVES = "primitives"
    BRIDGE = "bridge"
    PRIVACY = "privacy"
    SECURITY = "security"
    CROSSCHAIN = "crosschain"
    COMPLIANCE = "compliance"
    GOVERNANCE = "governance"
    RELAYER = "relayer"
    VERIFIERS = "verifiers"
    LIBRARIES = "libraries"
    UPGRADEABLE = "upgradeable"


@dataclass
class SoulContractFile:
    """A single Solidity file from the Soul repo."""
    name: str
    path: str
    category: SoulContractDir | None
    source: str
    size: int
    imports: list[str] = field(default_factory=list)
    pragma: str = ""


@dataclass
class SoulRepoSnapshot:
    """A snapshot of the Soul Protocol repository."""
    commit: str
    branch: str
    tag: str | None
    files: list[SoulContractFile]
    total_contracts: int
    total_lines: int
    framework: str = "foundry"

    @property
    def by_category(self) -> dict[str, list[SoulContractFile]]:
        result: dict[str, list[SoulContractFile]] = {}
        for f in self.files:
            cat = f.category.value if f.category else "uncategorized"
            result.setdefault(cat, []).append(f)
        return result


class SoulContractFetcher:
    """Fetch Soul Protocol contracts from GitHub."""

    def __init__(
        self,
        cache_dir: str | None = None,
        github_token: str | None = None,
    ):
        self.cache_dir = Path(cache_dir or tempfile.mkdtemp(prefix="zaseon_soul_"))
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self._repo_path: Path | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_all(
        self,
        branch: str = "main",
        refresh: bool = False,
    ) -> SoulRepoSnapshot:
        """Fetch all Soul Protocol contracts.

        Args:
            branch: Git branch to fetch.
            refresh: Force re-clone even if cached.

        Returns:
            SoulRepoSnapshot with all Solidity files indexed.
        """
        repo_path = await self._ensure_repo(branch, refresh)
        contracts_dir = repo_path / SOUL_CONTRACTS_ROOT

        if not contracts_dir.exists():
            # Try src/ as alternative
            contracts_dir = repo_path / "src"
            if not contracts_dir.exists():
                logger.warning("No contracts/ or src/ directory found")
                contracts_dir = repo_path

        files = self._index_solidity_files(contracts_dir, repo_path)
        commit = await self._get_commit_hash(repo_path)
        tag = await self._get_latest_tag(repo_path)

        total_lines = sum(f.source.count("\n") for f in files)

        snapshot = SoulRepoSnapshot(
            commit=commit,
            branch=branch,
            tag=tag,
            files=files,
            total_contracts=len(files),
            total_lines=total_lines,
        )

        logger.info(
            "Fetched Soul Protocol: %d contracts, %d lines (commit %s)",
            snapshot.total_contracts,
            snapshot.total_lines,
            snapshot.commit[:8],
        )

        return snapshot

    async def fetch_category(
        self,
        category: SoulContractDir,
        branch: str = "main",
    ) -> list[SoulContractFile]:
        """Fetch contracts from a specific category directory."""
        snapshot = await self.fetch_all(branch)
        return [
            f for f in snapshot.files
            if f.category == category
        ]

    async def fetch_contract(
        self,
        contract_name: str,
        branch: str = "main",
    ) -> SoulContractFile | None:
        """Fetch a single contract by name."""
        snapshot = await self.fetch_all(branch)
        for f in snapshot.files:
            if f.name == contract_name or f.name == f"{contract_name}.sol":
                return f
        return None

    async def fetch_with_dependencies(
        self,
        contract_name: str,
        branch: str = "main",
    ) -> dict[str, str]:
        """Fetch a contract and all its import dependencies.

        Returns:
            Dict mapping file path → source code.
        """
        snapshot = await self.fetch_all(branch)
        file_map = {f.path: f for f in snapshot.files}
        name_map = {f.name: f for f in snapshot.files}

        # Find the target contract
        target = name_map.get(contract_name) or name_map.get(f"{contract_name}.sol")
        if not target:
            return {}

        # BFS to resolve all imports
        resolved: dict[str, str] = {}
        queue = [target]
        visited: set[str] = set()

        while queue:
            current = queue.pop(0)
            if current.path in visited:
                continue
            visited.add(current.path)
            resolved[current.path] = current.source

            for imp in current.imports:
                # Resolve import path
                imp_file = self._resolve_import(imp, current.path, file_map, name_map)
                if imp_file and imp_file.path not in visited:
                    queue.append(imp_file)

        return resolved

    def get_source_map(self, snapshot: SoulRepoSnapshot) -> dict[str, str]:
        """Get {name: source_code} map from snapshot."""
        return {f.name: f.source for f in snapshot.files}

    # ------------------------------------------------------------------
    # Repository management
    # ------------------------------------------------------------------

    async def _ensure_repo(
        self,
        branch: str,
        refresh: bool,
    ) -> Path:
        """Ensure the Soul repo is available locally."""
        repo_path = self.cache_dir / "SOUL"

        if repo_path.exists() and not refresh:
            # Pull latest
            await self._run_git(
                ["git", "fetch", "origin", branch],
                cwd=repo_path,
            )
            await self._run_git(
                ["git", "checkout", branch],
                cwd=repo_path,
            )
            await self._run_git(
                ["git", "pull", "origin", branch],
                cwd=repo_path,
            )
        else:
            if repo_path.exists():
                shutil.rmtree(repo_path)

            clone_url = SOUL_REPO
            if self.github_token:
                clone_url = SOUL_REPO.replace(
                    "https://",
                    f"https://{self.github_token}@",
                )

            await self._run_git(
                [
                    "git", "clone",
                    "--depth", "1",
                    "--branch", branch,
                    clone_url,
                    str(repo_path),
                ],
            )

        self._repo_path = repo_path
        return repo_path

    async def _run_git(
        self,
        cmd: list[str],
        cwd: Path | None = None,
    ) -> str:
        """Run a git command."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.warning("Git command failed: %s\n%s", cmd, stderr.decode())
                return ""

            return stdout.decode().strip()
        except Exception as e:
            logger.warning("Git command error: %s — %s", cmd, e)
            return ""

    async def _get_commit_hash(self, repo_path: Path) -> str:
        return await self._run_git(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
        )

    async def _get_latest_tag(self, repo_path: Path) -> str | None:
        tag = await self._run_git(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=repo_path,
        )
        return tag or None

    # ------------------------------------------------------------------
    # File indexing
    # ------------------------------------------------------------------

    def _index_solidity_files(
        self,
        contracts_dir: Path,
        repo_root: Path,
    ) -> list[SoulContractFile]:
        """Index all .sol files in the contracts directory."""
        files: list[SoulContractFile] = []

        for sol_path in sorted(contracts_dir.rglob("*.sol")):
            try:
                source = sol_path.read_text(encoding="utf-8")
                rel_path = str(sol_path.relative_to(repo_root))
                category = self._detect_category(rel_path)
                imports = self._extract_imports(source)
                pragma = self._extract_pragma(source)

                files.append(SoulContractFile(
                    name=sol_path.name,
                    path=rel_path,
                    category=category,
                    source=source,
                    size=len(source),
                    imports=imports,
                    pragma=pragma,
                ))
            except Exception as e:
                logger.warning("Failed to index %s: %s", sol_path, e)

        return files

    def _detect_category(self, rel_path: str) -> SoulContractDir | None:
        """Detect contract category from its path."""
        parts = rel_path.lower().split("/")
        for part in parts:
            for cat in SoulContractDir:
                if cat.value == part:
                    return cat
        return None

    def _extract_imports(self, source: str) -> list[str]:
        """Extract import paths from Solidity source."""
        imports: list[str] = []
        for line in source.splitlines():
            line = line.strip()
            if line.startswith("import"):
                # Extract path from import statement
                if '"' in line:
                    start = line.index('"') + 1
                    end = line.index('"', start)
                    imports.append(line[start:end])
                elif "'" in line:
                    start = line.index("'") + 1
                    end = line.index("'", start)
                    imports.append(line[start:end])
        return imports

    def _extract_pragma(self, source: str) -> str:
        """Extract pragma version from source."""
        for line in source.splitlines():
            line = line.strip()
            if line.startswith("pragma solidity"):
                return line.rstrip(";").replace("pragma solidity ", "")
        return ""

    def _resolve_import(
        self,
        import_path: str,
        from_path: str,
        file_map: dict[str, SoulContractFile],
        name_map: dict[str, SoulContractFile],
    ) -> SoulContractFile | None:
        """Resolve an import path to a SoulContractFile."""
        # Try direct path match
        if import_path in file_map:
            return file_map[import_path]

        # Try relative resolution
        from_dir = "/".join(from_path.split("/")[:-1])
        resolved = os.path.normpath(f"{from_dir}/{import_path}")
        if resolved in file_map:
            return file_map[resolved]

        # Try by filename
        filename = import_path.split("/")[-1]
        if filename in name_map:
            return name_map[filename]

        # Try without leading paths (forge remappings)
        for key, f in file_map.items():
            if key.endswith(import_path) or key.endswith(filename):
                return f

        return None
