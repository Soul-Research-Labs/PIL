"""Docker sandbox — execute PoC exploits in isolated containers."""

from __future__ import annotations

import asyncio
import json
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engine.core.config import get_settings


@dataclass
class SandboxResult:
    """Result from a sandboxed PoC execution."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    exploit_confirmed: bool
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SandboxConfig:
    """Configuration for Docker sandbox."""

    image: str = "python:3.12-slim"
    timeout_seconds: int = 30
    memory_limit: str = "256m"
    cpu_limit: float = 0.5
    network_disabled: bool = True
    read_only_root: bool = True
    extra_mounts: list[str] = field(default_factory=list)


class DockerSandbox:
    """Execute PoC exploit code in an isolated Docker container.

    Security measures:
    - No network access (unless explicitly needed for blockchain forks)
    - Read-only root filesystem
    - Memory and CPU limits
    - Timeout enforcement
    - Dropped capabilities
    - No privilege escalation
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._docker_host = settings.docker_host

    async def execute(
        self,
        code: str,
        language: str,
        config: SandboxConfig | None = None,
        files: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Execute PoC code in a sandbox.

        Args:
            code: The exploit/PoC source code
            language: Programming language (python, javascript, solidity)
            config: Sandbox configuration overrides
            files: Additional files to mount {filename: content}
        """
        config = config or self._get_default_config(language)
        sandbox_id = str(uuid.uuid4())[:8]

        with tempfile.TemporaryDirectory(prefix=f"zaseon-sandbox-{sandbox_id}-") as tmpdir:
            tmppath = Path(tmpdir)

            # Write main PoC file
            main_file = self._write_main_file(tmppath, code, language)

            # Write additional files (with path traversal protection)
            if files:
                for fname, content in files.items():
                    # Sanitize filename: resolve and ensure it stays within tmpdir
                    safe_name = Path(fname).name  # Strip any directory traversal
                    if not safe_name or safe_name.startswith('.'):
                        continue
                    (tmppath / safe_name).write_text(content)

            # Build Docker command
            cmd = self._build_docker_cmd(
                sandbox_id, config, tmppath, main_file, language
            )

            # Execute with timeout
            try:
                result = await self._run_container(cmd, config.timeout_seconds)
            except asyncio.TimeoutError:
                result = SandboxResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="Execution timed out",
                    duration_seconds=config.timeout_seconds,
                    exploit_confirmed=False,
                    metadata={"reason": "timeout"},
                )

            # Analyze results
            result.exploit_confirmed = self._analyze_output(result)

            return result

    def _get_default_config(self, language: str) -> SandboxConfig:
        """Get default sandbox config for a language."""
        configs = {
            "python": SandboxConfig(image="python:3.12-slim"),
            "javascript": SandboxConfig(image="node:20-slim"),
            "typescript": SandboxConfig(image="node:20-slim"),
            "solidity": SandboxConfig(
                image="ghcr.io/foundry-rs/foundry:latest",
                timeout_seconds=60,
                memory_limit="512m",
                network_disabled=True,  # Disabled by default; enable explicitly for fork testing
            ),
        }
        return configs.get(language, SandboxConfig())

    def _write_main_file(self, tmpdir: Path, code: str, language: str) -> str:
        """Write the PoC code to the appropriate file."""
        ext_map = {
            "python": "exploit.py",
            "javascript": "exploit.js",
            "typescript": "exploit.ts",
            "solidity": "test/Exploit.t.sol",
        }
        filename = ext_map.get(language, "exploit.txt")
        filepath = tmpdir / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(code)
        return filename

    def _build_docker_cmd(
        self,
        sandbox_id: str,
        config: SandboxConfig,
        workdir: Path,
        main_file: str,
        language: str,
    ) -> list[str]:
        """Build the Docker run command."""
        cmd = [
            "docker", "run",
            "--rm",
            "--name", f"zaseon-poc-{sandbox_id}",
            "-v", f"{workdir}:/workspace:ro",
            "-w", "/workspace",
            "--memory", config.memory_limit,
            "--cpus", str(config.cpu_limit),
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
        ]

        if config.network_disabled:
            cmd.extend(["--network", "none"])

        if config.read_only_root:
            cmd.extend(["--read-only", "--tmpfs", "/tmp"])

        cmd.append(config.image)

        # Add execution command based on language
        exec_cmds = {
            "python": ["python", main_file],
            "javascript": ["node", main_file],
            "typescript": ["npx", "tsx", main_file],
            "solidity": ["forge", "test", "--match-path", f"test/{main_file}", "-vvv"],
        }
        cmd.extend(exec_cmds.get(language, ["cat", main_file]))

        return cmd

    async def _run_container(
        self, cmd: list[str], timeout: int
    ) -> SandboxResult:
        """Run Docker container and capture output."""
        import time
        start = time.time()

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        duration = time.time() - start

        return SandboxResult(
            success=proc.returncode == 0,
            exit_code=proc.returncode or 0,
            stdout=self._sanitize_output(stdout.decode("utf-8", errors="replace")[:50000]),
            stderr=self._sanitize_output(stderr.decode("utf-8", errors="replace")[:50000]),
            duration_seconds=duration,
            exploit_confirmed=False,
        )

    @staticmethod
    def _sanitize_output(text: str) -> str:
        """Strip HTML/script tags from sandbox output to prevent XSS."""
        import re
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<[^>]+>', '', text)
        return text

    def _analyze_output(self, result: SandboxResult) -> bool:
        """Analyze sandbox output to determine if exploit was confirmed."""
        output = result.stdout + result.stderr
        lower_output = output.lower()

        # Positive indicators — exploit confirmed
        success_markers = [
            "exploit successful",
            "vulnerability confirmed",
            "poc succeeded",
            "assertion passed",
            "[pass]",
            "test result: ok",
            "tests passed",
            "suite result: ok",
        ]

        # Negative indicators — exploit failed
        failure_markers = [
            "exploit failed",
            "vulnerability not confirmed",
            "poc failed",
            "assertion failed",
            "[fail]",
            "error:",
            "revert",
        ]

        has_success = any(m in lower_output for m in success_markers)
        has_failure = any(m in lower_output for m in failure_markers)

        if has_success and not has_failure:
            return True
        if result.success and not has_failure:
            return True
        return False


class FoundrySandbox(DockerSandbox):
    """Specialized sandbox for Foundry-based smart contract PoCs.

    Supports:
    - Fork testing against mainnet/testnet
    - Cheatcodes (vm.prank, vm.deal, vm.warp, etc.)
    - Gas profiling
    - Trace output
    """

    async def execute_foundry_test(
        self,
        test_contract: str,
        target_contract: str | None = None,
        fork_url: str | None = None,
        fork_block: int | None = None,
    ) -> SandboxResult:
        """Execute a Foundry test exploiting a vulnerability.

        Args:
            test_contract: Solidity test code using Foundry's Test framework
            target_contract: The vulnerable contract source (optional)
            fork_url: RPC URL for fork testing
            fork_block: Block number for fork
        """
        files: dict[str, str] = {}

        if target_contract:
            files["src/Target.sol"] = target_contract

        # Create foundry.toml
        foundry_config = ['[profile.default]', 'src = "src"', 'out = "out"', 'libs = ["lib"]']
        if fork_url:
            foundry_config.append(f'eth_rpc_url = "{fork_url}"')
        if fork_block:
            foundry_config.append(f'fork_block_number = {fork_block}')
        files["foundry.toml"] = "\n".join(foundry_config)

        config = SandboxConfig(
            image="ghcr.io/foundry-rs/foundry:latest",
            timeout_seconds=120,
            memory_limit="1g",
            cpu_limit=1.0,
            network_disabled=fork_url is None,
            read_only_root=False,
        )

        return await self.execute(
            test_contract, "solidity", config=config, files=files
        )
