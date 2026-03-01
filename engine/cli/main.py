"""ZASEON CLI — local smart contract security scanner.

Usage:
    zaseon scan <path>              Scan a Solidity file or project directory
    zaseon scan --address <addr>    Fetch and scan a verified contract from Etherscan
    zaseon report <scan-id>         Generate a report from a previous scan
    zaseon config                   Show current configuration
    zaseon version                  Print version

Examples:
    zaseon scan ./contracts/
    zaseon scan ./contracts/Token.sol --severity high --format sarif -o results.sarif
    zaseon scan --address 0x1234...abcd --chain ethereum
    zaseon report latest --format pdf -o audit.pdf
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from engine.core.types import ScanResult, Severity


# ── Coloured output helpers ──────────────────────────────────────────────────

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_DIM = "\033[2m"

_SEV_COLOR = {
    "critical": _RED,
    "high": "\033[38;5;208m",  # orange
    "medium": _YELLOW,
    "low": _CYAN,
    "informational": _DIM,
    "gas": _DIM,
}


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}"


# ── Banner ───────────────────────────────────────────────────────────────────

BANNER = rf"""
{_BOLD}{_CYAN} ______  _    ___  _____ ___  _   _
|__  / _` /  ___|| ____/ _ \| \ | |
  / / (_| \___ \|  _|| | | |  \| |
 / _ \__,_|___) | |__| |_| | |\  |
/____\__,_|____/|_____\___/|_| \_|{_RESET}
  {_DIM}Smart Contract Security Scanner — v2.0.0{_RESET}
"""


# ── CLI argument parser ─────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zaseon",
        description="ZASEON — smart contract security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the startup banner")
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output")

    sub = parser.add_subparsers(dest="command")

    # ── scan ─────────────────────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Scan Solidity files or a contract address")
    scan_p.add_argument("path", nargs="?", help="Path to .sol file or project directory")
    scan_p.add_argument("--address", "-a", help="On-chain contract address to fetch & scan")
    scan_p.add_argument(
        "--chain",
        default="ethereum",
        choices=["ethereum", "polygon", "arbitrum", "optimism", "base", "bsc"],
        help="Chain to fetch contract from (default: ethereum)",
    )
    scan_p.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info", "gas"],
        help="Minimum severity to report",
    )
    scan_p.add_argument(
        "--format",
        "-f",
        default="table",
        choices=["table", "json", "sarif", "html"],
        help="Output format (default: table)",
    )
    scan_p.add_argument("--output", "-o", help="Write output to file instead of stdout")
    scan_p.add_argument("--no-verify", action="store_true", help="Skip PoC verification step")
    scan_p.add_argument("--no-llm", action="store_true", help="Disable LLM-powered deep analysis")
    scan_p.add_argument("--max-findings", type=int, default=0, help="Limit findings shown (0=all)")

    # ── report ───────────────────────────────────────────────────────────────
    report_p = sub.add_parser("report", help="Generate report from scan results")
    report_p.add_argument("scan_id", help="Scan ID (or 'latest')")
    report_p.add_argument(
        "--format",
        "-f",
        default="html",
        choices=["html", "pdf", "json", "sarif"],
        help="Report format (default: html)",
    )
    report_p.add_argument("--output", "-o", help="Output file path")

    # ── config ───────────────────────────────────────────────────────────────
    sub.add_parser("config", help="Show current configuration")

    return parser


# ── Scan command ─────────────────────────────────────────────────────────────

_SEV_ORDER = ["critical", "high", "medium", "low", "informational", "gas"]


def _sev_index(sev: str) -> int:
    try:
        return _SEV_ORDER.index(sev.lower())
    except ValueError:
        return 99


def _filter_findings(result: ScanResult, min_severity: str | None, max_count: int) -> list:
    findings = list(result.findings)
    if min_severity:
        # "info" is an alias
        if min_severity == "info":
            min_severity = "informational"
        cutoff = _sev_index(min_severity)
        findings = [f for f in findings if _sev_index(f.severity.value) <= cutoff]

    # Sort by severity (critical first)
    findings.sort(key=lambda f: _sev_index(f.severity.value))

    if max_count > 0:
        findings = findings[:max_count]
    return findings


def _print_table(findings: list, result: ScanResult, quiet: bool = False) -> None:
    """Pretty-print findings as a coloured table."""
    if not quiet:
        print(f"\n{_BOLD}Scan complete{_RESET} — {result.scan_id}")
        print(
            f"  Score: {_c(f'{result.security_score:.0f}/100', _GREEN if result.security_score >= 80 else _YELLOW)}"
            f"  |  Lines scanned: {result.total_lines_scanned}"
            f"  |  Duration: {result.scan_duration_seconds:.1f}s\n"
        )

    if not findings:
        print(_c("  ✓ No findings at the requested severity level.", _GREEN))
        return

    # Count by severity
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    summary_parts = []
    for sev in _SEV_ORDER:
        count = by_sev.get(sev, 0)
        if count > 0:
            summary_parts.append(f"{_SEV_COLOR.get(sev, '')}{count} {sev.upper()}{_RESET}")
    print(f"  {' · '.join(summary_parts)}\n")

    # Print each finding
    for i, f in enumerate(findings, 1):
        sev_col = _SEV_COLOR.get(f.severity.value, "")
        badge = _c(f" {f.severity.value.upper()} ", sev_col + _BOLD)
        title = _c(f.title, _BOLD)
        loc = ""
        if f.location and f.location.file_path:
            loc = _c(
                f"  {f.location.file_path}:{f.location.start_line}",
                _DIM,
            )

        print(f"  {_DIM}{i:>3}.{_RESET} {badge} {title}{loc}")

        if f.description and not quiet:
            # Truncate long descriptions
            desc = f.description[:200]
            if len(f.description) > 200:
                desc += "…"
            print(f"       {_DIM}{desc}{_RESET}")

        cwe = f.cwe_id or f.scwe_id or ""
        if cwe:
            print(f"       {_DIM}Ref: {cwe}{_RESET}")

        print()


async def _run_scan(args: argparse.Namespace) -> int:
    """Execute a scan and print results."""
    from engine.pipeline.orchestrator import ScanOrchestrator
    from engine.reports.generator import ReportGenerator

    if not args.path and not args.address:
        print(_c("Error: provide a path or --address to scan.", _RED), file=sys.stderr)
        return 1

    scan_id = str(uuid.uuid4())
    config: dict[str, Any] = {"scan_id": scan_id}

    if args.address:
        config["contract_address"] = args.address
        config["chain"] = args.chain
        if not args.quiet:
            print(f"  Fetching contract {_c(args.address, _CYAN)} on {args.chain}…")
    else:
        path = Path(args.path).resolve()
        if not path.exists():
            print(_c(f"Error: path '{path}' does not exist.", _RED), file=sys.stderr)
            return 1

        if path.is_file():
            config["source_code"] = path.read_text()
            config["file_path"] = str(path)
            if not args.quiet:
                print(f"  Scanning {_c(str(path), _CYAN)}…")
        else:
            # Collect all .sol files in directory
            sol_files = sorted(path.rglob("*.sol"))
            if not sol_files:
                print(_c(f"Error: no .sol files found in '{path}'.", _RED), file=sys.stderr)
                return 1

            source_parts = []
            for sf in sol_files:
                source_parts.append(f"// File: {sf.relative_to(path)}\n{sf.read_text()}")
            config["source_code"] = "\n\n".join(source_parts)
            config["project_path"] = str(path)
            if not args.quiet:
                print(f"  Scanning {_c(str(len(sol_files)), _CYAN)} Solidity files in {path}…")

    start = time.monotonic()
    orchestrator = ScanOrchestrator(enable_llm=not args.no_llm)

    try:
        raw_result = await orchestrator.run(
            scan_id=scan_id,
            project_id="cli-local",
            config=config,
        )
    except Exception as exc:
        print(_c(f"\nScan failed: {exc}", _RED), file=sys.stderr)
        return 1

    elapsed = time.monotonic() - start

    # Build ScanResult from orchestrator dict
    from engine.core.types import ScanType, SecurityScore

    result = ScanResult(
        scan_id=scan_id,
        scan_type=ScanType.SMART_CONTRACT,
        findings=raw_result.get("findings", []),
        gas_optimizations=raw_result.get("gas_optimizations", []),
        security_score=raw_result.get("security_score", 0),
        threat_score=raw_result.get("threat_score", 0),
        total_lines_scanned=raw_result.get("total_lines_scanned", 0),
        scan_duration_seconds=elapsed,
        metadata=raw_result.get("metadata", {}),
    )

    findings = _filter_findings(result, args.severity, args.max_findings)

    # Format output
    fmt = args.format
    reporter = ReportGenerator()

    if fmt == "table":
        _print_table(findings, result, quiet=args.quiet)
        output = None
    elif fmt == "json":
        output = reporter.generate_json(result)
    elif fmt == "sarif":
        output = reporter.generate_sarif(result)
    elif fmt == "html":
        output = reporter.generate_html(result)
    else:
        output = None

    if output:
        if args.output:
            Path(args.output).write_text(output)
            if not args.quiet:
                print(f"  Written to {_c(args.output, _CYAN)}")
        else:
            print(output)

    # Exit code: 1 if any critical/high findings
    has_critical = any(
        f.severity.value in ("critical", "high") for f in findings
    )
    return 1 if has_critical else 0


# ── Report command ───────────────────────────────────────────────────────────


async def _run_report(args: argparse.Namespace) -> int:
    """Generate a report from stored scan results."""
    print(_c("Report generation from stored scans requires a running database.", _YELLOW))
    print("  Use `zaseon scan --format pdf -o report.pdf` for local reports.")
    return 0


# ── Config command ───────────────────────────────────────────────────────────


def _run_config() -> int:
    """Print current settings (redacted)."""
    from engine.core.config import get_settings

    s = get_settings()
    print(f"\n{_BOLD}ZASEON Configuration{_RESET}\n")
    for field_name in sorted(s.model_fields.keys()):
        val = getattr(s, field_name, "")
        # Redact secrets
        if any(kw in field_name for kw in ("password", "secret", "key", "token")):
            val = "****" if val else "(not set)"
        print(f"  {_DIM}{field_name}:{_RESET}  {val}")
    print()
    return 0


# ── Entrypoint ───────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print("zaseon 2.0.0")
        return 0

    if not args.no_banner if hasattr(args, "no_banner") else True:
        print(BANNER, file=sys.stderr)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "config":
        return _run_config()

    if args.command == "scan":
        return asyncio.run(_run_scan(args))

    if args.command == "report":
        return asyncio.run(_run_report(args))

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
