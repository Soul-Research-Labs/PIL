"""PDF report generator using Jinja2 + WeasyPrint."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from engine.core.types import FindingSchema, ScanResult, SecurityScore, Severity


TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Generate professional PDF security audit reports.

    Features:
    - Executive summary with security score
    - Findings by severity with full details
    - Gas optimization section (for smart contracts)
    - Remediation roadmap
    - Verification status badges
    - Custom branding support
    """

    def __init__(self) -> None:
        self._jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
        )
        self._jinja_env.filters["severity_color"] = self._severity_color
        self._jinja_env.filters["severity_badge"] = self._severity_badge

    def generate_html(
        self,
        scan_result: ScanResult,
        project_name: str = "Unnamed Project",
        auditor_name: str = "ZASEON Security Scanner",
        branding: dict[str, str] | None = None,
    ) -> str:
        """Generate HTML report from scan results."""
        template = self._jinja_env.get_template("report.html")

        # Group findings by severity
        findings_by_severity: dict[str, list[dict]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFORMATIONAL": [],
        }
        for f in scan_result.findings:
            sev = f.severity.value.upper()
            if sev in findings_by_severity:
                findings_by_severity[sev].append(self._finding_to_dict(f))

        # Group gas optimizations
        gas_opts = [
            {
                "description": g.description,
                "suggestion": g.suggestion,
                "estimated_gas_saved": g.estimated_gas_saved,
                "category": g.category,
                "location": f"{g.location.file_path}:{g.location.start_line}" if g.location else "N/A",
            }
            for g in scan_result.gas_optimizations
        ]

        # Calculate summary stats
        total_findings = len(scan_result.findings)
        confirmed_count = sum(
            1 for f in scan_result.findings if f.metadata.get("verification", {}).get("exploit_confirmed")
        )

        context = {
            "project_name": project_name,
            "auditor_name": auditor_name,
            "scan_date": datetime.now(timezone.utc).strftime("%B %d, %Y"),
            "scan_id": scan_result.scan_id,
            "scan_type": scan_result.scan_type.value,
            "security_score": scan_result.security_score,
            "threat_score": scan_result.threat_score,
            "total_findings": total_findings,
            "confirmed_findings": confirmed_count,
            "findings_by_severity": findings_by_severity,
            "gas_optimizations": gas_opts,
            "total_lines": scan_result.total_lines_scanned,
            "scan_duration": f"{scan_result.scan_duration_seconds:.1f}s",
            "metadata": scan_result.metadata,
            "branding": branding or {},
            "score_grade": self._score_to_grade(scan_result.security_score),
            "score_color": self._score_to_color(scan_result.security_score),
        }

        return template.render(**context)

    def generate_pdf(
        self,
        scan_result: ScanResult,
        output_path: str,
        **kwargs: Any,
    ) -> str:
        """Generate PDF report with professional layout.

        Uses a PDF-optimized template with:
        - Cover page with grade badge and metadata
        - Table of contents
        - Page numbers and headers/footers
        - Severity distribution bar chart
        - Proper page breaks between sections

        Returns path to generated PDF file.
        """
        try:
            from weasyprint import HTML  # type: ignore
        except ImportError:
            raise RuntimeError(
                "WeasyPrint is required for PDF generation. "
                "Install it with: pip install weasyprint"
            )

        # Use PDF-specific template if available, fall back to standard
        try:
            pdf_template = self._jinja_env.get_template("report_pdf.html")
        except Exception:
            pdf_template = self._jinja_env.get_template("report.html")

        # Build context (same as generate_html but with PDF template)
        findings_by_severity: dict[str, list[dict]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFORMATIONAL": [],
        }
        for f in scan_result.findings:
            sev = f.severity.value.upper()
            if sev in findings_by_severity:
                findings_by_severity[sev].append(self._finding_to_dict(f))

        gas_opts = [
            {
                "description": g.description,
                "suggestion": g.suggestion,
                "estimated_gas_saved": g.estimated_gas_saved,
                "category": g.category,
                "location": f"{g.location.file_path}:{g.location.start_line}" if g.location else "N/A",
            }
            for g in scan_result.gas_optimizations
        ]

        total_findings = len(scan_result.findings)
        confirmed_count = sum(
            1 for f in scan_result.findings if f.metadata.get("verification", {}).get("exploit_confirmed")
        )

        project_name = kwargs.get("project_name", "Unnamed Project")
        auditor_name = kwargs.get("auditor_name", "ZASEON Security Scanner")
        branding = kwargs.get("branding", {})

        context = {
            "project_name": project_name,
            "auditor_name": auditor_name,
            "scan_date": datetime.now(timezone.utc).strftime("%B %d, %Y"),
            "scan_id": scan_result.scan_id,
            "scan_type": scan_result.scan_type.value,
            "security_score": scan_result.security_score,
            "threat_score": scan_result.threat_score,
            "total_findings": total_findings,
            "confirmed_findings": confirmed_count,
            "findings_by_severity": findings_by_severity,
            "gas_optimizations": gas_opts,
            "total_lines": scan_result.total_lines_scanned,
            "scan_duration": f"{scan_result.scan_duration_seconds:.1f}s",
            "metadata": scan_result.metadata,
            "branding": branding,
            "score_grade": self._score_to_grade(scan_result.security_score),
            "score_color": self._score_to_color(scan_result.security_score),
        }

        html_content = pdf_template.render(**context)
        HTML(string=html_content, base_url=str(TEMPLATE_DIR)).write_pdf(output_path)
        return output_path

    def generate_json(self, scan_result: ScanResult) -> str:
        """Generate machine-readable JSON report."""
        report = {
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan_result.scan_id,
            "scan_type": scan_result.scan_type.value,
            "security_score": scan_result.security_score,
            "threat_score": scan_result.threat_score,
            "total_lines_scanned": scan_result.total_lines_scanned,
            "scan_duration_seconds": scan_result.scan_duration_seconds,
            "findings": [self._finding_to_dict(f) for f in scan_result.findings],
            "gas_optimizations": [
                {
                    "description": g.description,
                    "suggestion": g.suggestion,
                    "estimated_gas_saved": g.estimated_gas_saved,
                    "category": g.category,
                }
                for g in scan_result.gas_optimizations
            ],
            "metadata": scan_result.metadata,
        }

        content = json.dumps(report, indent=2, default=str)

        # Add verification hash
        report["verification_hash"] = hashlib.sha256(content.encode()).hexdigest()

        return json.dumps(report, indent=2, default=str)

    def generate_sarif(self, scan_result: ScanResult) -> str:
        """Generate SARIF format for GitHub Advanced Security integration."""
        rules = []
        results = []

        for i, f in enumerate(scan_result.findings):
            rule_id = f.cwe_id or f.scwe_id or f"ZASEON-{i:04d}"

            rules.append({
                "id": rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description[:1000]},
                "defaultConfiguration": {
                    "level": self._severity_to_sarif_level(f.severity)
                },
                "properties": {
                    "security-severity": str(self._severity_to_score(f.severity)),
                    "tags": ["security", f.category],
                },
            })

            results.append({
                "ruleId": rule_id,
                "message": {"text": f.description},
                "level": self._severity_to_sarif_level(f.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location.file_path},
                            "region": {
                                "startLine": f.location.start_line,
                                "endLine": f.location.end_line,
                            },
                        }
                    }
                ],
                "fixes": [
                    {
                        "description": {"text": f.remediation},
                    }
                ] if f.remediation else [],
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ZASEON",
                            "version": "0.1.0",
                            "informationUri": "https://zaseon.io",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def _finding_to_dict(self, f: FindingSchema) -> dict:
        return {
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value,
            "category": f.category,
            "cwe_id": f.cwe_id,
            "scwe_id": f.scwe_id,
            "location": {
                "file": f.location.file_path,
                "start_line": f.location.start_line,
                "end_line": f.location.end_line,
                "snippet": f.location.snippet,
            },
            "remediation": f.remediation,
            "proof_of_concept": f.poc_script,
            "confidence": f.confidence,
            "status": f.status.value if f.status else "open",
            "verified": f.metadata.get("verification", {}).get("exploit_confirmed", False),
        }

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
            "INFO": "#6b7280",
        }.get(severity.upper(), "#6b7280")

    @staticmethod
    def _severity_badge(severity: str) -> str:
        colors = {
            "CRITICAL": "bg-red-600",
            "HIGH": "bg-orange-500",
            "MEDIUM": "bg-yellow-500",
            "LOW": "bg-blue-500",
            "INFO": "bg-gray-400",
        }
        return colors.get(severity.upper(), "bg-gray-400")

    @staticmethod
    def _score_to_grade(score: float) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        return "F"

    @staticmethod
    def _score_to_color(score: float) -> str:
        if score >= 90:
            return "#16a34a"
        elif score >= 80:
            return "#65a30d"
        elif score >= 70:
            return "#ca8a04"
        elif score >= 60:
            return "#ea580c"
        return "#dc2626"

    @staticmethod
    def _severity_to_sarif_level(severity: Severity) -> str:
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFORMATIONAL: "note",
            Severity.GAS: "note",
        }.get(severity, "note")

    @staticmethod
    def _severity_to_score(severity: Severity) -> float:
        return {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.5,
            Severity.INFORMATIONAL: 1.0,
            Severity.GAS: 0.5,
        }.get(severity, 1.0)
