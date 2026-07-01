"""Markdown report exporter."""


class MarkdownExporter:
    """Exports a report to Markdown format."""

    @staticmethod
    def export(report_data) -> str:
        lines: list[str] = []
        lines.append(f"# {report_data.title}")
        lines.append("")
        lines.append(f"**Target:** {report_data.target_url}")
        lines.append(f"**Scan Date:** {report_data.scan_date}")
        lines.append(f"**Risk Score:** {report_data.risk_score}")
        lines.append(f"**Generated:** {report_data.generated_at}")
        lines.append("")

        if report_data.executive_summary:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(report_data.executive_summary)
            lines.append("")

        if report_data.methodology:
            lines.append("## Methodology")
            lines.append("")
            lines.append(report_data.methodology)
            lines.append("")

        if report_data.findings:
            lines.append("## Findings")
            lines.append("")
            for i, f in enumerate(report_data.findings, 1):
                title = getattr(f, "title", None) or getattr(f, "detail", "") or f"Finding {i}"
                severity = getattr(f, "severity", "unknown")
                status = getattr(f, "status", "unknown")
                lines.append(f"### {i}. {title}")
                lines.append("")
                lines.append(f"- **Severity:** {severity}")
                lines.append(f"- **Status:** {status}")
                if getattr(f, "cvss_score", None):
                    lines.append(f"- **CVSS:** {f.cvss_score}")
                if getattr(f, "detail", None):
                    lines.append(f"- **Detail:** {f.detail}")
                if getattr(f, "compliance", None):
                    for cm in f.compliance:
                        lines.append(f'  - {cm["framework"]}: {cm["control_id"]} — {cm["control_name"]}')
                lines.append("")

        if report_data.compliance_summary:
            lines.append("## Compliance Mapping")
            lines.append("")
            for framework, controls in report_data.compliance_summary.items():
                lines.append(f"- **{framework}:** {', '.join(controls)}")
            lines.append("")

        if report_data.remediation_summary:
            lines.append("## Remediation")
            lines.append("")
            lines.append(report_data.remediation_summary)
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def content_type() -> str:
        return "text/markdown"
