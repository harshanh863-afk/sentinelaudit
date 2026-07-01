"""PDF report generator using HTML-to-PDF rendering.

In production, this wraps the professional HTML output and feeds it to WeasyPrint
or a similar HTML-to-PDF library. The generator produces printable HTML with
@page rules suitable for PDF rendering.
"""

from __future__ import annotations

from app.services.reporting.models import ProfessionalReport
from app.services.reporting.professional_html import generate_professional_html, _CSS


_PDF_CSS = """
@media print {
  @page {
    size: A4;
    margin: 20mm 15mm;
    @bottom-center { content: counter(page); font-size: 10px; color: #888; }
  }
  .page { page-break-after: always; padding: 20mm 15mm; }
}
""" + _CSS


def generate_pdf_html(report: ProfessionalReport) -> str:
    """Generate HTML formatted for PDF rendering (with @page rules)."""
    body = _build_body(report)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{report.title}</title>
<style>{_PDF_CSS}</style>
</head>
<body>{body}</body>
</html>"""


def _build_body(report: ProfessionalReport) -> str:
    from app.services.reporting.professional_html import (
        _appendix, _compliance_section, _cover_page, _executive_summary,
        _findings_section, _methodology_section, _privacy_section,
        _remediation_section, _risk_score_overview, _toc_page,
    )
    sections = [
        _cover_page(report),
        _toc_page(report),
        _executive_summary(report),
        _methodology_section(report),
        _risk_score_overview(report),
        _findings_section(report),
        _compliance_section(report),
    ]
    if report.privacy_section:
        sections.append(_privacy_section(report))
    sections.append(_appendix(report))
    if report.remediation_summary:
        sections.append(_remediation_section(report))
    return "\n".join(sections)


class PDFExporter:
    """Exports a ProfessionalReport to PDF-ready HTML.

    For true PDF rendering, pipe the output through WeasyPrint:
        weasyprint input.html output.pdf
    """

    @staticmethod
    def export(report: ProfessionalReport) -> str:
        return generate_pdf_html(report)

    @staticmethod
    def content_type() -> str:
        return "text/html"
