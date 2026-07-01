"""PDF report exporter (placeholder — rendering will be implemented separately)."""


class PDFExporter:
    """Exports a report to PDF format (placeholder)."""

    @staticmethod
    def export(report_data) -> bytes:
        raise NotImplementedError("PDF rendering not yet implemented")

    @staticmethod
    def content_type() -> str:
        return "application/pdf"
