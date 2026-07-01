"""Professional JSON report exporter with enhanced structure."""

import json
from dataclasses import asdict

from app.services.reporting.models import ProfessionalReport


class JSONExporter:
    """Exports a ProfessionalReport to JSON format."""

    @staticmethod
    def export(report_data) -> str:
        if isinstance(report_data, ProfessionalReport):
            data = asdict(report_data)
            # Convert UUIDs to strings
            for f in data.get("findings", []):
                f["finding_id"] = str(f["finding_id"])
            return json.dumps(data, indent=2, default=str)

        # Legacy support for ReportData
        data = asdict(report_data)
        return json.dumps(data, indent=2, default=str)

    @staticmethod
    def content_type() -> str:
        return "application/json"
