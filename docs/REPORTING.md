# Reporting Architecture

## Overview

SentinelAudit's reporting subsystem transforms scan results into professional security assessment reports. It follows a pipeline architecture:

```
Scan Results → ReportEngine.build() → ReportData → Exporter.export() → File
                    ↓
           FindingFormatter.format()
```

## Report Structure

Each report contains the following sections:

| Section | Description |
|---------|-------------|
| Executive Summary | High-level overview of findings and risk score |
| Methodology | Assessment approach, tools used, severity classification |
| Findings | Detailed list of each finding with evidence and compliance mapping |
| Remediation | Prioritised remediation recommendations |
| Compliance Mapping | Cross-reference of findings to industry frameworks |

## Report Data Model

```
ReportData
├── title: str
├── target_url: str
├── scan_date: str
├── risk_score: float
├── findings: list[FormattedFinding]
│   ├── finding_id
│   ├── title
│   ├── severity
│   ├── status
│   ├── cvss_score
│   ├── evidence_summary
│   └── compliance: list[dict]
├── compliance_summary: dict
├── methodology: str
├── executive_summary: str
├── remediation_summary: str
└── generated_at: str
```

## Evidence Handling

The expanded `Evidence` model supports:

| Field | Type | Description |
|-------|------|-------------|
| `request_data` | Text | Raw HTTP request sent |
| `response_data` | Text | Raw HTTP response received |
| `request_headers` | JSON | Parsed request headers |
| `response_headers` | JSON | Parsed response headers |
| `response_body` | Text | Response body snippet |
| `captured_at` | DateTime | Timestamp of evidence capture |
| `screenshot_path` | String | Path to screenshot file (placeholder) |
| `metadata` | JSON | Arbitrary additional metadata |

Evidence is always linked to a Scan and optionally to a specific Finding.

## Finding Lifecycle

```
NEW ──> CONFIRMED ──> FIXED ──> RETEST_REQUIRED ──> FIXED
  │                      │
  └──> FALSE_POSITIVE    └──> ACCEPTED_RISK
```

| Status | Description |
|--------|-------------|
| NEW | Recently discovered, awaiting triage |
| CONFIRMED | Verified as a legitimate security issue |
| FALSE_POSITIVE | Determined not to be a real vulnerability |
| ACCEPTED_RISK | Known risk accepted by the organisation |
| FIXED | Remediation has been applied |
| RETEST_REQUIRED | Fix needs verification |

## Severity Calculation

Severity is calculated using a combination of:

1. **CVSS Score** — Common Vulnerability Scoring System (v3.1)
   - Attack Vector (Network, Adjacent, Local, Physical)
   - Attack Complexity (Low, High)
   - Privileges Required (None, Low, High)
   - User Interaction (None, Required)

2. **Rule Severity** — Base severity from the matched rule definition

3. **Contextual Adjustments** — Environment-specific factors

The final severity level is one of: Critical, High, Medium, Low, Info.

## Export Formats

| Format | Exporter | Status | Content Type |
|--------|----------|--------|-------------|
| JSON | `JSONExporter` | Implemented | `application/json` |
| Markdown | `MarkdownExporter` | Implemented | `text/markdown` |
| HTML | `HTMLExporter` | Placeholder | `text/html` |
| PDF | `PDFExporter` | Placeholder | `application/pdf` |

## Extending Exporters

To add a new export format:

1. Create a new exporter class in `backend/app/services/reporting/exporters/`
2. Implement the `export(report_data) -> str | bytes` method
3. Implement the `content_type() -> str` static method
4. Register the exporter in `exporters/__init__.py`

## Templates

Report templates are stored in `reports/templates/` as Markdown files with Jinja2-style placeholder syntax. Templates are used for generating the human-readable sections of the report.

Available templates:
- `executive_summary.md`
- `methodology.md`
- `findings.md`
- `remediation.md`
- `compliance_mapping.md`
