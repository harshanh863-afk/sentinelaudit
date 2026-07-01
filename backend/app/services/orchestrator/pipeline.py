"""Pipeline stage definitions for scan orchestration."""

from dataclasses import dataclass
from enum import Enum


class PipelineStage(str, Enum):
    QUEUED = "queued"
    HTTP_ANALYSIS = "http_analysis"
    TLS_ANALYSIS = "tls_analysis"
    DNS_ANALYSIS = "dns_analysis"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    RULE_PROCESSING = "rule_processing"
    RISK_SCORING = "risk_scoring"
    COMPLIANCE_ASSESSMENT = "compliance_assessment"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class StageDefinition:
    stage: PipelineStage
    label: str
    start_progress: int
    end_progress: int


PIPELINE: list[StageDefinition] = [
    StageDefinition(PipelineStage.QUEUED, "Queued", 0, 5),
    StageDefinition(PipelineStage.HTTP_ANALYSIS, "HTTP Security Analysis", 5, 25),
    StageDefinition(PipelineStage.TLS_ANALYSIS, "TLS/SSL Analysis", 25, 40),
    StageDefinition(PipelineStage.DNS_ANALYSIS, "DNS Analysis", 40, 55),
    StageDefinition(PipelineStage.TECHNOLOGY_FINGERPRINT, "Technology Fingerprinting", 55, 70),
    StageDefinition(PipelineStage.JAVASCRIPT_ANALYSIS, "JavaScript Analysis", 70, 80),
    StageDefinition(PipelineStage.RULE_PROCESSING, "Rule Processing", 80, 88),
    StageDefinition(PipelineStage.RISK_SCORING, "Risk Scoring", 88, 93),
    StageDefinition(PipelineStage.COMPLIANCE_ASSESSMENT, "Compliance Assessment", 93, 97),
    StageDefinition(PipelineStage.REPORT_GENERATION, "Report Generation", 97, 100),
]


def get_stage(stage: PipelineStage) -> StageDefinition | None:
    for s in PIPELINE:
        if s.stage == stage:
            return s
    return None
