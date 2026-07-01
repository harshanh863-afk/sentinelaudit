export interface PublicScanResponse {
  scan_id: string;
  status: string;
  created_at: string;
}

export interface PublicScanStatus {
  scan_id: string;
  status: string;
  progress: number;
  current_stage: string;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  risk_score: number | null;
  target_url: string;
}

export interface ProfessionalReport {
  title: string;
  client_name: string;
  target_url: string;
  scan_date: string;
  generated_at: string;
  executive_summary: ExecutiveSummary;
  findings: FindingDetail[];
  compliance_sections: ComplianceSection[];
  privacy_section: PrivacySection | null;
  appendix: TechnicalAppendix;
  remediation_summary: string;
}

export interface ExecutiveSummary {
  security_score: number;
  risk_rating: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  compliance_score: number;
  frameworks_assessed: string[];
  privacy_score: number;
  regulations_checked: string[];
}

export interface FindingDetail {
  finding_id: string;
  title: string;
  severity: string;
  status: string;
  detail: string | null;
  cvss_score: number | null;
  evidence_summary: string | null;
  evidence_hash: string | null;
  remediation: string | null;
  compliance: Record<string, unknown>[];
  impact: string;
  business_impact: string;
  risk_explanation: string;
  affected_component: string;
  false_positive_notes: string;
  cwe: Record<string, string>[];
  capec: Record<string, string>[];
  mitre_attack: Record<string, string>[];
}

export interface ComplianceSection {
  framework: string;
  score: number;
  status: string;
  passed: number;
  failed: number;
  partial: number;
  not_applicable: number;
  total: number;
}

export interface PrivacySection {
  privacy_score: number;
  gdpr_score: number;
  ccpa_score: number;
  coppa_score: number;
  cookie_score: number;
  detected_issues: number;
  recommendations: string[];
}

export interface TechnicalAppendix {
  scanner_version: string;
  scan_duration_seconds: number;
  methodology: string;
  target_info: Record<string, string>;
  assessment_limitations: string[];
  scanner_modules: string[];
  evidence_collected: string[];
}
