import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, Download, ChevronDown, ChevronUp, AlertTriangle,
  CheckCircle, XCircle, ExternalLink, FileText, Award, Globe,
  Lock, Server, Cookie, BarChart3, ArrowRight, Loader2, Info,
} from "lucide-react";
import { usePublicReport, getPublicReportUrl } from "@/api/public";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ProfessionalReport, FindingDetail } from "@/types";

const severityConfig = {
  critical: { color: "#dc3545", bg: "bg-red-500/10", border: "border-red-500/30", label: "Critical" },
  high: { color: "#fd7e14", bg: "bg-orange-500/10", border: "border-orange-500/30", label: "High" },
  medium: { color: "#ffc107", bg: "bg-yellow-500/10", border: "border-yellow-500/30", label: "Medium" },
  low: { color: "#28a745", bg: "bg-green-500/10", border: "border-green-500/30", label: "Low" },
  info: { color: "#17a2b8", bg: "bg-cyan-500/10", border: "border-cyan-500/30", label: "Info" },
} as const;

const SEVERITY_ORDER: (keyof typeof severityConfig)[] = ["critical", "high", "medium", "low", "info"];

function ScoreCircle({ score, label, size = "lg" }: { score: number; label: string; size?: "sm" | "lg" }) {
  const radius = size === "lg" ? 60 : 40;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(score, 100) / 100) * circumference;
  const isLarge = size === "lg";

  const color = score >= 80 ? "#dc3545" : score >= 60 ? "#fd7e14" : score >= 40 ? "#ffc107" : "#28a745";

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative">
        <svg width={isLarge ? 160 : 110} height={isLarge ? 160 : 110} viewBox={`0 0 ${(radius + 20) * 2} ${(radius + 20) * 2}`}>
          <circle
            cx={radius + 20} cy={radius + 20} r={radius}
            fill="none" stroke="hsl(var(--muted))" strokeWidth="6" opacity="0.2"
          />
          <motion.circle
            cx={radius + 20} cy={radius + 20} r={radius}
            fill="none" stroke={color} strokeWidth="6" strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.5, ease: "easeOut" }}
            transform={`rotate(-90 ${radius + 20} ${radius + 20})`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.span
            className={cn("font-bold", isLarge ? "text-4xl" : "text-2xl")}
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.5, duration: 0.5 }}
          >
            {Math.round(score)}
          </motion.span>
          {isLarge && <span className="text-xs text-muted-foreground">/ 100</span>}
        </div>
      </div>
      <span className={cn("font-semibold", isLarge ? "text-lg" : "text-sm")}>{label}</span>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = severityConfig[severity.toLowerCase() as keyof typeof severityConfig] || severityConfig.info;
  return (
    <span
      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider"
      style={{ backgroundColor: cfg.bg, color: cfg.color, borderColor: cfg.color }}
    >
      {cfg.label}
    </span>
  );
}

function FindingCard({ finding }: { finding: FindingDetail }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = severityConfig[finding.severity.toLowerCase() as keyof typeof severityConfig] || severityConfig.info;

  return (
    <motion.div
      layout
      className="glass-card border-l-4 overflow-hidden"
      style={{ borderLeftColor: cfg.color }}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-4 p-5 text-left hover:bg-card/50 transition-colors"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-1">
            <SeverityBadge severity={finding.severity} />
            {finding.cvss_score !== null && (
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-card" style={{ color: cfg.color }}>
                CVSS {finding.cvss_score}
              </span>
            )}
          </div>
          <h4 className="font-semibold text-base truncate">{finding.title}</h4>
        </div>
        <div className="text-muted-foreground shrink-0">
          {expanded ? <ChevronUp className="h-5 w-5" /> : <ChevronDown className="h-5 w-5" />}
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 space-y-4 border-t border-border/30 pt-4">
              {finding.detail && (
                <div>
                  <p className="text-sm text-muted-foreground">{finding.detail}</p>
                </div>
              )}

              <div className="grid md:grid-cols-2 gap-4">
                {finding.business_impact && (
                  <div className="glass-card p-3 border border-cyan-500/20 bg-cyan-500/5">
                    <p className="text-xs font-semibold text-cyan-400 mb-1">Business Impact</p>
                    <p className="text-sm">{finding.business_impact}</p>
                  </div>
                )}
                {finding.risk_explanation && (
                  <div className="glass-card p-3 border border-yellow-500/20 bg-yellow-500/5">
                    <p className="text-xs font-semibold text-yellow-400 mb-1">Risk Explanation</p>
                    <p className="text-sm">{finding.risk_explanation}</p>
                  </div>
                )}
                {finding.affected_component && (
                  <div className="glass-card p-3">
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Affected Component</p>
                    <p className="text-sm font-mono">{finding.affected_component}</p>
                  </div>
                )}
                {finding.evidence_summary && (
                  <div className="glass-card p-3">
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Evidence</p>
                    <p className="text-sm font-mono text-xs">{finding.evidence_summary}</p>
                  </div>
                )}
              </div>

              {/* References */}
              <div className="flex flex-wrap gap-2">
                {finding.cwe?.map((c, i) => (
                  <span key={i} className="px-2 py-1 rounded text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                    {c.cwe_id || c.name || "CWE"}
                  </span>
                ))}
                {finding.capec?.map((c, i) => (
                  <span key={i} className="px-2 py-1 rounded text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    {c.capec_id || c.name || "CAPEC"}
                  </span>
                ))}
                {finding.mitre_attack?.map((m, i) => (
                  <span key={i} className="px-2 py-1 rounded text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
                    {m.technique_id || m.name || "MITRE"}
                  </span>
                ))}
              </div>

              {/* Remediation */}
              {finding.remediation && (
                <div className="glass-card p-4 border border-green-500/20 bg-green-500/5">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-security-low mt-0.5 shrink-0" />
                    <div>
                      <p className="text-sm font-semibold text-security-low mb-1">Remediation</p>
                      <p className="text-sm">{finding.remediation}</p>
                    </div>
                  </div>
                </div>
              )}

              {finding.false_positive_notes && (
                <p className="text-xs text-muted-foreground italic">False positive notes: {finding.false_positive_notes}</p>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function ComplianceCard({ framework, score, passed, failed, total }: { framework: string; score: number; passed: number; failed: number; total: number }) {
  const color = score >= 80 ? "#28a745" : score >= 50 ? "#fd7e14" : "#dc3545";
  return (
    <div className="glass-card p-5">
      <div className="flex items-center justify-between mb-3">
        <h4 className="font-semibold text-sm">{framework.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}</h4>
        <span className="text-lg font-bold" style={{ color }}>{score.toFixed(0)}%</span>
      </div>
      <div className="h-2 rounded-full bg-card overflow-hidden mb-3">
        <motion.div
          className="h-full rounded-full transition-all"
          style={{ backgroundColor: color, width: `${Math.min(score, 100)}%` }}
          initial={{ width: 0 }}
          animate={{ width: `${Math.min(score, 100)}%` }}
          transition={{ duration: 1, delay: 0.3 }}
        />
      </div>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span className="text-security-low">{passed} passed</span>
        <span className="text-destructive">{failed} failed</span>
        <span>{total} total</span>
      </div>
    </div>
  );
}

export default function ReportViewer() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: report, isLoading, error } = usePublicReport(id);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-12 w-12 text-primary animate-spin" />
          <p className="text-muted-foreground">Loading report...</p>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="glass-card p-12 text-center max-w-md">
          <AlertTriangle className="h-16 w-16 text-destructive mx-auto mb-6" />
          <h2 className="text-2xl font-bold mb-2">Report Not Found</h2>
          <p className="text-muted-foreground mb-6">The scan may still be in progress or the report has expired.</p>
          <Button onClick={() => navigate("/")} className="gap-2">
            <ArrowRight className="h-4 w-4" /> Start New Assessment
          </Button>
        </div>
      </div>
    );
  }

  const exec = report.executive_summary;
  const findingGroups: Record<string, FindingDetail[]> = {};
  for (const f of report.findings) {
    const sev = f.severity.toLowerCase();
    if (!findingGroups[sev]) findingGroups[sev] = [];
    findingGroups[sev].push(f);
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border/30 bg-background/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-primary to-purple-600 flex items-center justify-center">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <div>
              <span className="font-bold">SentinelAudit</span>
              <span className="text-xs text-muted-foreground ml-2">Security Assessment Report</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => window.open(getPublicReportUrl(id!, "json"), "_blank")} className="gap-1.5">
              <Download className="h-4 w-4" /> JSON
            </Button>
            <Button variant="outline" size="sm" onClick={() => window.open(getPublicReportUrl(id!, "html"), "_blank")} className="gap-1.5">
              <Download className="h-4 w-4" /> HTML
            </Button>
            <Button variant="outline" size="sm" onClick={() => window.open(getPublicReportUrl(id!, "pdf"), "_blank")} className="gap-1.5">
              <Download className="h-4 w-4" /> PDF
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-12 space-y-12">
        {/* Report Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="glass-card p-8 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-primary/5 to-purple-500/5 rounded-full blur-3xl" />
            <div className="relative">
              <div className="flex items-center gap-3 mb-4">
                <Shield className="h-6 w-6 text-primary" />
                <h1 className="text-2xl font-bold">SentinelAudit Security Assessment</h1>
              </div>
              <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mt-6">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Target</p>
                  <p className="font-mono text-sm">{report.target_url}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Date</p>
                  <p className="text-sm">{new Date(report.scan_date).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Security Grade</p>
                  <p className="text-2xl font-bold" style={{ color: exec.risk_rating === "Critical" ? "#dc3545" : exec.risk_rating === "High" ? "#fd7e14" : exec.risk_rating === "Medium" ? "#ffc107" : exec.risk_rating === "Low" ? "#28a745" : "#17a2b8" }}>
                    {exec.risk_rating}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Risk Level</p>
                  <p className="text-sm font-semibold">{exec.security_score.toFixed(1)} / 100</p>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Executive Score Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="flex items-center gap-3 mb-8">
            <BarChart3 className="h-6 w-6 text-primary" />
            <h2 className="text-2xl font-bold">Executive Summary</h2>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-5 gap-6">
            <div className="lg:col-span-1 glass-card p-6 flex items-center justify-center">
              <ScoreCircle score={exec.security_score} label="Security Score" />
            </div>

            <div className="lg:col-span-4 grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: "Critical Issues", value: exec.critical_count, color: "#dc3545" },
                { label: "High Issues", value: exec.high_count, color: "#fd7e14" },
                { label: "Medium Issues", value: exec.medium_count, color: "#ffc107" },
                { label: "Low Issues", value: exec.low_count + exec.info_count, color: "#28a745" },
              ].map((item, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 + i * 0.05 }}
                  className="glass-card p-4 text-center"
                >
                  <motion.span
                    className="text-3xl font-bold block"
                    style={{ color: item.color }}
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ delay: 0.3 + i * 0.05, type: "spring" }}
                  >
                    {item.value}
                  </motion.span>
                  <span className="text-xs text-muted-foreground">{item.label}</span>
                </motion.div>
              ))}
            </div>
          </div>

          {(exec.compliance_score > 0 || exec.privacy_score > 0) && (
            <div className="grid md:grid-cols-2 gap-6 mt-6">
              {exec.compliance_score > 0 && (
                <div className="glass-card p-6">
                  <p className="text-sm text-muted-foreground mb-1">Compliance Score</p>
                  <div className="flex items-center gap-4">
                    <ScoreCircle score={exec.compliance_score} label="" size="sm" />
                    <div className="flex-1">
                      <div className="h-2 rounded-full bg-card overflow-hidden">
                        <motion.div
                          className="h-full rounded-full bg-gradient-to-r from-orange-500 to-green-500"
                          initial={{ width: 0 }}
                          animate={{ width: `${exec.compliance_score}%` }}
                          transition={{ duration: 1, delay: 0.5 }}
                        />
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">{exec.frameworks_assessed.length} frameworks assessed</p>
                    </div>
                  </div>
                </div>
              )}
              {exec.privacy_score > 0 && (
                <div className="glass-card p-6">
                  <p className="text-sm text-muted-foreground mb-1">Privacy Score</p>
                  <div className="flex items-center gap-4">
                    <ScoreCircle score={exec.privacy_score} label="" size="sm" />
                    <div className="flex-1">
                      <div className="h-2 rounded-full bg-card overflow-hidden">
                        <motion.div
                          className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
                          initial={{ width: 0 }}
                          animate={{ width: `${exec.privacy_score}%` }}
                          transition={{ duration: 1, delay: 0.6 }}
                        />
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">{exec.regulations_checked.length} regulations checked</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </motion.div>

        {/* Security Findings */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="flex items-center gap-3 mb-8">
            <AlertTriangle className="h-6 w-6 text-primary" />
            <h2 className="text-2xl font-bold">Security Findings</h2>
            <span className="text-sm text-muted-foreground">({report.findings.length} total)</span>
          </div>

          {report.findings.length === 0 ? (
            <div className="glass-card p-12 text-center">
              <CheckCircle className="h-16 w-16 text-security-low mx-auto mb-4" />
              <h3 className="text-xl font-semibold mb-2">No Findings</h3>
              <p className="text-muted-foreground">No security issues were identified. The target has a strong security posture.</p>
            </div>
          ) : (
            <div className="space-y-8">
              {SEVERITY_ORDER.map((sev) => {
                const items = findingGroups[sev];
                if (!items?.length) return null;
                return (
                  <div key={sev}>
                    <h3 className="text-lg font-bold mb-4 flex items-center gap-2" style={{ color: severityConfig[sev].color }}>
                      <span className="h-3 w-3 rounded-full inline-block" style={{ backgroundColor: severityConfig[sev].color }} />
                      {severityConfig[sev].label} ({items.length})
                    </h3>
                    <div className="space-y-3">
                      {items.map((f) => (
                        <FindingCard key={f.finding_id} finding={f} />
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </motion.div>

        {/* Compliance Section */}
        {report.compliance_sections.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <div className="flex items-center gap-3 mb-8">
              <Award className="h-6 w-6 text-primary" />
              <h2 className="text-2xl font-bold">Compliance Summary</h2>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
              {report.compliance_sections.map((cs) => (
                <ComplianceCard key={cs.framework} {...cs} />
              ))}
            </div>
          </motion.div>
        )}

        {/* Privacy Section */}
        {report.privacy_section && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35 }}
          >
            <div className="flex items-center gap-3 mb-8">
              <Shield className="h-6 w-6 text-primary" />
              <h2 className="text-2xl font-bold">Privacy Assessment</h2>
            </div>
            <div className="grid md:grid-cols-4 gap-4 mb-6">
              {[
                { label: "GDPR", score: report.privacy_section.gdpr_score },
                { label: "CCPA/CPRA", score: report.privacy_section.ccpa_score },
                { label: "COPPA", score: report.privacy_section.coppa_score },
                { label: "Cookie", score: report.privacy_section.cookie_score },
              ].map((item) => (
                <div key={item.label} className="glass-card p-4 text-center">
                  <ScoreCircle score={item.score} label={item.label} size="sm" />
                </div>
              ))}
            </div>
            {report.privacy_section.recommendations.length > 0 && (
              <div className="glass-card p-6">
                <h3 className="font-semibold mb-4">Recommendations ({report.privacy_section.detected_issues} issues detected)</h3>
                <ul className="space-y-2">
                  {report.privacy_section.recommendations.map((r, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                      <Info className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </motion.div>
        )}

        {/* Appendix */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <div className="flex items-center gap-3 mb-8">
            <FileText className="h-6 w-6 text-primary" />
            <h2 className="text-2xl font-bold">Technical Appendix</h2>
          </div>
          <div className="glass-card p-6 space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-muted-foreground mb-1">Scanner Version</p>
                <p className="font-mono text-sm">{report.appendix.scanner_version || "1.0.0"}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1">Methodology</p>
                <p className="text-sm">{report.appendix.methodology || "Automated security assessment using SentinelAudit."}</p>
              </div>
            </div>
            {report.appendix.assessment_limitations.length > 0 && (
              <div>
                <p className="text-xs text-muted-foreground mb-2">Assessment Limitations</p>
                <ul className="space-y-1">
                  {report.appendix.assessment_limitations.map((l, i) => (
                    <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                      <Info className="h-4 w-4 text-muted-foreground mt-0.5 shrink-0" />
                      {l}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </motion.div>

        {/* Footer */}
        <div className="text-center py-8 text-sm text-muted-foreground border-t border-border/30">
          <p>Generated by SentinelAudit — {new Date(report.generated_at).toLocaleString()}</p>
          <p className="mt-1">Passive security assessment. No exploitation performed.</p>
        </div>
      </main>
    </div>
  );
}
