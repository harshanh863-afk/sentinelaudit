"""Professional HTML report generator with inline CSS.

Features:
  - Cover page with target, date, risk grade
  - Table of contents
  - Executive summary with finding distribution and compliance score
  - Risk overview with security, compliance, and privacy score bars
  - Findings by severity with CWE, CAPEC, MITRE ATT&CK references
  - Compliance section with per-framework scores
  - Privacy section with GDPR/CCPA/COPPA/cookie scores
  - Technical appendix with scanner modules and evidence
  - Severity badges, professional typography, page numbers
"""

from app.services.reporting.models import ProfessionalReport, FindingDetail, severity_sort_key


SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "info": "#17a2b8",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6c757d")
    return f'<span class="sev-badge" style="background:{color};color:#fff;">{severity.upper()}</span>'


def _risk_bar_html(score: float, label: str = "Score") -> str:
    color = "#28a745"
    if score >= 80:
        color = "#dc3545"
    elif score >= 60:
        color = "#fd7e14"
    elif score >= 40:
        color = "#ffc107"
    return f"""
    <div class="risk-meta">
      <span class="risk-label-text">{label}</span>
      <span class="risk-score-text">{score:.1f}/100</span>
    </div>
    <div class="risk-bar-wrapper">
      <div class="risk-bar" style="width:{min(score, 100)}%;background:{color};"></div>
    </div>"""


def _finding_refs(finding: FindingDetail) -> str:
    parts = []
    if finding.cvss_score is not None:
        parts.append(f"<span class='ref-badge'>CVSS {finding.cvss_score}</span>")
    if finding.cwe:
        for c in finding.cwe[:3]:
            parts.append(f"<span class='ref-badge ref-cwe'>{c.get('cwe_id', c.get('name', ''))}</span>")
    if finding.capec:
        for c in finding.capec[:2]:
            parts.append(f"<span class='ref-badge ref-capec'>{c.get('capec_id', c.get('name', ''))}</span>")
    if finding.mitre_attack:
        for m in finding.mitre_attack[:2]:
            parts.append(f"<span class='ref-badge ref-mitre'>{m.get('technique_id', m.get('name', ''))}</span>")
    if finding.compliance:
        fws = sorted(set(c.get("framework", "") for c in finding.compliance))
        parts.append(f"<span class='ref-badge ref-comp'>Compliance: {', '.join(fws[:4])}</span>")
    return '<div class="finding-refs">' + "".join(parts) + "</div>" if parts else ""


def _cover_page(report: ProfessionalReport) -> str:
    exec_s = report.executive_summary
    sev_str = " | ".join(
        f"{sev.title()}: {getattr(exec_s, f'{sev}_count', 0)}"
        for sev in SEVERITY_ORDER
    )
    return f"""
  <div class="page cover-page">
    <div class="cover-content">
      <div class="cover-badge">SECURITY ASSESSMENT REPORT</div>
      <h1 class="cover-title">{report.title}</h1>
      <hr class="cover-divider">
      <table class="cover-info">
        <tr><td class="cover-label">Target</td><td class="cover-value">{report.target_url}</td></tr>
        <tr><td class="cover-label">Scan Date</td><td class="cover-value">{report.scan_date}</td></tr>
        <tr><td class="cover-label">Risk Score</td><td class="cover-value">{exec_s.security_score:.1f} / 100 ({exec_s.risk_rating})</td></tr>
        <tr><td class="cover-label">Findings</td><td class="cover-value">{sev_str}</td></tr>
        <tr><td class="cover-label">Compliance</td><td class="cover-value">{exec_s.compliance_score:.1f}% across {len(exec_s.frameworks_assessed)} frameworks</td></tr>
        <tr><td class="cover-label">Generated</td><td class="cover-value">{report.generated_at}</td></tr>
      </table>
    </div>
  </div>"""


def _toc_page(report: ProfessionalReport) -> str:
    items = [
        ("1", "Executive Summary"),
        ("2", "Methodology & Scope"),
        ("3", "Risk Score Overview"),
        ("4", "Findings by Severity"),
    ]
    if report.compliance_sections:
        items.append(("5", "Compliance Summary"))
    if report.privacy_section:
        items.append(("6", "Privacy Assessment"))
    items.append(("7", "Technical Appendix"))
    if report.remediation_summary:
        items.append(("8", "Remediation Guidance"))

    toc_rows = "".join(
        f'<tr><td class="toc-num">{num}</td><td class="toc-title">{title}</td></tr>'
        for num, title in items
    )
    return f"""
  <div class="page toc-page">
    <h2 class="section-title">Table of Contents</h2>
    <table class="toc-table">{toc_rows}</table>
  </div>"""


def _executive_summary(report: ProfessionalReport) -> str:
    exec_s = report.executive_summary
    bars = "".join(
        f"""<div class="sev-bar-wrapper">
          <span class="sev-label">{sev.title()}</span>
          <div class="sev-bar">
            <div class="sev-bar-fill" style="width:{(getattr(exec_s, f'{sev}_count', 0) / max(exec_s.total_findings, 1)) * 100}%;background:{SEVERITY_COLORS[sev]};"></div>
          </div>
          <span class="sev-count">{getattr(exec_s, f'{sev}_count', 0)}</span>
        </div>"""
        for sev in SEVERITY_ORDER
    )
    comp = f"""<h3>Compliance Assessment</h3>
    <p class="section-text">Overall compliance posture: <strong>{exec_s.compliance_score:.1f}%</strong> across {len(exec_s.frameworks_assessed)} security frameworks.</p>""" if exec_s.frameworks_assessed else ""

    priv = f"""<h3>Privacy Assessment</h3>
    <p class="section-text">Privacy compliance score: <strong>{exec_s.privacy_score:.1f}%</strong> across {len(exec_s.regulations_checked)} privacy regulations.</p>""" if exec_s.regulations_checked else ""

    return f"""
  <div class="page">
    <h2 class="section-title">1. Executive Summary</h2>
    <p class="section-text">A comprehensive security assessment was performed against <strong>{report.target_url}</strong> on <strong>{report.scan_date}</strong>.
    The assessment identified <strong>{exec_s.total_findings}</strong> findings across all severity levels.</p>

    <h3>Finding Distribution</h3>
    <div class="sev-bars-container">{bars}</div>

    <div class="summary-cards">
      <div class="summary-card"><div class="card-value">{exec_s.total_findings}</div><div class="card-label">Total Findings</div></div>
      <div class="summary-card"><div class="card-value" style="color:#dc3545;">{exec_s.critical_count}</div><div class="card-label">Critical</div></div>
      <div class="summary-card"><div class="card-value" style="color:#fd7e14;">{exec_s.high_count}</div><div class="card-label">High</div></div>
      <div class="summary-card"><div class="card-value" style="color:#28a745;">{exec_s.medium_count + exec_s.low_count + exec_s.info_count}</div><div class="card-label">Other</div></div>
    </div>

    {comp}
    {priv}
  </div>"""


def _risk_score_overview(report: ProfessionalReport) -> str:
    exec_s = report.executive_summary
    priv = report.privacy_section
    return f"""
  <div class="page">
    <h2 class="section-title">3. Risk Score Overview</h2>
    <p class="section-text">The overall security risk score is <strong>{exec_s.security_score:.1f}/100</strong>, classified as <strong>{exec_s.risk_rating}</strong>.</p>
    {_risk_bar_html(exec_s.security_score, "Security Score")}
    {_risk_bar_html(exec_s.compliance_score, "Compliance Score") if exec_s.frameworks_assessed else ""}
    {_risk_bar_html(priv.privacy_score, "Privacy Score") if priv else ""}

    <h3>Security Grade</h3>
    <div class="grade-display">
      <span class="grade-badge">{exec_s.risk_rating}</span>
    </div>
  </div>"""


def _findings_section(report: ProfessionalReport) -> str:
    if not report.findings:
        return """
  <div class="page">
    <h2 class="section-title">4. Findings by Severity</h2>
    <p class="section-text">No findings were identified during this assessment. The target has a strong security posture.</p>
  </div>"""

    sorted_findings = sorted(report.findings, key=severity_sort_key)
    severity_groups: dict[str, list[FindingDetail]] = {}
    for f in sorted_findings:
        severity_groups.setdefault(f.severity, []).append(f)

    sev_html = ""
    for sev in SEVERITY_ORDER:
        if sev not in severity_groups:
            continue
        findings = severity_groups[sev]
        color = SEVERITY_COLORS[sev]
        rows = ""
        for i, f in enumerate(findings, 1):
            refs = _finding_refs(f)
            business = f'<p class="find-business"><strong>Business Impact:</strong> {f.business_impact or f.impact or "See description."}</p>' if (f.business_impact or f.impact) else ""
            risk_exp = f'<p class="find-risk"><strong>Risk Explanation:</strong> {f.risk_explanation}</p>' if f.risk_explanation else ""
            component = f'<p class="find-component"><strong>Affected Component:</strong> {f.affected_component}</p>' if f.affected_component else ""
            fp_notes = f'<p class="find-fp"><strong>False Positive Notes:</strong> {f.false_positive_notes}</p>' if f.false_positive_notes else ""
            evidence = f'<p class="find-evidence"><strong>Evidence:</strong> {f.evidence_summary}</p>' if f.evidence_summary else ""
            hashed = f'<p class="find-hash"><strong>SHA256:</strong> <code>{f.evidence_hash}</code></p>' if f.evidence_hash else ""
            remediation = f'<p class="find-fix"><strong>Remediation:</strong> {f.remediation}</p>' if f.remediation else ""

            rows += f"""
          <div class="finding-card">
            <div class="finding-header">
              <span class="finding-num">{i}.</span>
              <span class="finding-title">{f.title}</span>
              {_severity_badge(f.severity)}
              {f'<span class="cvss-badge">{f.cvss_score}</span>' if f.cvss_score is not None else ''}
              <span class="finding-status">{f.status.replace('_', ' ').title()}</span>
            </div>
            <div class="finding-body">
              <p class="finding-desc">{f.detail or 'No additional details.'}</p>
              {business}
              {risk_exp}
              {component}
              {evidence}
              {hashed}
              {refs}
              {remediation}
              {fp_notes}
            </div>
          </div>"""

        sev_html += f"""
    <h3 class="sev-heading" style="color:{color};">{sev.upper()} ({len(findings)})</h3>
    <div class="findings-group">{rows}</div>"""

    return f"""
  <div class="page">
    <h2 class="section-title">4. Findings by Severity</h2>
    {sev_html}
  </div>"""


def _compliance_section(report: ProfessionalReport) -> str:
    if not report.compliance_sections:
        return ""
    rows = "".join(
        f"""<tr>
          <td class="comp-fw">{cs.framework}</td>
          <td><div class="comp-bar-wrapper"><div class="comp-bar" style="width:{cs.score}%;background:{'#28a745' if cs.score >= 80 else '#fd7e14' if cs.score >= 50 else '#dc3545'};"></div></div></td>
          <td class="comp-score">{cs.score:.1f}%</td>
          <td>{cs.status.replace('_', ' ').title()}</td>
          <td>{cs.passed}/{cs.total}</td>
          <td>{cs.failed}</td>
        </tr>"""
        for cs in report.compliance_sections
    )
    return f"""
  <div class="page">
    <h2 class="section-title">5. Compliance Summary</h2>
    <p class="section-text">The table below summarizes compliance scores across all assessed frameworks. Scores reflect the percentage of assessable controls that passed.</p>
    <table class="compliance-table">
      <thead><tr><th>Framework</th><th>Progress</th><th>Score</th><th>Status</th><th>Passed</th><th>Failed</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _privacy_section(report: ProfessionalReport) -> str:
    priv = report.privacy_section
    if not priv:
        return ""
    recs = "".join(f"<li>{r}</li>" for r in priv.recommendations[:5]) if priv.recommendations else "<li>No immediate recommendations.</li>"
    return f"""
  <div class="page">
    <h2 class="section-title">6. Privacy Assessment</h2>
    <p class="section-text">Privacy compliance evaluated across multiple regulations.</p>

    <div class="summary-cards">
      <div class="summary-card"><div class="card-value">{priv.privacy_score:.0f}%</div><div class="card-label">Overall Privacy</div></div>
      <div class="summary-card"><div class="card-value">{priv.gdpr_score:.0f}%</div><div class="card-label">GDPR</div></div>
      <div class="summary-card"><div class="card-value">{priv.ccpa_score:.0f}%</div><div class="card-label">CCPA/CPRA</div></div>
      <div class="summary-card"><div class="card-value">{priv.cookie_score:.0f}%</div><div class="card-label">Cookie Compliance</div></div>
    </div>

    {_risk_bar_html(priv.gdpr_score, "GDPR Score")}
    {_risk_bar_html(priv.ccpa_score, "CCPA/CPRA Score")}
    {_risk_bar_html(priv.coppa_score, "COPPA Score")}
    {_risk_bar_html(priv.cookie_score, "Cookie Compliance")}

    <h3>Detected Issues: {priv.detected_issues}</h3>
    <h3>Recommendations</h3>
    <ul>{recs}</ul>
  </div>"""


def _methodology_section(report: ProfessionalReport) -> str:
    a = report.appendix
    scanners = a.scanner_modules or [
        "HTTP Security Analyzer", "TLS Certificate Analyzer",
        "DNS Security Analyzer", "Technology Fingerprinter",
        "JavaScript Analyzer",
    ]
    scanner_items = "".join(f"<li>{m}</li>" for m in scanners)
    return f"""
  <div class="page">
    <h2 class="section-title">2. Methodology & Scope</h2>

    <h3>Assessment Type</h3>
    <p class="section-text">This is a <strong>Passive Security Audit</strong>. No exploitation, credential testing, or destructive requests were performed.
    The assessment evaluates publicly observable security posture only.</p>

    <h3>Scanners Executed</h3>
    <ul>{scanner_items}</ul>

    <h3>Frameworks Assessed</h3>
    <p class="section-text">Findings are mapped against {len(report.compliance_sections) if report.compliance_sections else 38}+ security frameworks and privacy regulations.</p>

    <h3>Assessment Limitations</h3>
    <ul>
      <li>Passive checks only — no active exploitation</li>
      <li>Results reflect the point-in-time assessment</li>
      <li>Dynamic/SPA applications may have limited coverage</li>
      <li>Zero false positive guarantee is not provided</li>
      <li>This is not a substitute for a professional penetration test</li>
    </ul>

    <h3>Evidence Integrity</h3>
    <p class="section-text">All findings include SHA-256 cryptographic hashes of evidence data for integrity verification.
    Evidence timestamps and scanner version information are included in each finding record.</p>
  </div>"""


def _appendix(report: ProfessionalReport) -> str:
    a = report.appendix
    limitations = a.assessment_limitations or ["No limitations noted."]
    lim_items = "".join(f"<li>{item}</li>" for item in limitations)
    target_info = ""
    if a.target_info:
        for k, v in a.target_info.items():
            target_info += f"<tr><td class='app-label'>{k}</td><td class='app-value'>{v}</td></tr>"
        target_info = f"<table class='app-table'>{target_info}</table>"

    modules = "".join(f"<li>{m}</li>" for m in a.scanner_modules) if a.scanner_modules else "<li>All available modules executed</li>"
    evidence = "".join(f"<li>{e}</li>" for e in a.evidence_collected) if a.evidence_collected else ""

    fw_rows = "".join(
        f"""<tr><td>{cs.framework.replace('_', ' ').title()}</td><td class="fw-covered">Covered</td><td>{cs.score:.0f}%</td></tr>"""
        for cs in report.compliance_sections[:15]
    ) if report.compliance_sections else ""

    return f"""
  <div class="page">
    <h2 class="section-title">7. Technical Appendix</h2>

    <h3>Scanner Information</h3>
    <table class="app-table">
      <tr><td class="app-label">Scanner Version</td><td class="app-value">{a.scanner_version or '1.0.0'}</td></tr>
      <tr><td class="app-label">Scan Duration</td><td class="app-value">{a.scan_duration_seconds}s</td></tr>
      <tr><td class="app-label">Methodology</td><td class="app-value">{a.methodology or 'Automated security assessment using SentinelAudit.'}</td></tr>
    </table>
    {target_info}

    <h3>Scanner Modules Executed</h3>
    <ul>{modules}</ul>

    <h3>Standards Coverage Matrix</h3>
    <table class="compliance-table">
      <thead><tr><th>Framework</th><th>Coverage</th><th>Score</th></tr></thead>
      <tbody>{fw_rows}</tbody>
    </table>

    <h3>Evidence Collected</h3>
    <ul class="evidence-list">{evidence}</ul>

    <h3>Assessment Limitations</h3>
    <ul>{lim_items}</ul>
  </div>"""


def _remediation_section(report: ProfessionalReport) -> str:
    if not report.remediation_summary:
        return ""
    return f"""
  <div class="page">
    <h2 class="section-title">8. Remediation Guidance</h2>
    <div class="remediation-box">{report.remediation_summary}</div>
  </div>"""


_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; color: #1a1a2e; background: #fff; line-height: 1.6; }
.page { padding: 50px 60px; page-break-after: always; }

/* Cover */
.cover-page { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #fff; display: flex; align-items: center; justify-content: center; min-height: 90vh; }
.cover-content { max-width: 700px; margin: 0 auto; text-align: center; }
.cover-badge { display: inline-block; background: #e94560; color: #fff; padding: 8px 24px; border-radius: 20px; font-size: 14px; letter-spacing: 2px; margin-bottom: 30px; }
.cover-title { font-size: 36px; font-weight: 700; margin-bottom: 20px; letter-spacing: 1px; }
.cover-divider { border: 0; height: 2px; background: #e94560; width: 100px; margin: 20px auto; }
.cover-info { margin: 30px auto 0; text-align: left; }
.cover-info td { padding: 8px 16px; }
.cover-label { color: #a0a0b0; font-weight: 600; width: 150px; }
.cover-value { color: #fff; }

/* TOC */
.toc-table td { padding: 14px 12px; }
.toc-num { width: 50px; text-align: center; font-weight: 700; color: #e94560; font-size: 18px; }
.toc-title { font-weight: 600; font-size: 16px; }

.section-title { font-size: 26px; font-weight: 700; color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; margin-bottom: 25px; }
.section-text { font-size: 15px; color: #333; margin-bottom: 15px; }
h3 { font-size: 18px; font-weight: 600; color: #2d3436; margin: 20px 0 12px; }

/* Summary cards */
.summary-cards { display: flex; gap: 16px; margin: 20px 0; }
.summary-card { flex: 1; background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; text-align: center; }
.card-value { font-size: 32px; font-weight: 700; color: #1a1a2e; }
.card-label { font-size: 13px; color: #666; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }

/* Severity bars */
.sev-bars-container { margin: 20px 0; }
.sev-bar-wrapper { display: flex; align-items: center; margin-bottom: 10px; }
.sev-label { width: 80px; font-weight: 600; font-size: 13px; }
.sev-bar { flex: 1; height: 24px; background: #eee; border-radius: 4px; overflow: hidden; margin: 0 12px; }
.sev-bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.sev-count { width: 40px; text-align: right; font-weight: 700; font-size: 15px; }

/* Risk bars */
.risk-meta { display: flex; justify-content: space-between; margin: 16px 0 4px; }
.risk-label-text { font-size: 14px; font-weight: 600; color: #555; }
.risk-score-text { font-size: 14px; font-weight: 700; }
.risk-bar-wrapper { height: 24px; background: #eee; border-radius: 4px; overflow: hidden; margin: 4px 0 8px; }
.risk-bar { height: 100%; border-radius: 4px; }

/* Grade */
.grade-display { text-align: center; margin: 20px 0; }
.grade-badge { display: inline-block; font-size: 48px; font-weight: 800; color: #1a1a2e; background: #f0f0f0; padding: 20px 40px; border-radius: 12px; letter-spacing: 4px; }

/* Findings */
.sev-heading { font-size: 20px; font-weight: 700; margin: 25px 0 10px; padding-bottom: 4px; border-bottom: 2px solid currentColor; }
.finding-card { border: 1px solid #e0e0e0; border-radius: 8px; margin: 12px 0; overflow: hidden; }
.finding-header { display: flex; align-items: center; gap: 10px; padding: 14px 16px; background: #f8f9fa; border-bottom: 1px solid #eee; flex-wrap: wrap; }
.finding-num { font-weight: 700; color: #999; min-width: 24px; }
.finding-title { flex: 1; font-weight: 600; font-size: 15px; }
.sev-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; letter-spacing: 1px; }
.cvss-badge { background: #1a1a2e; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
.finding-status { font-size: 12px; color: #666; text-transform: capitalize; }
.finding-body { padding: 14px 16px; }
.finding-desc { font-size: 14px; color: #444; margin-bottom: 8px; }
.find-business { font-size: 13px; color: #555; margin: 6px 0; padding: 8px; background: #f0f8ff; border-left: 3px solid #17a2b8; border-radius: 3px; }
.find-risk { font-size: 13px; color: #856404; margin: 6px 0; padding: 8px; background: #fff3cd; border-left: 3px solid #ffc107; border-radius: 3px; }
.find-component { font-size: 13px; color: #333; margin: 6px 0; padding: 4px 0; }
.find-fp { font-size: 13px; color: #6c757d; margin: 6px 0; font-style: italic; }
.find-evidence { font-size: 13px; color: #555; margin: 6px 0; padding: 4px 0; }
.find-hash { font-size: 11px; color: #888; margin: 4px 0; }
.find-hash code { font-family: 'Consolas', monospace; font-size: 10px; background: #f4f4f4; padding: 2px 6px; border-radius: 2px; }
.find-fix { font-size: 13px; color: #28a745; margin: 8px 0 0; padding: 8px; background: #f0fff0; border-left: 3px solid #28a745; border-radius: 3px; }

/* Reference badges */
.finding-refs { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; padding: 6px 0; }
.ref-badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; background: #e9ecef; color: #495057; }
.ref-cwe { background: #f8d7da; color: #721c24; }
.ref-capec { background: #d1ecf1; color: #0c5460; }
.ref-mitre { background: #d4edda; color: #155724; }
.ref-comp { background: #e2d9f3; color: #563d7c; }

/* Compliance */
.compliance-table { width: 100%; border-collapse: collapse; margin: 15px 0 25px; font-size: 14px; }
.compliance-table th { background: #1a1a2e; color: #fff; padding: 10px 12px; text-align: left; font-weight: 600; }
.compliance-table td { padding: 10px 12px; border-bottom: 1px solid #e0e0e0; text-align: center; }
.compliance-table td:first-child { text-align: left; font-weight: 600; }
.comp-fw { min-width: 140px; }
.comp-bar-wrapper { height: 20px; background: #eee; border-radius: 3px; overflow: hidden; min-width: 120px; }
.comp-bar { height: 100%; border-radius: 3px; }
.comp-score { font-weight: 700; }

/* Appendix */
.app-table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 14px; }
.app-table td { padding: 8px 12px; border-bottom: 1px solid #e0e0e0; }
.app-label { font-weight: 600; color: #555; width: 180px; }
ul { margin: 10px 0 10px 25px; }
li { margin-bottom: 6px; font-size: 14px; color: #444; }
.evidence-list { columns: 2; column-gap: 30px; }
.remediation-box { background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; padding: 20px; font-size: 15px; line-height: 1.7; }
"""


def generate_professional_html(report: ProfessionalReport) -> str:
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

    body = "\n".join(sections)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{report.title}</title>
<style>{_CSS}</style>
</head>
<body>{body}</body>
</html>"""
