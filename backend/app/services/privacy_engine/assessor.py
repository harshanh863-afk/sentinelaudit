"""Privacy Assessment Engine — evaluates cookie compliance, data protection, and privacy regulation adherence.

Assesses findings against privacy regulations:
    - GDPR (consent, cookie opt-in, data minimization, privacy notice)
    - CCPA/CPRA (opt-out mechanism, Do Not Sell link detection)
    - COPPA (child privacy indicators)
    - ePrivacy Directive / EU Cookie Law (cookie consent, transparency)
    - LGPD, DPDP, Australia APP (privacy practices)
"""

from app.services.privacy_engine.models import PrivacyAssessmentReport, PrivacyIssue


class PrivacyAssessmentEngine:
    """Evaluates detected issues against privacy regulations and produces a report."""

    def __init__(self, findings: list | None = None, scan_evidence: dict | None = None):
        self.findings = findings or []
        self.evidence = scan_evidence or {}

    def assess(self) -> PrivacyAssessmentReport:
        issues: list[PrivacyIssue] = []
        recommendations: list[str] = []

        issues.extend(self._check_cookie_compliance())
        issues.extend(self._check_gdpr_compliance())
        issues.extend(self._check_ccpa_compliance())
        issues.extend(self._check_coppa_indicators())

        passed = sum(1 for i in issues if i.passed)
        failed = sum(1 for i in issues if not i.passed)
        total = len(issues)
        score = round((passed / total * 100) if total > 0 else 100.0, 1)

        if failed > 0:
            recommendations.extend(self._generate_recommendations(issues))

        gdpr_issues = [i for i in issues if "gdpr" in str(i.affected_regulations).lower() or "eprivacy" in str(i.affected_regulations).lower()]
        ccpa_issues = [i for i in issues if "ccpa" in str(i.affected_regulations).lower()]
        coppa_issues = [i for i in issues if "coppa" in str(i.affected_regulations).lower()]
        cookie_issues = [i for i in issues if i.category == "cookie_compliance"]

        def _subscore(subset: list) -> float:
            if not subset:
                return 100.0
            sp = sum(1 for i in subset if i.passed)
            return round(sp / len(subset) * 100, 1)

        return PrivacyAssessmentReport(
            score=score,
            issues=issues,
            passed_controls=passed,
            failed_controls=failed,
            recommendations=recommendations,
            gdpr_score=_subscore(gdpr_issues),
            ccpa_score=_subscore(ccpa_issues),
            coppa_score=_subscore(coppa_issues),
            cookie_score=_subscore(cookie_issues),
        )

    def _check_cookie_compliance(self) -> list[PrivacyIssue]:
        issues: list[PrivacyIssue] = []
        cookie_secure = any(
            f.get("category") == "cookie_security" or "Secure" in str(f.get("detail", ""))
            for f in self.findings
        )
        hsts_present = any(
            "Strict-Transport-Security" in str(f.get("detail", ""))
            or f.get("id") == "HTTP-001"
            for f in self.findings
        )
        has_http_only = any(
            "HttpOnly" in str(f.get("detail", ""))
            or "COOKIE" in str(f.get("id", ""))
            for f in self.findings
        )
        issues.append(PrivacyIssue(
            issue_id="PRIV-COOKIE-1",
            title="Cookie Consent Mechanism",
            description="Check if the site provides a cookie consent mechanism for non-essential cookies.",
            severity="medium",
            category="cookie_compliance",
            affected_regulations=["gdpr", "eprivacy", "eu_cookie", "lgpd"],
            remediation="Implement a cookie consent banner with granular opt-in options.",
            passed=False,
        ))
        issues.append(PrivacyIssue(
            issue_id="PRIV-COOKIE-2",
            title="Secure Cookie Flag",
            description="Cookies should use the Secure flag to prevent transmission over unencrypted HTTP.",
            severity="high",
            category="cookie_compliance",
            affected_regulations=["gdpr", "hipaa", "pci_dss"],
            remediation="Set the Secure flag on all cookies.",
            passed=cookie_secure,
        ))
        issues.append(PrivacyIssue(
            issue_id="PRIV-COOKIE-3",
            title="HSTS Implementation",
            description="HSTS ensures cookies are only transmitted over HTTPS connections.",
            severity="medium",
            category="cookie_compliance",
            affected_regulations=["gdpr", "nist"],
            remediation="Enable HSTS with includeSubDomains directive.",
            passed=hsts_present,
        ))
        issues.append(PrivacyIssue(
            issue_id="PRIV-COOKIE-4",
            title="HttpOnly Cookie Flag",
            description="Session cookies should use HttpOnly to prevent XSS-based theft.",
            severity="high",
            category="cookie_compliance",
            affected_regulations=["gdpr", "owasp", "pci_dss"],
            remediation="Set the HttpOnly flag on session cookies.",
            passed=has_http_only,
        ))
        return issues

    def _check_gdpr_compliance(self) -> list[PrivacyIssue]:
        issues: list[PrivacyIssue] = []
        privacy_policy = self.evidence.get("privacy_policy_detected", False)
        cookie_banner = self.evidence.get("cookie_banner_detected", False)
        data_transparency = self.evidence.get("data_collection_transparency", False)
        issues.append(PrivacyIssue(
            issue_id="PRIV-GDPR-1",
            title="Privacy Policy Availability",
            description="A comprehensive privacy policy is required by GDPR Article 13-14.",
            severity="high",
            category="gdpr",
            affected_regulations=["gdpr", "lgpd", "dpdp", "au_privacy"],
            remediation="Publish a clear privacy policy detailing data collection, processing, and rights.",
            passed=privacy_policy,
        ))
        issues.append(PrivacyIssue(
            issue_id="PRIV-GDPR-2",
            title="Cookie Consent Mechanism",
            description="GDPR requires opt-in consent for non-essential cookies per ePrivacy Directive.",
            severity="high",
            category="gdpr",
            affected_regulations=["gdpr", "eprivacy", "eu_cookie"],
            remediation="Implement a consent management platform with granular controls.",
            passed=cookie_banner,
        ))
        issues.append(PrivacyIssue(
            issue_id="PRIV-GDPR-3",
            title="Data Collection Transparency",
            description="Individuals must be informed about what data is collected and why.",
            severity="medium",
            category="gdpr",
            affected_regulations=["gdpr", "ccpa", "lgpd"],
            remediation="Clearly disclose all data collection practices and purposes.",
            passed=data_transparency,
        ))
        return issues

    def _check_ccpa_compliance(self) -> list[PrivacyIssue]:
        issues: list[PrivacyIssue] = []
        opt_out_link = self.evidence.get("dns_link_detected", False) or self.evidence.get("opt_out_link_detected", False)
        privacy_policy = self.evidence.get("privacy_policy_detected", False)
        issues.append(PrivacyIssue(
            issue_id="PRIV-CCPA-1",
            title="Do Not Sell/Share Link",
            description="CCPA/CPRA requires a 'Do Not Sell or Share My Personal Information' link.",
            severity="high",
            category="ccpa",
            affected_regulations=["ccpa", "cpra_expanded"],
            remediation="Add a clear 'Do Not Sell or Share My Personal Information' link on the homepage.",
            passed=opt_out_link,
        ))
        issues.append(PrivacyIssue(
            issue_id="PRIV-CCPA-2",
            title="Privacy Policy Disclosures",
            description="CCPA requires specific disclosures about data collection and consumer rights.",
            severity="medium",
            category="ccpa",
            affected_regulations=["ccpa", "cpra_expanded"],
            remediation="Update privacy policy with CCPA-required disclosures and consumer rights information.",
            passed=privacy_policy,
        ))
        issues.append(PrivacyIssue(
            issue_id="PRIV-CCPA-3",
            title="Consumer Rights Mechanism",
            description="CCPA requires a mechanism for consumers to exercise their privacy rights.",
            severity="medium",
            category="ccpa",
            affected_regulations=["ccpa", "cpra_expanded"],
            remediation="Provide a toll-free number or web form for consumer privacy requests.",
            passed=False,
        ))
        return issues

    def _check_coppa_indicators(self) -> list[PrivacyIssue]:
        issues: list[PrivacyIssue] = []
        targets_children = self.evidence.get("targets_children", False)
        has_privacy_policy = self.evidence.get("privacy_policy_detected", False)
        issues.append(PrivacyIssue(
            issue_id="PRIV-COPPA-1",
            title="Children's Privacy Notice",
            description="COPPA requires specific privacy protections for children under 13.",
            severity="high",
            category="coppa",
            affected_regulations=["coppa", "gdpr", "dpdp"],
            remediation="Implement age verification and parental consent mechanisms if targeting children.",
            passed=False,
        ))
        issues.append(PrivacyIssue(
            issue_id="PRIV-COPPA-2",
            title="Data Minimization for Children",
            description="Collect only minimal information from children as required by COPPA.",
            severity="medium",
            category="coppa",
            affected_regulations=["coppa"],
            remediation="Review data collection practices to minimize data from children.",
            passed=not targets_children or has_privacy_policy,
        ))
        return issues

    def _generate_recommendations(self, issues: list[PrivacyIssue]) -> list[str]:
        recs = []
        for issue in issues:
            if not issue.passed and issue.remediation:
                recs.append(f"[{issue.issue_id}] {issue.remediation}")
        return recs[:10]
