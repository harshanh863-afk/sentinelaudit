"""Security grade calculation — converts numerical risk scores into letter grades.

Grade scale:
    95-100  A+
    85-94   A
    75-84   B
    60-74   C
    40-59   D
    0-39    F
"""

from app.services.risk_engine.models import SecurityGrade


def calculate_grade(security_score: float) -> SecurityGrade:
    if security_score >= 95:
        return SecurityGrade.A_PLUS
    if security_score >= 85:
        return SecurityGrade.A
    if security_score >= 75:
        return SecurityGrade.B
    if security_score >= 60:
        return SecurityGrade.C
    if security_score >= 40:
        return SecurityGrade.D
    return SecurityGrade.F


def grade_description(grade: SecurityGrade) -> str:
    descriptions = {
        SecurityGrade.A_PLUS: "Exceptional security posture — minimal residual risk.",
        SecurityGrade.A: "Strong security posture — well-managed risk.",
        SecurityGrade.B: "Good security posture — moderate residual risk.",
        SecurityGrade.C: "Fair security posture — notable risks requiring attention.",
        SecurityGrade.D: "Poor security posture — significant risks present.",
        SecurityGrade.F: "Critical security posture — urgent remediation required.",
    }
    return descriptions.get(grade, "Unknown grade.")
