"""Privacy Assessment Engine.

Evaluates findings for:
    - Cookie compliance (Secure, HttpOnly, SameSite, consent)
    - GDPR compliance (privacy notice, consent, transparency)
    - CCPA/CPRA compliance (opt-out, disclosures)
    - COPPA (child privacy indicators)

Outputs a PrivacyAssessmentReport with per-regulation subscores.
"""

from app.services.privacy_engine.models import PrivacyAssessmentReport, PrivacyIssue
from app.services.privacy_engine.assessor import PrivacyAssessmentEngine

__all__ = [
    "PrivacyAssessmentReport",
    "PrivacyIssue",
    "PrivacyAssessmentEngine",
]
