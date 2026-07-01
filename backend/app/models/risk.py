import uuid

from sqlalchemy import Enum, Float, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin
from app.models.enums import AttackComplexity, AttackVector, PrivilegesRequired, UserInteraction


class RiskScore(UUIDMixin, Base):
    __tablename__ = "risk_scores"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("findings.id"), nullable=False, unique=True, index=True
    )
    cvss_version: Mapped[str] = mapped_column(String(5), default="3.1", nullable=False)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    attack_vector: Mapped[AttackVector] = mapped_column(
        Enum(AttackVector, name="attack_vector", create_constraint=True, values_callable=lambda enum: [item.value for item in enum]),
        nullable=False,
    )
    attack_complexity: Mapped[AttackComplexity] = mapped_column(
        Enum(AttackComplexity, name="attack_complexity", create_constraint=True, values_callable=lambda enum: [item.value for item in enum]),
        nullable=False,
    )
    privileges_required: Mapped[PrivilegesRequired] = mapped_column(
        Enum(PrivilegesRequired, name="privileges_required", create_constraint=True, values_callable=lambda enum: [item.value for item in enum]),
        nullable=False,
    )
    user_interaction: Mapped[UserInteraction] = mapped_column(
        Enum(UserInteraction, name="user_interaction", create_constraint=True, values_callable=lambda enum: [item.value for item in enum]),
        nullable=False,
    )

    finding: Mapped["Finding"] = relationship("Finding", back_populates="risk_score")
