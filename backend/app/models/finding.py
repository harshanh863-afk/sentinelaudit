import uuid

from sqlalchemy import Boolean, Enum, Float, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin
from app.models.enums import FindingStatus, SeverityLevel


class Finding(UUIDMixin, Base):
    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id"), nullable=False, index=True
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("rules.id"), nullable=True, index=True
    )
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    finding_type: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel, name="severity_level", create_constraint=True, values_callable=lambda enum: [item.value for item in enum]),
        nullable=False,
        index=True,
    )
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status", create_constraint=True, values_callable=lambda enum: [item.value for item in enum]),
        default=FindingStatus.NEW,
        nullable=False,
        index=True,
    )
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    rule: Mapped["Rule | None"] = relationship("Rule", back_populates="findings")
    risk_score: Mapped["RiskScore | None"] = relationship(
        "RiskScore", back_populates="finding", uselist=False,
        primaryjoin="RiskScore.finding_id == Finding.id",
        foreign_keys="RiskScore.finding_id",
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        "Evidence", back_populates="finding", cascade="all, delete-orphan"
    )
    compliance_mappings: Mapped[list["ComplianceMapping"]] = relationship(
        "ComplianceMapping", back_populates="finding", cascade="all, delete-orphan"
    )
