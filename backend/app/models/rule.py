from sqlalchemy import Enum, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin
from app.models.enums import SeverityLevel


class Rule(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("rule_id", name="uq_rules_rule_id"),)

    rule_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel, name="severity_level", create_constraint=True),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list | None] = mapped_column(JSON, nullable=True, default=list)

    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="rule")
    framework_controls: Mapped[list["FrameworkControl"]] = relationship(
        "FrameworkControl",
        secondary="rule_framework_controls",
        backref="rules",
    )
