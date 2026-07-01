import uuid

from sqlalchemy import ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class ComplianceMapping(UUIDMixin, Base):
    __tablename__ = "compliance_mappings"
    __table_args__ = (
        UniqueConstraint("finding_id", "framework", "control_id", name="uq_compliance_mapping"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("findings.id"), nullable=False, index=True
    )
    framework: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    control_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    finding: Mapped["Finding"] = relationship("Finding", back_populates="compliance_mappings")
