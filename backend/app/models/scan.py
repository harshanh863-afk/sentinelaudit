import uuid

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin
from app.models.enums import ScanStatus


class Scan(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("targets.id"), nullable=False, index=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", create_constraint=True),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    started_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress: Mapped[int | None] = mapped_column(Integer, nullable=True)
    progress_stage: Mapped[str | None] = mapped_column(String(100), nullable=True)

    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        "Evidence", back_populates="scan", cascade="all, delete-orphan"
    )
