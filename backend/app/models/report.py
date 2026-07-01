import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class Report(UUIDMixin, Base):
    __tablename__ = "reports"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id"), nullable=False, index=True
    )
    scan_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Professional report fields
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_rating: Mapped[str | None] = mapped_column(String(20), nullable=True)
    findings_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity_breakdown: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    project: Mapped["Project"] = relationship("Project", back_populates="reports")
