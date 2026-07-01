import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class Evidence(UUIDMixin, Base):
    __tablename__ = "evidence"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("findings.id"), nullable=True, index=True
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    request_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_headers: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    response_headers: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    captured_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    screenshot_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    evidence_meta: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True, default=dict)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="evidence")
    finding: Mapped["Finding | None"] = relationship("Finding", back_populates="evidence")
