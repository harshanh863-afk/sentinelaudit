import uuid

from sqlalchemy import ForeignKey, Integer, JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class Target(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "targets"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tags: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)

    project: Mapped["Project"] = relationship("Project", back_populates="targets")
    scans: Mapped[list["Scan"]] = relationship(
        "Scan", back_populates="target", cascade="all, delete-orphan"
    )
