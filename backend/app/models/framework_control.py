import uuid

from sqlalchemy import Column, ForeignKey, String, Table, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin

rule_framework_controls = Table(
    "rule_framework_controls",
    Base.metadata,
    Column("rule_id", Uuid, ForeignKey("rules.id"), primary_key=True),
    Column("framework_control_id", Uuid, ForeignKey("framework_controls.id"), primary_key=True),
)


class FrameworkControl(UUIDMixin, Base):
    __tablename__ = "framework_controls"

    framework_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("frameworks.id"), nullable=False, index=True
    )
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    framework: Mapped["Framework"] = relationship("Framework", back_populates="controls")
