from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class Framework(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "frameworks"

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    controls: Mapped[list["FrameworkControl"]] = relationship(
        "FrameworkControl", back_populates="framework", cascade="all, delete-orphan"
    )
