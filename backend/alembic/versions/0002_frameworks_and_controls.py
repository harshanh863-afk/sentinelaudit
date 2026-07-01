"""Add frameworks, framework_controls, rule_framework_controls, update rules

Revision ID: 0002
Revises: 0001
Create Date: 2024-01-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "frameworks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("version", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("type", sa.String(50), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "framework_controls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("framework_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("frameworks.id"), nullable=False, index=True),
        sa.Column("control_id", sa.String(50), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
    )

    op.create_table(
        "rule_framework_controls",
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("rules.id"), primary_key=True),
        sa.Column("framework_control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("framework_controls.id"), primary_key=True),
    )

    op.add_column("rules", sa.Column("references", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("rules", "references")
    op.drop_table("rule_framework_controls")
    op.drop_table("framework_controls")
    op.drop_table("frameworks")
