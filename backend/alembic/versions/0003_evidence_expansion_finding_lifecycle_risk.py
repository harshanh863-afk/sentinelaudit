"""Expand evidence, finding lifecycle, risk scoring

Revision ID: 0003
Revises: 0002
Create Date: 2024-01-17
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Risk scores table ---
    op.create_table(
        "risk_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id"), nullable=False, unique=True, index=True),
        sa.Column("cvss_version", sa.String(5), nullable=False, server_default="3.1"),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("attack_vector", sa.Enum("network", "adjacent", "local", "physical", name="attack_vector"), nullable=False),
        sa.Column("attack_complexity", sa.Enum("low", "high", name="attack_complexity"), nullable=False),
        sa.Column("privileges_required", sa.Enum("none", "low", "high", name="privileges_required"), nullable=False),
        sa.Column("user_interaction", sa.Enum("none", "required", name="user_interaction"), nullable=False),
    )

    # --- Expand evidence ---
    op.add_column("evidence", sa.Column("request_data", sa.Text(), nullable=True))
    op.add_column("evidence", sa.Column("response_data", sa.Text(), nullable=True))
    op.add_column("evidence", sa.Column("request_headers", postgresql.JSONB(), nullable=True))
    op.add_column("evidence", sa.Column("response_headers", postgresql.JSONB(), nullable=True))
    op.add_column("evidence", sa.Column("response_body", sa.Text(), nullable=True))
    op.add_column("evidence", sa.Column("captured_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("evidence", sa.Column("screenshot_path", sa.String(512), nullable=True))
    op.add_column("evidence", sa.Column("metadata", postgresql.JSONB(), nullable=True))

    # --- Expand findings ---
    op.add_column("findings", sa.Column("risk_score_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("risk_scores.id"), nullable=True, index=True))
    op.add_column("findings", sa.Column("title", sa.String(255), nullable=True))
    op.add_column("findings", sa.Column("finding_type", sa.String(50), nullable=True, index=True))
    op.add_column("findings", sa.Column("cvss_score", sa.Float(), nullable=True))

    # --- Rebuild finding_status enum with new values ---
    op.execute("ALTER TYPE finding_status RENAME TO finding_status_old")
    op.execute("CREATE TYPE finding_status AS ENUM('new', 'confirmed', 'false_positive', 'accepted_risk', 'fixed', 'retest_required')")
    op.execute("ALTER TABLE findings ALTER COLUMN status TYPE finding_status USING status::text::finding_status")
    op.execute("DROP TYPE finding_status_old")


def downgrade() -> None:
    # Revert finding_status enum
    op.execute("ALTER TYPE finding_status RENAME TO finding_status_old")
    op.execute("CREATE TYPE finding_status AS ENUM('open', 'confirmed', 'false_positive', 'remediated')")
    op.execute("ALTER TABLE findings ALTER COLUMN status TYPE finding_status USING status::text::finding_status")
    op.execute("DROP TYPE finding_status_old")

    op.drop_column("findings", "cvss_score")
    op.drop_column("findings", "finding_type")
    op.drop_column("findings", "title")
    op.drop_column("findings", "risk_score_id")

    op.drop_column("evidence", "metadata")
    op.drop_column("evidence", "screenshot_path")
    op.drop_column("evidence", "captured_at")
    op.drop_column("evidence", "response_body")
    op.drop_column("evidence", "response_headers")
    op.drop_column("evidence", "request_headers")
    op.drop_column("evidence", "response_data")
    op.drop_column("evidence", "request_data")

    op.drop_table("risk_scores")
    op.execute("DROP TYPE IF EXISTS user_interaction")
    op.execute("DROP TYPE IF EXISTS privileges_required")
    op.execute("DROP TYPE IF EXISTS attack_complexity")
    op.execute("DROP TYPE IF EXISTS attack_vector")
