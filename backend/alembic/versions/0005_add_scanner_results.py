"""Add scanner_results column to scans table

Revision ID: 0005
Revises: 0004
Create Date: 2024-01-19
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("scanner_results", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "scanner_results")
