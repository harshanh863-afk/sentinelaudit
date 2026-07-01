"""Add progress and progress_stage columns to scans table

Revision ID: 0004
Revises: 0003
Create Date: 2024-01-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("progress", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("progress_stage", sa.String(100), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "progress_stage")
    op.drop_column("scans", "progress")
