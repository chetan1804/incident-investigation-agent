"""Persist AI prompt regression runs."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260906_0004"
down_revision: str | None = "20260905_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_regression_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("dataset_version", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("prompt_sha256", sa.String(length=64), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("total_cases", sa.Integer(), nullable=False),
        sa.Column("passed_cases", sa.Integer(), nullable=False),
        sa.Column("results_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ai_regression_runs_id"), "ai_regression_runs", ["id"])
    op.create_index(
        op.f("ix_ai_regression_runs_run_id"),
        "ai_regression_runs",
        ["run_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_ai_regression_runs_dataset_version"),
        "ai_regression_runs",
        ["dataset_version"],
    )
    op.create_index(
        op.f("ix_ai_regression_runs_prompt_version"),
        "ai_regression_runs",
        ["prompt_version"],
    )
    op.create_index(
        op.f("ix_ai_regression_runs_created_at"),
        "ai_regression_runs",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_table("ai_regression_runs")
