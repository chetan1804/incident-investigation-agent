"""Persist AI analyses and operator feedback."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260905_0003"
down_revision: str | None = "20260902_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("prompt_sha256", sa.String(length=64), nullable=False),
        sa.Column("correlation_window_json", sa.JSON(), nullable=False),
        sa.Column("ranked_signal_ids_json", sa.JSON(), nullable=False),
        sa.Column("hypotheses_json", sa.JSON(), nullable=False),
        sa.Column("remediation_suggestions_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ai_analyses_id"), "ai_analyses", ["id"])
    op.create_index(
        op.f("ix_ai_analyses_analysis_id"), "ai_analyses", ["analysis_id"], unique=True
    )
    op.create_index(op.f("ix_ai_analyses_incident_id"), "ai_analyses", ["incident_id"])
    op.create_index(op.f("ix_ai_analyses_created_at"), "ai_analyses", ["created_at"])

    op.create_table(
        "ai_analysis_feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("feedback_id", sa.String(length=64), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("hypothesis_index", sa.Integer(), nullable=False),
        sa.Column("rating", sa.String(length=32), nullable=False),
        sa.Column("operator_name", sa.String(length=255), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["ai_analyses.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ai_analysis_feedback_id"), "ai_analysis_feedback", ["id"])
    op.create_index(
        op.f("ix_ai_analysis_feedback_feedback_id"),
        "ai_analysis_feedback",
        ["feedback_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_ai_analysis_feedback_analysis_id"),
        "ai_analysis_feedback",
        ["analysis_id"],
    )
    op.create_index(
        op.f("ix_ai_analysis_feedback_created_at"),
        "ai_analysis_feedback",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_table("ai_analysis_feedback")
    op.drop_table("ai_analyses")
