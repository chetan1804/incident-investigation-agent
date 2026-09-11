"""Persist external ingestion delivery audits and replay payloads."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_0011"
down_revision: str | None = "20260910_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ingestion_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("delivery_id", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("source_delivery_id", sa.String(length=255), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("payload_size_bytes", sa.Integer(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=True),
        sa.Column("request_metadata_json", sa.JSON(), nullable=True),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("error_type", sa.String(length=128), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("replayable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("replay_of_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["replay_of_id"], ["ingestion_deliveries.id"]),
        sa.UniqueConstraint("delivery_id"),
    )
    op.create_index("ix_ingestion_deliveries_delivery_id", "ingestion_deliveries", ["delivery_id"])
    op.create_index("ix_ingestion_deliveries_source", "ingestion_deliveries", ["source"])
    op.create_index("ix_ingestion_deliveries_source_delivery_id", "ingestion_deliveries", ["source_delivery_id"])
    op.create_index("ix_ingestion_deliveries_status", "ingestion_deliveries", ["status"])
    op.create_index("ix_ingestion_deliveries_payload_sha256", "ingestion_deliveries", ["payload_sha256"])
    op.create_index("ix_ingestion_deliveries_replay_of_id", "ingestion_deliveries", ["replay_of_id"])
    op.create_index("ix_ingestion_deliveries_created_at", "ingestion_deliveries", ["created_at"])


def downgrade() -> None:
    op.drop_table("ingestion_deliveries")
