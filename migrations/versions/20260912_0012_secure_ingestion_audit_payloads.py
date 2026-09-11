"""Add redaction and retention metadata to ingestion audit payloads."""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from alembic import op

revision: str = "20260912_0012"
down_revision: str | None = "20260911_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    default_expiry = datetime.now(UTC) + timedelta(days=30)
    with op.batch_alter_table("ingestion_deliveries") as batch_op:
        batch_op.add_column(
            sa.Column(
                "payload_redacted",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(
            sa.Column(
                "payload_expires_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=default_expiry.isoformat(),
            )
        )
        batch_op.add_column(
            sa.Column("payload_purged_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.create_index(
            "ix_ingestion_deliveries_payload_expires_at", ["payload_expires_at"]
        )


def downgrade() -> None:
    with op.batch_alter_table("ingestion_deliveries") as batch_op:
        batch_op.drop_index("ix_ingestion_deliveries_payload_expires_at")
        batch_op.drop_column("payload_purged_at")
        batch_op.drop_column("payload_expires_at")
        batch_op.drop_column("payload_redacted")
