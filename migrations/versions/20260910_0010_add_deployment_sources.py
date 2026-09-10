"""Track external deployment sources for lifecycle ingestion."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260910_0010"
down_revision: str | None = "20260910_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("deployments") as batch_op:
        batch_op.add_column(
            sa.Column(
                "source",
                sa.String(length=64),
                server_default="api",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column("source_event_id", sa.String(length=255), nullable=True)
        )
        batch_op.create_unique_constraint(
            "uq_deployments_source_event", ["source", "source_event_id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("deployments") as batch_op:
        batch_op.drop_constraint("uq_deployments_source_event", type_="unique")
        batch_op.drop_column("source_event_id")
        batch_op.drop_column("source")
