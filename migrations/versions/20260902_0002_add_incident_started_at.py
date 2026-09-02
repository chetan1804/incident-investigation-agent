"""Add an explicit incident correlation timestamp."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260902_0002"
down_revision: str | None = "20260822_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE incidents SET started_at = created_at WHERE started_at IS NULL")
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.alter_column("started_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch_op.create_index("ix_incidents_started_at", ["started_at"])


def downgrade() -> None:
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.drop_index("ix_incidents_started_at")
        batch_op.drop_column("started_at")
