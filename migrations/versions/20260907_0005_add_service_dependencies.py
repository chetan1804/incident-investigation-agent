"""Add directed service dependencies."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260907_0005"
down_revision: str | None = "20260906_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_dependencies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dependency_id", sa.String(length=64), nullable=False),
        sa.Column("service_id", sa.Integer(), nullable=False),
        sa.Column("depends_on_service_id", sa.Integer(), nullable=False),
        sa.Column("criticality", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["depends_on_service_id"], ["services.id"]),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "service_id",
            "depends_on_service_id",
            name="uq_service_dependencies_direction",
        ),
    )
    op.create_index(
        op.f("ix_service_dependencies_id"), "service_dependencies", ["id"]
    )
    op.create_index(
        op.f("ix_service_dependencies_dependency_id"),
        "service_dependencies",
        ["dependency_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_service_dependencies_service_id"),
        "service_dependencies",
        ["service_id"],
    )
    op.create_index(
        op.f("ix_service_dependencies_depends_on_service_id"),
        "service_dependencies",
        ["depends_on_service_id"],
    )


def downgrade() -> None:
    op.drop_table("service_dependencies")
