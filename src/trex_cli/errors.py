from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TrexCliError(Exception):
    code: str
    message: str
    category: str = "INTERNAL"
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message


class IdempotencyConflict(TrexCliError):
    def __init__(self) -> None:
        super().__init__(
            code="IDEMPOTENCY_CONFLICT",
            message="the idempotency key is already bound to a different document",
            category="INPUT",
        )


class NotFound(TrexCliError):
    def __init__(self, resource: str) -> None:
        super().__init__(
            code="NOT_FOUND",
            message=f"{resource} was not found",
            category="INPUT",
        )


class RevisionConflict(TrexCliError):
    def __init__(self) -> None:
        super().__init__(
            code="REVISION_CONFLICT",
            message="the Job revision changed concurrently",
            category="INTERNAL",
            retryable=True,
        )


class DatabaseMigrationError(TrexCliError):
    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            code="DATABASE_MIGRATION_FAILED",
            message=message,
            category="RESOURCE",
            details=details or {},
        )
