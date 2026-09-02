class IncidentInvestigationError(Exception):
    """Base class for expected application errors."""


class ResourceNotFoundError(IncidentInvestigationError):
    """Raised when a requested domain resource does not exist."""


class ResourceConflictError(IncidentInvestigationError):
    """Raised when a request conflicts with existing domain data."""
