class IncidentInvestigationError(Exception):
    """Base class for expected application errors."""


class ResourceNotFoundError(IncidentInvestigationError):
    """Raised when a requested domain resource does not exist."""


class ResourceConflictError(IncidentInvestigationError):
    """Raised when a request conflicts with existing domain data."""


class AIAnalysisUnavailableError(IncidentInvestigationError):
    """Raised when AI analysis is not configured or cannot be reached."""


class AIAnalysisError(IncidentInvestigationError):
    """Raised when an AI provider returns unusable analysis."""


class InvalidFeedbackError(IncidentInvestigationError):
    """Raised when feedback does not reference a hypothesis in an analysis."""


class InvalidIngestionPayloadError(IncidentInvestigationError):
    """Raised when an external payload lacks required normalization context."""


class IngestionAuthenticationError(IncidentInvestigationError):
    """Raised when an external ingestion request cannot be authenticated."""


class IngestionUnavailableError(IncidentInvestigationError):
    """Raised when an ingestion adapter is not configured for use."""
