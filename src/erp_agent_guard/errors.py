"""Exception types. Every refusal the agent sees is one of these."""


class GuardError(Exception):
    """Base class. ``code`` is stable and safe to show to the agent."""

    code = "guard_error"


class PolicyError(GuardError):
    code = "policy_denied"


class QuotaExceeded(GuardError):
    code = "quota_exceeded"


class ApprovalError(GuardError):
    code = "approval_invalid"


class ConflictError(GuardError):
    """The record changed between dry-run and commit."""

    code = "stale_proposal"


class UpstreamError(GuardError):
    """The ERP returned an error (message is sanitized)."""

    code = "upstream_error"
