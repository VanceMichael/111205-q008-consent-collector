"""Exceptions used by the recording / replay transport layer.

All failures are explicit: the replay transport never falls back to the
network, and unknown requests raise :class:`UnknownRequestError` with an
explanation of what was tried and what the pack actually contains.
"""


class HarvestError(Exception):
    """Base class for transport-adapter failures."""


class SensitiveStructureError(HarvestError):
    """Raised before anything is written when the policy cannot classify a
    potentially sensitive structure (fail-closed packet rejection)."""

    def __init__(self, location, reason):
        self.location = location
        self.reason = reason
        super().__init__(f"refusing to pack sensitive structure at {location}: {reason}")


class RecordingError(HarvestError):
    """Raised when an exchange violates the recording contract."""


class ReplayError(HarvestError):
    """Base class for replay-time failures."""


class UnknownRequestError(ReplayError):
    """No recorded exchange matches the incoming request.

    ``nearest`` carries human-readable candidates so the failure is
    explainable instead of a bare assertion.
    """

    def __init__(self, request_key, nearest):
        self.request_key = request_key
        self.nearest = nearest
        details = "; ".join(nearest) if nearest else "the pack contains no exchanges"
        super().__init__(
            "no recorded exchange matches "
            f"[{request_key['source']} {request_key['method']} {request_key['path']}] -> {details}"
        )


class AttemptLimitError(ReplayError):
    """The request matched a recording, but its attempt budget is exhausted."""

    def __init__(self, key, attempts, limit):
        self.key = key
        self.attempts = attempts
        self.limit = limit
        super().__init__(
            f"attempt limit reached for [{key['source']} {key['method']} {key['path']}]: "
            f"{attempts} call(s) but recording allows {limit}"
        )


class UnboundCorrelationError(ReplayError):
    """A correlation slot carried a value that was never minted in this run."""

    def __init__(self, location, value):
        self.location = location
        self.value = value
        super().__init__(
            f"correlation slot {location} carries unbound value {value!r}; "
            "this run never generated it (recordings bind symbols, not raw values)"
        )


class IncompletePackError(HarvestError):
    """A pack directory contains interrupted material and cannot be used."""


class UnusedExchangeError(ReplayError):
    """Strict replay ended while some recorded exchanges were never called."""


class PackValidationError(HarvestError):
    """The pack fails validation; ``problems`` lists every reason found."""

    def __init__(self, problems):
        self.problems = problems
        super().__init__("pack validation failed: " + "; ".join(problems))


class PolicyCompatibilityError(HarvestError):
    """The installed sanitizing policy cannot safely reuse an old pack."""
