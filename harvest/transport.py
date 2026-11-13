"""Transport factory and public surface for the collection adapter layer."""

from enum import Enum

from .errors import (
    AttemptLimitError,
    HarvestError,
    IncompletePackError,
    PackValidationError,
    PolicyCompatibilityError,
    RecordingError,
    SensitiveStructureError,
    UnknownRequestError,
    UnboundCorrelationError,
    UnusedExchangeError,
)
from .pack import cleanup_partial, list_partial_artifacts, validate_pack
from .policy import Emitter, SourcePolicy
from .recorder import RecordingTransport
from .replayer import ReplayTransport
from .verify import VerifyTransport


class Mode(str, Enum):
    RECORD = "record"
    REPLAY = "replay"
    VERIFY = "verify"


def open_transport(mode, policy, pack_dir, inner=None, strict=True):
    """Open the transport adapter in one of the three supported modes.

    * ``record``  : wraps ``inner`` (the real/local client transport) and
      writes a sanitized, symbolized pack to ``pack_dir``.
    * ``replay``  : strict offline replay from ``pack_dir``; no network path
      exists in this transport.
    * ``verify``  : validates ``pack_dir`` under ``policy`` without serving.
    """
    if mode == Mode.RECORD or mode == "record":
        if inner is None:
            raise ValueError("record mode requires an inner transport")
        return RecordingTransport(inner, policy, pack_dir)
    if mode == Mode.REPLAY or mode == "replay":
        return ReplayTransport(pack_dir, policy, strict=strict)
    if mode == Mode.VERIFY or mode == "verify":
        return VerifyTransport(pack_dir, policy)
    raise ValueError(f"unknown transport mode: {mode!r}")


__all__ = [
    "Mode",
    "Emitter",
    "SourcePolicy",
    "open_transport",
    "RecordingTransport",
    "ReplayTransport",
    "VerifyTransport",
    "validate_pack",
    "cleanup_partial",
    "list_partial_artifacts",
    "HarvestError",
    "RecordingError",
    "SensitiveStructureError",
    "UnknownRequestError",
    "AttemptLimitError",
    "UnboundCorrelationError",
    "UnusedExchangeError",
    "IncompletePackError",
    "PackValidationError",
    "PolicyCompatibilityError",
]
