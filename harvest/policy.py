"""Source policies that decide what may be persisted.

A policy is the *only* component that knows which fields are sensitive.
Sanitization is deliberately fail-closed: any structure containing a
sensitive hint that is not explicitly listed for redaction aborts the whole
packet, so unknown sensitive data can never silently reach disk.
"""

from dataclasses import dataclass, field

from .errors import SensitiveStructureError

# Structural keys that must never be persisted raw, regardless of the
# policy declared by a source. Policies extend this set; they cannot shrink it.
ALWAYS_REDACT_HEADER_KEYS = frozenset({"authorization", "proxy-authorization"})

# Substring hints used only for *fail-closed* checks: when a structure
# contains one of these hints, the policy must explicitly know how to
# handle it. The fake-token prefix makes the check deterministic for the
# synthetic fixtures without needing any real secret material.
SENSITIVE_HINTS = (
    "token",
    "secret",
    "password",
    "credential",
    "signature",
    "cookie",
    "auth",
)


def _hint_in(key):
    lowered = key.lower()
    return any(hint in lowered for hint in SENSITIVE_HINTS)


@dataclass(frozen=True)
class Emitter:
    """A JSON path inside a response that mints a correlation value.

    ``symbol`` is the persistent placeholder (e.g. ``session``). Values
    minted here are replaced by the symbol at record time and materialized
    into fresh ephemeral values at replay time, so two runs never need to
    generate the same temporary value.
    """

    path: str
    symbol: str


@dataclass(frozen=True)
class SourcePolicy:
    """Retention policy for one cooperation source."""

    source: str
    policy_version: str
    # Policy versions whose packs this policy considers safe to reuse.
    accepts_versions: frozenset
    # JSON body keys whose values must be replaced with a redaction marker.
    redacted_body_keys: frozenset
    # Request/response header keys (lower-case) whose values are redacted.
    redacted_header_keys: frozenset
    # URL query parameters whose values are redacted.
    redacted_query_params: frozenset
    # Query parameters that carry no semantic value for matching.
    ignored_query_params: frozenset
    # Response locations that generate correlation values.
    emitters: tuple = ()
    # Correlation slots in requests: location key -> symbol name. A value
    # seen in one of these slots is replaced by the named symbol.
    correlation_headers: dict = field(default_factory=dict)
    correlation_query: dict = field(default_factory=dict)
    correlation_body: dict = field(default_factory=dict)
    # Endpoints (method, path) that may legitimately be called repeatedly;
    # every other endpoint is recorded with a single-attempt budget.
    repeatable_endpoints: frozenset = frozenset()
    rules_hash: str = ""

    @classmethod
    def create(cls, **kwargs):
        sets = {
            "accepts_versions": frozenset,
            "redacted_body_keys": frozenset,
            "redacted_header_keys": frozenset,
            "redacted_query_params": frozenset,
            "ignored_query_params": frozenset,
            "repeatable_endpoints": frozenset,
        }
        for name, factory in sets.items():
            if name in kwargs:
                kwargs[name] = factory(kwargs[name])
        for name in ("correlation_headers", "correlation_query", "correlation_body"):
            if name in kwargs:
                kwargs[name] = dict(kwargs[name])
        if "emitters" in kwargs:
            kwargs["emitters"] = tuple(
                Emitter(**e) if isinstance(e, dict) else e for e in kwargs["emitters"]
            )
        policy = cls(**kwargs)
        if not policy.rules_hash:
            from .rules import compute_rules_hash

            object.__setattr__(policy, "rules_hash", compute_rules_hash(policy))
        return policy

    @property
    def safe_header_keys(self):
        return ALWAYS_REDACT_HEADER_KEYS | self.redacted_header_keys

    def is_repeatable(self, method, path):
        return (method, path) in self.repeatable_endpoints

    def fail_on_unknown_sensitive_structure(self, structure, location):
        """Reject a packet when an unhandled sensitive-looking key appears."""
        if isinstance(structure, dict):
            for key, value in structure.items():
                child = f"{location}.{key}"
                if _hint_in(key):
                    if key in self.redacted_body_keys:
                        continue
                    raise SensitiveStructureError(
                        child,
                        "key looks sensitive but the policy does not list it for redaction",
                    )
                self.fail_on_unknown_sensitive_structure(value, child)
        elif isinstance(structure, list):
            for index, value in enumerate(structure):
                self.fail_on_unknown_sensitive_structure(value, f"{location}[{index}]")

    def check_url_safety(self, url, location):
        """Unknown sensitive query parameters fail closed.

        Userinfo credentials embedded in download URLs are always stripped
        by :func:`sanitize_url_string`, so they do not need a policy entry;
        undeclared sensitive-looking query parameters do.
        """
        for part in url.split("&"):
            if "=" in part:
                key = part.split("=", 1)[0].rsplit("?", 1)[-1].lower()
                if _hint_in(key) and key not in self.redacted_query_params:
                    raise SensitiveStructureError(
                        f"{location}?{key}",
                        "query parameter looks sensitive but the policy does not redact it",
                    )


def sanitize_headers(headers, policy):
    """Return headers safe to persist and the set of removed keys."""
    safe = {}
    removed = set()
    for key, value in headers.items():
        if key.lower() in policy.safe_header_keys:
            safe[key] = {"redacted": True}
            removed.add(key)
        else:
            safe[key] = value
    return safe, removed


def sanitize_query(query_pairs, policy):
    """Sanitize parsed query pairs (list of (key, value))."""
    safe_pairs = []
    for key, value in query_pairs:
        if key in policy.redacted_query_params:
            safe_pairs.append((key, {"redacted": True}))
        else:
            safe_pairs.append((key, value))
    return safe_pairs


def sanitize_json_body(body, policy, location="body"):
    """Deep-copy a JSON body replacing every redacted key with a marker.

    Strings that look like URLs are additionally sanitized so credentials
    embedded in download addresses (userinfo or sensitive query parameters)
    never reach disk even when they are just one field among many.
    """
    if isinstance(body, dict):
        result = {}
        for key, value in body.items():
            if key in policy.redacted_body_keys:
                result[key] = {"redacted": True}
            else:
                result[key] = sanitize_json_body(value, policy, f"{location}.{key}")
        return result
    if isinstance(body, list):
        return [sanitize_json_body(item, policy, f"{location}[{i}]") for i, item in enumerate(body)]
    if isinstance(body, str) and "://" in body:
        return sanitize_url_string(body, policy)
    return body


def sanitize_url_string(url, policy):
    """Redact userinfo credentials and declared sensitive query parameters."""
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

    parts = urlsplit(url)
    netloc = parts.netloc
    if "@" in netloc:
        host = netloc.rsplit("@", 1)[1]
        netloc = "redacted:redacted@" + host
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        pairs = [
            (key, "[REDACTED]") if key in policy.redacted_query_params else (key, value)
            for key, value in pairs
        ]
        query = urlencode(pairs)
    else:
        query = parts.query
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
