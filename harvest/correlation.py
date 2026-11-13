"""Symbolization of ephemeral correlation values.

Temporary values (session ids, pagination cursors) are referenced across
requests. They cannot be stored raw, yet two runs do not generate the same
values. The correlation table therefore maps *symbols* to concrete values
per run:

* recording: the first concrete value seen for a symbol is registered;
  every later occurrence (in requests or responses) is replaced by the
  symbol marker. Only symbols ever reach the pack on disk.
* replay: a response materializes a fresh fake value for each symbol, and
  subsequent requests must present that exact value. A value the run never
  minted is an explicit binding failure rather than a wrong-key lookup.
"""

import re

SYMBOL_MARKER = "symbol"


def symbol_ref(symbol):
    return {SYMBOL_MARKER: symbol}


def is_symbol_ref(value):
    return isinstance(value, dict) and set(value.keys()) == {SYMBOL_MARKER}


class CorrelationTable:
    def __init__(self):
        # symbol -> concrete value for this run
        self.bindings = {}
        # concrete value -> symbol (reverse lookup when symbolizing requests)
        self.reverse = {}

    def register(self, symbol, value):
        """Bind a freshly minted value to a symbol and return its marker."""
        self.bindings[symbol] = value
        self.reverse[value] = symbol
        return symbol_ref(symbol)

    def bind_slot(self, symbol, value):
        """Recording-side correlation: bind unknown values on first use."""
        if value in self.reverse:
            return symbol_ref(self.reverse[value])
        return self.register(symbol, value)

    def symbolize_value(self, value, location):
        """Replace a concrete value with its symbol when already bound."""
        if value in self.reverse:
            return symbol_ref(self.reverse[value])
        return value

    def materialize(self, ref):
        symbol = ref[SYMBOL_MARKER]
        if symbol not in self.bindings:
            raise KeyError(symbol)
        return self.bindings[symbol]

    def resolve_incoming(self, value, location):
        """Map an incoming concrete value back to its symbol, or fail."""
        if value in self.reverse:
            return symbol_ref(self.reverse[value])
        from .errors import UnboundCorrelationError

        raise UnboundCorrelationError(location, value)


class ReplayCorrelationTable(CorrelationTable):
    """Correlation table used while replaying.

    Symbols are bound lazily when recorded responses are materialized. The
    generated values are obviously fake and unique per run.
    """

    def __init__(self, source):
        super().__init__()
        self._source = source
        self._counters = {}

    def mint(self, symbol):
        if symbol in self.bindings:
            return self.bindings[symbol]
        index = self._counters.get(symbol, 0) + 1
        self._counters[symbol] = index
        value = f"REPLAY-{symbol.upper()}-{self._source}-{index}"
        self.register(symbol, value)
        return value

    def bind_slot(self, symbol, value):
        """Replay-side correlation: unknown values are never auto-bound."""
        return self.resolve_incoming(value, f"slot:{symbol}")


def extract_json_path(data, path):
    """Return the value at a dotted JSON path (no arrays)."""
    current = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None, False
        current = current[part]
    return current, True


def set_json_path(data, path, value):
    parts = path.split(".")
    current = data
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def replace_occurrences(obj, old, new):
    """Deep-replace every occurrence of scalar ``old`` with ``new``."""
    if obj == old and not isinstance(obj, (dict, list)):
        return new
    if isinstance(obj, dict):
        return {key: replace_occurrences(value, old, new) for key, value in obj.items()}
    if isinstance(obj, list):
        return [replace_occurrences(item, old, new) for item in obj]
    return obj


_FINGERPRINT_RE = re.compile(r"^(?:SYNTHETIC|REPLAY|TEMP)-[A-Z0-9-]+$")


def looks_like_ephemeral(value):
    """Heuristic used only to flag unsymbolized synthetic ephemeral values
    in the validation leak scan (e.g. ``SYNTHETIC-SESSION-7``).

    Stable business identifiers such as ``SYN-1`` deliberately do not match:
    correlation correctness is also checked deterministically against the
    policy's declared correlation slots.
    """
    return isinstance(value, str) and bool(_FINGERPRINT_RE.match(value))
