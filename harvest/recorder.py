"""Recording transport.

The recorder sits in the transport-adapter layer in front of the real
client transport. Every request/response pair is sanitized under the source
policy before touching disk; unrecognized sensitive structures abort the
packet. Ephemeral values are symbolized so the pack stays valid across runs
that generate different temporary values.
"""

from urllib.parse import urlencode, urlunsplit

from .correlation import (
    CorrelationTable,
    extract_json_path,
    replace_occurrences,
)
from .errors import RecordingError, SensitiveStructureError
from .matching import (
    build_match_key,
    key_fingerprint,
    split_url,
    symbolized_headers_for_storage,
)
from .pack import PackWriter
from .policy import sanitize_headers, sanitize_json_body


class RecordingTransport:
    def __init__(self, inner, policy, pack_dir):
        self.inner = inner
        self.policy = policy
        self.writer = PackWriter(pack_dir, policy)
        self.table = CorrelationTable()
        self._by_fingerprint = {}
        self.closed = False
        self.pack_dir = self.writer.pack_dir

    # -- public API ---------------------------------------------------------

    def request(self, method, url, headers=None, body=None):
        if self.closed:
            raise RecordingError("recording transport is already closed")
        headers = dict(headers or {})
        method = method.upper()

        # Fail closed before any disk write when the policy cannot classify
        # the structure or the URL carries undeclared credentials.
        self._guard_request(url, headers, body)
        match_key = build_match_key(
            self.policy.source, method, url, headers, body, self.policy, self.table
        )
        fingerprint = key_fingerprint(match_key)

        response = self.inner.request(method, url, headers=headers, body=body)
        stored_response, emits = self._sanitize_response(response)

        exchange = self._build_exchange(
            method, url, headers, body, match_key, fingerprint, response, stored_response, emits
        )
        self._store(fingerprint, exchange)
        return response

    def close(self):
        if self.closed:
            return
        self.writer.finish()
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _exc, _tb):
        # On a clean exit finalize; on failure leave the pack visibly
        # incomplete (complete=false) so cleanup tooling can identify it.
        if exc_type is None:
            self.close()
        return False

    # -- internals ----------------------------------------------------------

    def _guard_request(self, url, headers, body):
        self.policy.check_url_safety(url, "request.url")
        for key in headers:
            lowered = key.lower()
            if any(
                hint in lowered for hint in ("token", "secret", "password", "cookie", "auth")
            ) and lowered not in self.policy.safe_header_keys:
                raise SensitiveStructureError(
                    f"header:{key}", "sensitive header is not covered by the policy"
                )
        if isinstance(body, (dict, list)):
            self.policy.fail_on_unknown_sensitive_structure(body, "request.body")

    def _sanitize_response(self, response):
        status = response.get("status")
        payload = response.get("json")
        if payload is not None and not isinstance(payload, (dict, list)):
            raise SensitiveStructureError("response.json", "response body is not structured JSON")
        if isinstance(payload, (dict, list)):
            self.policy.fail_on_unknown_sensitive_structure(payload, "response.body")
        sanitized = sanitize_json_body(payload, self.policy) if isinstance(payload, (dict, list)) else payload

        emits = []
        if isinstance(sanitized, dict):
            for emitter in self.policy.emitters:
                value, found = extract_json_path(sanitized, emitter.path)
                if not found or isinstance(value, (dict, list)) or value is None:
                    continue
                marker = self.table.register(emitter.symbol, value)
                # Replace every occurrence, including values outside the
                # canonical emitter path (e.g. download signatures).
                sanitized = replace_occurrences(sanitized, value, marker)
                emits.append(emitter.symbol)
        return {"status": status, "json": sanitized}, emits

    def _build_exchange(self, method, url, headers, body, match_key, fingerprint, response, stored_response, emits):
        path, _query_pairs = split_url(url)
        # The match key already carries the sanitized, symbolized query;
        # reuse it so raw ephemeral values never appear in the stored copy.
        safe_query = [(key, value) for key, value in match_key["query"]]
        stored_headers = symbolized_headers_for_storage(headers, self.policy, self.table)
        safe_headers, _removed = sanitize_headers(stored_headers, self.policy)

        def _display(value):
            if isinstance(value, dict):
                if value.get("redacted"):
                    return "[REDACTED]"
                if "symbol" in value:
                    return "{" + value["symbol"] + "}"
            return value

        display_query = [(key, _display(value)) for key, value in safe_query]
        safe_url = urlunsplit(("", "", path, urlencode(display_query, doseq=True), ""))
        stored_body = None
        if body is not None:
            stored_body = sanitize_json_body(body, self.policy)

        return {
            "fingerprint": fingerprint,
            "match_key": match_key,
            "request": {
                "method": method,
                "url": safe_url,
                "path": path,
                "query": [[key, value] for key, value in safe_query],
                "headers": safe_headers,
                "body": stored_body,
            },
            "response": stored_response,
            "emits": sorted(set(emits)),
            "recorded_at": response.get("recorded_at"),
            "repeatable": self.policy.is_repeatable(method, path),
            "attempts": 1,
        }

    def _store(self, fingerprint, exchange):
        existing = self._by_fingerprint.get(fingerprint)
        if existing is not None:
            if not existing["repeatable"]:
                raise RecordingError(
                    f"duplicate call for non-repeatable endpoint {exchange['request']['method']} "
                    f"{exchange['request']['path']}: declare it repeatable in the policy or fix the client"
                )
            existing["attempts"] += 1
            # Keep one canonical exchange file per match key carrying the
            # total observed attempt budget.
            self.writer.upsert_exchange(existing)
            return
        self._by_fingerprint[fingerprint] = exchange
        self.writer.upsert_exchange(exchange)
