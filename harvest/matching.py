"""Content-based request matching.

Requests are never matched by arrival order: pagination and detail calls
interleave concurrently. A match key is built from the source, HTTP method,
path, *significant* query parameters and the canonical structured body.
Correlation slots are symbolized first, so a replay with freshly minted
session values still matches the recorded exchange.
"""

import json
from urllib.parse import parse_qsl, urlsplit


def _canonical(value):
    """Stable, whitespace-free JSON encoding for dict/list values."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def split_url(url):
    parts = urlsplit(url)
    return parts.path, parse_qsl(parts.query, keep_blank_values=True)


def _symbolize_correlation(value, table, slot, location):
    """Replace a correlation slot value with its symbol.

    On the recording side unknown values are registered on first use; on the
    replay side an unknown value means the run never minted it.
    """
    if value is None:
        return value
    return table.bind_slot(slot, value)


def build_match_key(source, method, url, headers, body, policy, table):
    """Build the persistent match key for an outgoing request.

    ``table`` is a :class:`~harvest.correlation.CorrelationTable` whose
    behavior differs between recording and replay.
    """
    path, query_pairs = split_url(url)

    significant = []
    for key, value in query_pairs:
        if key in policy.ignored_query_params:
            continue
        if key in policy.redacted_query_params:
            significant.append((key, {"redacted": True}))
        elif key in policy.correlation_query:
            symbol = policy.correlation_query[key]
            significant.append((key, _symbolize_correlation(value, table, symbol, f"query:{key}")))
        else:
            significant.append((key, value))
    significant.sort(key=lambda pair: pair[0])

    safe_headers = {}
    for key, value in (headers or {}).items():
        lowered = key.lower()
        if lowered in policy.safe_header_keys:
            continue
        if lowered in policy.correlation_headers:
            symbol = policy.correlation_headers[lowered]
            value = _symbolize_correlation(value, table, symbol, f"header:{key}")
        safe_headers[key.lower()] = value

    symbolized_body = None
    if body is not None:
        symbolized_body = _symbolize_body(body, policy, table)

    key = {
        "source": source,
        "method": method.upper(),
        "path": path,
        "query": [[key, value] for key, value in significant],
        "headers": safe_headers,
        "body": _canonical(symbolized_body) if symbolized_body is not None else None,
    }
    return key


def _symbolize_body(body, policy, table):
    if isinstance(body, dict):
        result = {}
        for key, value in body.items():
            if key in policy.correlation_body and not isinstance(value, (dict, list)):
                symbol = policy.correlation_body[key]
                result[key] = _symbolize_correlation(value, table, symbol, f"body:{key}")
            else:
                result[key] = _symbolize_body(value, policy, table)
        return result
    if isinstance(body, list):
        return [_symbolize_body(item, policy, table) for item in body]
    return body


def key_fingerprint(key):
    """Short stable identifier for error messages and exchange filenames."""
    raw = f"{key['source']}|{key['method']}|{key['path']}|{_canonical(key['query'])}|{key['body'] or ''}"
    digest = 0
    for char in raw:
        digest = (digest * 131 + ord(char)) & 0xFFFFFFFF
    return f"{key['method'].lower()}-{key['path'].strip('/').replace('/', '-') or 'root'}-{digest:08x}"


def explain_differences(expected, actual):
    """Return a human-readable list of field-level differences."""
    diffs = []
    for field_name in ("method", "path"):
        if expected[field_name] != actual[field_name]:
            diffs.append(f"{field_name}: recorded={expected[field_name]!r} actual={actual[field_name]!r}")
    if expected["query"] != actual["query"]:
        diffs.append(
            "query differs: recorded="
            + _canonical(expected["query"])
            + " actual="
            + _canonical(actual["query"])
        )
    if expected["body"] != actual["body"]:
        diffs.append(
            "body differs: recorded=" + str(expected["body"]) + " actual=" + str(actual["body"])
        )
    if expected["headers"] != actual["headers"]:
        diffs.append("non-sensitive headers differ")
    return diffs


def similarity(expected, actual):
    """Rough 0..1 score used to pick the nearest candidate in error output."""
    score = 0
    total = 4
    if expected["method"] == actual["method"]:
        score += 1
    if expected["path"] == actual["path"]:
        score += 1
    if expected["query"] == actual["query"]:
        score += 1
    if expected["body"] == actual["body"]:
        score += 1
    return score / total


def symbolized_headers_for_storage(headers, policy, table):
    """Persist the non-redacted header set with correlation slots symbolized."""
    stored = {}
    for key, value in (headers or {}).items():
        lowered = key.lower()
        if lowered in policy.safe_header_keys:
            stored[key] = {"redacted": True}
        elif lowered in policy.correlation_headers:
            symbol = policy.correlation_headers[lowered]
            stored[key] = _symbolize_correlation(value, table, symbol, f"header:{key}")
        else:
            stored[key] = value
    return stored
