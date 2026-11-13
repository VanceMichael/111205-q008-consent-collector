"""Deterministic hash of the sanitizing rule set carried by a policy."""

import hashlib
import json


def compute_rules_hash(policy):
    rules = {
        "redacted_body_keys": sorted(policy.redacted_body_keys),
        "redacted_header_keys": sorted(policy.redacted_header_keys),
        "redacted_query_params": sorted(policy.redacted_query_params),
        "ignored_query_params": sorted(policy.ignored_query_params),
        "correlation_headers": dict(sorted(policy.correlation_headers.items())),
        "correlation_query": dict(sorted(policy.correlation_query.items())),
        "correlation_body": dict(sorted(policy.correlation_body.items())),
        "emitters": sorted((e.path, e.symbol) for e in policy.emitters),
        "repeatable_endpoints": sorted(policy.repeatable_endpoints),
    }
    encoded = json.dumps(rules, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
