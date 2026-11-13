"""Strict offline replay transport.

The replayer owns no network client at all: an unknown request raises
:class:`UnknownRequestError` instead of reaching the public internet.
Matching is content-based, so concurrently interleaved pagination and
detail requests replay in any order. Each recorded exchange carries an
attempt budget that distinguishes retries from genuine repeated calls.
"""

import os

from .correlation import ReplayCorrelationTable, is_symbol_ref
from .errors import (
    AttemptLimitError,
    IncompletePackError,
    UnknownRequestError,
    UnusedExchangeError,
)
from .matching import build_match_key, explain_differences, key_fingerprint, similarity
from .pack import _read_json, ensure_policy_accepts, load_manifest


class ReplayTransport:
    def __init__(self, pack_dir, policy, strict=True):
        self.pack_dir = os.path.abspath(pack_dir)
        self.policy = policy
        self.strict = strict
        self.table = ReplayCorrelationTable(policy.source)
        manifest = load_manifest(pack_dir)
        ensure_policy_accepts(manifest, policy)
        self.manifest = manifest
        self._exchanges = []
        for entry in manifest["exchanges"]:
            exchange = _read_json(os.path.join(pack_dir, entry["file"]))
            self._exchanges.append(
                {
                    "exchange": exchange,
                    "fingerprint": exchange["fingerprint"],
                    "limit": exchange["attempts"],
                    "consumed": 0,
                }
            )
        self._index = {item["fingerprint"]: item for item in self._exchanges}
        self.closed = False

    def request(self, method, url, headers=None, body=None):
        if self.closed:
            raise IncompletePackError("replay transport is already closed")
        headers = headers or {}
        key = build_match_key(
            self.policy.source, method.upper(), url, headers, body, self.policy, self.table
        )
        item = self._index.get(key_fingerprint(key))
        if item is None:
            raise UnknownRequestError(key, self._nearest(key))
        if item["consumed"] >= item["limit"]:
            raise AttemptLimitError(key, item["consumed"], item["limit"])
        item["consumed"] += 1
        return self._materialize_response(item["exchange"]["response"])

    def close(self):
        if self.closed:
            return
        if self.strict:
            unused = [
                item["fingerprint"]
                for item in self._exchanges
                if item["consumed"] == 0
            ]
            if unused:
                raise UnusedExchangeError(
                    "strict replay did not exercise every recorded exchange: " + ", ".join(unused)
                )
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _exc, _tb):
        if exc_type is None:
            self.close()
        return False

    # -- internals ----------------------------------------------------------

    def _nearest(self, actual_key):
        ranked = []
        for item in self._exchanges:
            expected = item["exchange"]["match_key"]
            ranked.append((similarity(expected, actual_key), expected, item))
        ranked.sort(key=lambda row: row[0], reverse=True)
        lines = []
        for score, expected, item in ranked[:3]:
            diffs = explain_differences(expected, actual_key)
            lines.append(
                f"candidate {expected['method']} {expected['path']} "
                f"(similarity {score:.2f}, used {item['consumed']}/{item['limit']})"
                + (": " + "; ".join(diffs) if diffs else ": matches structurally")
            )
        return lines

    def _materialize_response(self, recorded):
        return {
            "status": recorded["status"],
            "json": _materialize(recorded["json"], self.table),
        }


def _materialize(node, table):
    if is_symbol_ref(node):
        return table.mint(node["symbol"])
    if isinstance(node, dict):
        if node.get("redacted") is True and len(node) == 1:
            return {"redacted": True}
        return {key: _materialize(value, table) for key, value in node.items()}
    if isinstance(node, list):
        return [_materialize(item, table) for item in node]
    return node
