"""Verify-only transport.

Never serves, records or sends anything: it opens a pack, runs the full
offline validation (completeness, hashes, leak scan, symbol linkage and
current-policy compatibility) and produces an explainable report.
"""

from .pack import validate_pack


class VerifyTransport:
    mode = "verify"

    def __init__(self, pack_dir, policy):
        self.pack_dir = pack_dir
        self.policy = policy
        self.report = validate_pack(pack_dir, policy)

    @property
    def ok(self):
        return self.report["ok"]

    def request(self, *_args, **_kwargs):
        raise RuntimeError("verify-only transport never executes requests")

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        return False
