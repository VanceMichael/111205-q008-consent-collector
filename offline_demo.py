"""End-to-end offline demonstration of the harvest transport adapter.

All subjects, tokens and URLs are fictional. The synthetic source
(:class:`synthetic_source.SyntheticSource`) never opens a socket; the replay
transport has no network code path at all.

Scenarios demonstrated:

1. policy-driven recording with redaction of auth headers, cookies,
   contact fields and download-URL credentials;
2. session/cursor values changing between runs while the linkage survives
   symbolization (no run needs to reproduce the same temporary value);
3. out-of-order, concurrently interleaved requests replayed by content
   matching rather than arrival order;
4. fail-closed rejection of an unrecognized sensitive structure;
5. retries versus legitimate repeated calls under recorded attempt budgets;
6. an explainable unknown-request failure that never reaches the network;
7. interrupted-recording detection and cleanup;
8. policy-upgrade compatibility reporting for old material.
"""

import json
import tempfile
from pathlib import Path

from harvest import (
    AttemptLimitError,
    Mode,
    SensitiveStructureError,
    SourcePolicy,
    UnknownRequestError,
    UnusedExchangeError,
    cleanup_partial,
    open_transport,
    validate_pack,
)
from harvest.pack import load_manifest
from synthetic_source import SyntheticSource

FIXTURE_TOKEN = "Bearer SYNTHETIC-NOT-A-SECRET"


# ---------------------------------------------------------------------------
# Demo helpers: thin wrappers around the shared synthetic source. The shared
# source stays untouched so the existing baseline tests remain valid.
# ---------------------------------------------------------------------------


class SearchEnabledSource(SyntheticSource):
    """Adds a structured-body search endpoint used for body matching."""

    def request(self, method, url, headers=None, body=None):
        from urllib.parse import urlsplit

        if method == "POST" and urlsplit(url).path == "/search":
            return {"status": 200, "json": {"query": (body or {}).get("filter"), "ids": ["SYN-1"]}}
        return super().request(method, url, headers, body)


class LeakySource(SearchEnabledSource):
    """Returns a response containing an unknown sensitive-looking field."""

    def request(self, method, url, headers=None, body=None):
        response = super().request(method, url, headers, body)
        if response.get("status") == 200 and isinstance(response.get("json"), dict):
            response["json"]["legacy_api_token"] = "SYNTHETIC-NOT-A-SECRET"
        return response


# ---------------------------------------------------------------------------
# Policies. v2 is a compatible refinement; v3 changes the rule set and no
# longer accepts v1 packs, so old material must be re-recorded.
# ---------------------------------------------------------------------------


def build_policy(version="synthetic-v1", accepts=("synthetic-v1",)):
    return SourcePolicy.create(
        source="ledger",
        policy_version=version,
        accepts_versions=set(accepts),
        redacted_body_keys={"contact"},
        redacted_header_keys={"cookie"},
        redacted_query_params={"signature"},
        ignored_query_params={"trace_id"},
        emitters=[
            {"path": "session", "symbol": "session"},
            {"path": "next", "symbol": "cursor"},
        ],
        correlation_headers={"x-session": "session"},
        correlation_query={"cursor": "cursor"},
        correlation_body={},
        repeatable_endpoints={("GET", "/details/SYN-1")},
    )


def build_incompatible_policy():
    policy = build_policy(version="synthetic-v3", accepts=("synthetic-v3",))
    # A rules upgrade: a new field is now redacted, changing the rule set.
    object.__setattr__(policy, "redacted_body_keys", frozenset({"contact", "national_id"}))
    from harvest.rules import compute_rules_hash

    object.__setattr__(policy, "rules_hash", compute_rules_hash(policy))
    return policy


def record_full_batch(pack_dir, generation):
    """Record one realistic batch: session, paging, details and a search."""
    policy = build_policy()
    source = SearchEnabledSource(generation)
    with open_transport(Mode.RECORD, policy, pack_dir, inner=source) as transport:
        session = transport.request(
            "POST",
            "/session",
            headers={"Authorization": FIXTURE_TOKEN, "Cookie": "sid=fictional-cookie"},
        )["json"]["session"]
        headers = {"X-Session": session, "Cookie": "sid=fictional-cookie"}

        first_page = transport.request("GET", "/items?trace_id=noise-1", headers=headers)
        cursor = first_page["json"]["next"]
        second_page = transport.request(
            "GET", f"/items?cursor={cursor}&trace_id=noise-2", headers=headers
        )
        assert second_page["json"]["next"] is None

        transport.request("POST", "/search", headers=headers, body={"filter": "invoice", "size": 50})
        # A legitimate repeated call against a repeatable endpoint (retry #1
        # of the same detail fetch, e.g. after a transient timeout).
        transport.request("GET", "/details/SYN-1", headers=headers)
        transport.request("GET", "/details/SYN-1", headers=headers)
    return policy


def run():
    report = {}
    workspace = tempfile.mkdtemp(prefix="harvest-demo-")
    root = Path(workspace)

    # -- 1. recording with full sanitization --------------------------------
    recorded_pack = root / "recorded"
    policy = record_full_batch(str(recorded_pack), generation=1)
    stored_items_exchange = json.loads(
        (recorded_pack / "exchanges" / "0002-get-items-9cafba28.json").read_text()
    )
    stored_details_exchange = json.loads(
        (recorded_pack / "exchanges" / "0005-get-details-SYN-1-6e169b7f.json").read_text()
    )
    on_disk = json.dumps(
        [p.read_text() for p in sorted((recorded_pack / "exchanges").iterdir())]
    )
    report["1_recording"] = {
        "pack_dir": str(recorded_pack),
        "exchange_files": sorted(p.name for p in (recorded_pack / "exchanges").iterdir()),
        "secret_absent_from_disk": "SYNTHETIC-NOT-A-SECRET" not in on_disk,
        "cookie_absent_from_disk": "fictional-cookie" not in on_disk,
        "contact_redacted_on_disk": stored_items_exchange["response"]["json"]["items"][0]["contact"]
        == {"redacted": True},
        "stored_headers": stored_items_exchange["request"]["headers"],
        "download_credential_redacted": "signature=%5BREDACTED%5D" in on_disk,
        "stored_download_url": stored_details_exchange["response"]["json"]["download_url"],
        "verify": validate_pack(str(recorded_pack), policy)["ok"],
    }

    # -- 2. session values change across runs but linkage survives ----------
    # A different source generation produces entirely different temporary
    # values; replay must still bind every request to the right response.
    replay_pack = root / "replay"
    replay_policy = record_full_batch(str(replay_pack), generation=2)
    recorded_session = SearchEnabledSource(1).session
    replayed_values = {}
    with open_transport(Mode.REPLAY, replay_policy, str(replay_pack)) as replay:
        session_resp = replay.request(
            "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
        )
        new_session = session_resp["json"]["session"]
        headers = {"X-Session": new_session}
        page = replay.request("GET", "/items?trace_id=different-noise", headers=headers)
        new_cursor = page["json"]["next"]
        final = replay.request(
            "GET", f"/items?cursor={new_cursor}", headers=headers
        )
        # Exercise the remaining recorded endpoints so strict close passes.
        replay.request("POST", "/search", headers=headers, body={"filter": "invoice", "size": 50})
        replay.request("GET", "/details/SYN-1", headers=headers)
        replay.request("GET", "/details/SYN-1", headers=headers)
        replayed_values = {
            "recorded_session": recorded_session,
            "replayed_session": new_session,
            "replayed_cursor": new_cursor,
            "final_page_next_is_none": final["json"]["next"] is None,
        }
    report["2_session_values_change"] = replayed_values

    # -- 3. out-of-order interleaved requests -------------------------------
    order_evidence = []
    replayed_detail = None
    with open_transport(Mode.REPLAY, build_policy(), str(recorded_pack)) as replay:
        session = replay.request("POST", "/session", headers={"Authorization": FIXTURE_TOKEN})[
            "json"
        ]["session"]
        headers = {"X-Session": session}
        page = replay.request("GET", "/items?trace_id=x", headers=headers)
        cursor = page["json"]["next"]
        # Detail and search requests arrive before the second page is fetched,
        # i.e. in a different order than they were recorded.
        replayed_detail = replay.request("GET", "/details/SYN-1", headers=headers)
        order_evidence.append(replayed_detail["status"])
        order_evidence.append(
            replay.request("POST", "/search", headers=headers, body={"filter": "invoice", "size": 50})[
                "status"
            ]
        )
        order_evidence.append(
            replay.request("GET", f"/items?cursor={cursor}", headers=headers)["status"]
        )
        # The repeatable endpoint has budget 2; use the remaining attempt so
        # strict close succeeds.
        replay.request("GET", "/details/SYN-1", headers=headers)
    report["3_out_of_order_replay"] = {
        "statuses_in_arrival_order": order_evidence,
        "replayed_detail_body": replayed_detail["json"],
    }

    # -- 4. unknown sensitive structure is refused before writing -----------
    rejected_pack = root / "rejected"
    rejection = None
    try:
        with open_transport(
            Mode.RECORD, build_policy(), str(rejected_pack), inner=LeakySource(1)
        ) as transport:
            transport.request("POST", "/session", headers={"Authorization": FIXTURE_TOKEN})
    except SensitiveStructureError as exc:
        rejection = {"location": exc.location, "reason": exc.reason}
    report["4_sensitive_structure_rejected"] = {
        "failure": rejection,
        "pack_left_incomplete": not load_manifest_safe(str(rejected_pack)),
        "partial_material_cleaned": cleanup_partial(str(rejected_pack))["action"],
    }

    # -- 5. retries vs legitimate repeated calls ----------------------------
    # strict=False keeps the focus on attempt budgets; strict coverage is
    # demonstrated separately in scenario 9.
    retry_outcome = {}
    with open_transport(Mode.REPLAY, build_policy(), str(recorded_pack), strict=False) as replay:
        session = replay.request("POST", "/session", headers={"Authorization": FIXTURE_TOKEN})[
            "json"
        ]["session"]
        headers = {"X-Session": session}
        replay.request("GET", "/details/SYN-1", headers=headers)
        replay.request("GET", "/details/SYN-1", headers=headers)  # recorded budget = 2
        try:
            replay.request("GET", "/details/SYN-1", headers=headers)  # third call
        except AttemptLimitError as exc:
            retry_outcome["third_call"] = str(exc)
        try:
            # A non-repeatable endpoint may not be called twice at all.
            replay.request("GET", "/items?trace_id=z", headers=headers)
            replay.request("GET", "/items?trace_id=z", headers=headers)
        except AttemptLimitError as exc:
            retry_outcome["non_repeatable_second_call"] = str(exc)
    report["5_attempt_budgets"] = retry_outcome

    # -- 6. explainable unknown-request failure, never reaches the network --
    unknown_outcome = {}
    with open_transport(Mode.REPLAY, build_policy(), str(recorded_pack), strict=False) as replay:
        try:
            replay.request("DELETE", "/items/SYN-1")
        except UnknownRequestError as exc:
            unknown_outcome["message"] = str(exc)
            unknown_outcome["nearest_candidates"] = exc.nearest[:2]
        # A structured-body mismatch is also content-based and explainable.
        session = replay.request("POST", "/session", headers={"Authorization": FIXTURE_TOKEN})[
            "json"
        ]["session"]
        try:
            replay.request(
                "POST", "/search", headers={"X-Session": session}, body={"filter": "profile", "size": 1}
            )
        except UnknownRequestError as exc:
            unknown_outcome["body_mismatch"] = exc.nearest[0]
    report["6_unknown_request_explained"] = unknown_outcome

    # -- 7. interrupted recording is never treated as a complete scenario ---
    interrupted = root / "interrupted"
    policy_v1 = build_policy()
    transport = open_transport(
        Mode.RECORD, policy_v1, str(interrupted), inner=SearchEnabledSource(1)
    )
    transport.request("POST", "/session", headers={"Authorization": FIXTURE_TOKEN})
    # Simulate a crash: close() is never called, so the manifest stays
    # complete=false and temp material remains on disk.
    verify_report = validate_pack(str(interrupted), policy_v1)
    cleanup_report = cleanup_partial(str(interrupted))
    report["7_interrupted_recording"] = {
        "validation_errors": verify_report["errors"],
        "cleanup": cleanup_report,
        "directory_gone_after_cleanup": not interrupted.exists(),
    }

    # -- 8. policy upgrade decides whether old material is reusable ---------
    compatible = build_policy(version="synthetic-v2", accepts=("synthetic-v1", "synthetic-v2"))
    incompatible = build_incompatible_policy()
    report["8_policy_upgrade"] = {
        "compatible_policy_verifies": validate_pack(str(recorded_pack), compatible)["ok"],
        "incompatible_policy_errors": validate_pack(str(recorded_pack), incompatible)["errors"],
    }

    # -- 9. strict replay flags an unused recorded exchange ------------------
    strict_outcome = None
    try:
        with open_transport(Mode.REPLAY, build_policy(), str(recorded_pack)) as replay:
            replay.request("POST", "/session", headers={"Authorization": FIXTURE_TOKEN})
            # close without exercising the remaining exchanges
    except UnusedExchangeError as exc:
        strict_outcome = str(exc)
    report["9_strict_unused_exchange"] = strict_outcome

    # -- 10. verify-only mode serves nothing --------------------------------
    verifier = open_transport(Mode.VERIFY, build_policy(), str(recorded_pack))
    report["10_verify_only"] = {
        "ok": verifier.ok,
        "summary": verifier.report["summary"],
    }
    verifier.close()

    return report


def load_manifest_safe(pack_dir):
    try:
        return load_manifest(pack_dir)
    except Exception:
        return None


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
