import json
import os
import tempfile
import unittest
from pathlib import Path

from harvest import (
    AttemptLimitError,
    Mode,
    SensitiveStructureError,
    SourcePolicy,
    UnknownRequestError,
    UnboundCorrelationError,
    UnusedExchangeError,
    cleanup_partial,
    open_transport,
    validate_pack,
)
from harvest.pack import load_manifest, load_pack
from offline_demo import (
    FIXTURE_TOKEN,
    LeakySource,
    SearchEnabledSource,
    build_incompatible_policy,
    build_policy,
    record_full_batch,
    run,
)
from synthetic_source import SyntheticSource


class HarvestTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.policy = build_policy()

    def tearDown(self):
        self._tmp.cleanup()

    def pack_path(self, name):
        return str(self.root / name)

    def read_exchanges(self, pack_dir):
        exchange_dir = Path(pack_dir) / "exchanges"
        return [json.loads(path.read_text()) for path in sorted(exchange_dir.iterdir())]

    def manifest(self, pack_dir):
        return json.loads((Path(pack_dir) / "manifest.json").read_text())


class RecordingTests(HarvestTestBase):
    def test_redacts_headers_contacts_and_download_credentials_before_disk(self):
        pack = self.pack_path("pack")
        record_full_batch(pack, generation=3)
        raw = "".join(path.read_text() for path in (Path(pack) / "exchanges").iterdir())
        self.assertNotIn("SYNTHETIC-NOT-A-SECRET", raw)
        self.assertNotIn("fictional-cookie", raw)

        exchanges = self.read_exchanges(pack)
        session_headers = exchanges[0]["request"]["headers"]
        self.assertEqual(session_headers["Authorization"], {"redacted": True})
        self.assertEqual(session_headers["Cookie"], {"redacted": True})
        # Redacted headers never participate in request matching.
        self.assertEqual(exchanges[0]["match_key"]["headers"], {})

        items = next(ex for ex in exchanges if ex["match_key"]["path"] == "/items"
                     and not ex["match_key"]["query"])
        self.assertEqual(
            items["response"]["json"]["items"][0]["contact"], {"redacted": True}
        )
        details = next(ex for ex in exchanges if ex["match_key"]["path"] == "/details/SYN-1")
        self.assertIn("signature=%5BREDACTED%5D",
                      details["response"]["json"]["download_url"])

    def test_unknown_sensitive_structure_fails_closed_and_writes_nothing_usable(self):
        pack = self.pack_path("leaky")
        with self.assertRaises(SensitiveStructureError) as caught:
            with open_transport(Mode.RECORD, self.policy, pack, inner=LeakySource(1)) as rec:
                rec.request("POST", "/session", headers={"Authorization": FIXTURE_TOKEN})
        self.assertIn("legacy_api_token", caught.exception.location)
        # The response is rejected, so only the earlier request material exists
        # and the pack never reaches the complete state.
        with self.assertRaises(Exception):
            load_manifest(pack)
        report = validate_pack(pack, self.policy)
        self.assertFalse(report["ok"])
        self.assertTrue(
            any("manifest" in err and "interrupted" in err for err in report["errors"])
        )

    def test_unknown_sensitive_query_parameter_is_rejected(self):
        pack = self.pack_path("url")
        with open_transport(
            Mode.RECORD, self.policy, pack, inner=SyntheticSource(1)
        ) as rec:
            with self.assertRaises(SensitiveStructureError):
                rec.request(
                    "GET",
                    "/items?api_token=SYNTHETIC-NOT-A-SECRET",
                    headers={"X-Session": "x"},
                )

    def test_insignificant_query_params_are_ignored_by_the_match_key(self):
        pack = self.pack_path("trace")
        with open_transport(
            Mode.RECORD, self.policy, pack, inner=SyntheticSource(1)
        ) as rec:
            session = rec.request(
                "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
            )["json"]["session"]
            rec.request("GET", "/items?trace_id=abc", headers={"X-Session": session})
        exchange = self.read_exchanges(pack)[1]
        self.assertEqual(exchange["match_key"]["query"], [])

    def test_duplicate_call_on_non_repeatable_endpoint_is_a_recording_error(self):
        pack = self.pack_path("dup")
        with open_transport(
            Mode.RECORD, self.policy, pack, inner=SyntheticSource(1)
        ) as rec:
            session = rec.request(
                "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
            )["json"]["session"]
            headers = {"X-Session": session}
            rec.request("GET", "/items", headers=headers)
            with self.assertRaises(Exception):
                rec.request("GET", "/items", headers=headers)

    def test_repeatable_endpoint_records_attempt_budget_in_one_file(self):
        pack = self.pack_path("rep")
        with open_transport(
            Mode.RECORD, self.policy, pack, inner=SyntheticSource(1)
        ) as rec:
            session = rec.request(
                "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
            )["json"]["session"]
            headers = {"X-Session": session}
            rec.request("GET", "/details/SYN-1", headers=headers)
            rec.request("GET", "/details/SYN-1", headers=headers)
            rec.request("GET", "/details/SYN-1", headers=headers)
        details = [
            ex for ex in self.read_exchanges(pack)
            if ex["match_key"]["path"] == "/details/SYN-1"
        ]
        self.assertEqual(len(details), 1)
        self.assertEqual(details[0]["attempts"], 3)
        self.assertTrue(details[0]["repeatable"])


class SymbolizationTests(HarvestTestBase):
    def test_pack_holds_symbols_not_raw_ephemeral_values(self):
        pack = self.pack_path("sym")
        record_full_batch(pack, generation=5)
        raw = "".join(path.read_text() for path in (Path(pack) / "exchanges").iterdir())
        self.assertNotIn("SYNTHETIC-SESSION-5", raw)
        self.assertNotIn("SYNTHETIC-CURSOR-5", raw)
        paged = next(
            ex for ex in self.read_exchanges(pack)
            if ex["match_key"]["path"] == "/items" and ex["match_key"]["query"]
        )
        self.assertEqual(paged["request"]["query"], [["cursor", {"symbol": "cursor"}]])
        self.assertEqual(paged["match_key"]["query"], [["cursor", {"symbol": "cursor"}]])
        self.assertIn("cursor=%7Bcursor%7D", paged["request"]["url"])
        # Ignored parameters are dropped from both the stored copy and the key.
        self.assertNotIn("trace_id", paged["request"]["url"])
        report = validate_pack(pack, self.policy)
        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual(report["summary"]["emitted_symbols"], ["cursor", "session"])

    def test_replay_mints_fresh_values_and_binds_later_requests(self):
        recorded = self.pack_path("a")
        record_full_batch(recorded, generation=1)
        with open_transport(Mode.REPLAY, self.policy, recorded) as replay:
            session = replay.request(
                "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
            )["json"]["session"]
            self.assertNotEqual(session, "SYNTHETIC-SESSION-1")
            self.assertTrue(session.startswith("REPLAY-SESSION-"))
            page = replay.request("GET", "/items", headers={"X-Session": session})
            cursor = page["json"]["next"]
            self.assertTrue(cursor.startswith("REPLAY-CURSOR-"))
            final = replay.request(
                "GET", f"/items?cursor={cursor}", headers={"X-Session": session}
            )
            self.assertIsNone(final["json"]["next"])
            replay.request(
                "POST", "/search", headers={"X-Session": session},
                body={"filter": "invoice", "size": 50},
            )
            replay.request("GET", "/details/SYN-1", headers={"X-Session": session})
            replay.request("GET", "/details/SYN-1", headers={"X-Session": session})

    def test_unbound_correlation_value_is_rejected_not_matched(self):
        recorded = self.pack_path("b")
        record_full_batch(recorded, generation=1)
        with open_transport(
            Mode.REPLAY, self.policy, recorded, strict=False
        ) as replay:
            with self.assertRaises(UnboundCorrelationError):
                replay.request("GET", "/items", headers={"X-Session": "NEVER-MINTED"})


class MatchingTests(HarvestTestBase):
    def _recorded_pack(self):
        pack = self.pack_path("m")
        record_full_batch(pack, generation=1)
        return pack

    def test_out_of_order_requests_match_by_content(self):
        pack = self._recorded_pack()
        with open_transport(Mode.REPLAY, self.policy, pack) as replay:
            session = replay.request(
                "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
            )["json"]["session"]
            headers = {"X-Session": session}
            page = replay.request("GET", "/items", headers=headers)
            cursor = page["json"]["next"]
            # Interleaved order: details and search before page two.
            self.assertEqual(
                replay.request("GET", "/details/SYN-1", headers=headers)["status"], 200
            )
            self.assertEqual(
                replay.request(
                    "POST", "/search", headers=headers,
                    body={"filter": "invoice", "size": 50},
                )["status"],
                200,
            )
            self.assertEqual(
                replay.request(
                    "GET", f"/items?cursor={cursor}", headers=headers
                )["status"],
                200,
            )
            replay.request("GET", "/details/SYN-1", headers=headers)

    def test_structured_body_distinguishes_requests(self):
        pack = self._recorded_pack()
        with open_transport(
            Mode.REPLAY, self.policy, pack, strict=False
        ) as replay:
            session = replay.request(
                "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
            )["json"]["session"]
            with self.assertRaises(UnknownRequestError) as caught:
                replay.request(
                    "POST", "/search", headers={"X-Session": session},
                    body={"filter": "profile", "size": 1},
                )
            explanation = str(caught.exception)
            self.assertIn("body differs", explanation)

    def test_unknown_request_fails_with_candidates_and_never_falls_back(self):
        pack = self._recorded_pack()
        replay = open_transport(Mode.REPLAY, self.policy, pack, strict=False)
        self.assertFalse(hasattr(replay, "inner"))
        with self.assertRaises(UnknownRequestError) as caught:
            replay.request("DELETE", "/items/SYN-1")
        self.assertTrue(caught.exception.nearest)
        self.assertIn("DELETE /items/SYN-1", str(caught.exception))

    def test_attempt_budget_distinguishes_retry_from_extra_call(self):
        pack = self._recorded_pack()
        with open_transport(
            Mode.REPLAY, self.policy, pack, strict=False
        ) as replay:
            session = replay.request(
                "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
            )["json"]["session"]
            headers = {"X-Session": session}
            replay.request("GET", "/details/SYN-1", headers=headers)
            replay.request("GET", "/details/SYN-1", headers=headers)
            with self.assertRaises(AttemptLimitError):
                replay.request("GET", "/details/SYN-1", headers=headers)

    def test_strict_replay_requires_every_recorded_exchange(self):
        pack = self._recorded_pack()
        with self.assertRaises(UnusedExchangeError):
            with open_transport(Mode.REPLAY, self.policy, pack) as replay:
                replay.request(
                    "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
                )


class InterruptionAndPolicyTests(HarvestTestBase):
    def test_interrupted_pack_is_unusable_and_cleanup_removes_it(self):
        pack = self.pack_path("half")
        transport = open_transport(
            Mode.RECORD, self.policy, pack, inner=SearchEnabledSource(1)
        )
        transport.request("POST", "/session", headers={"Authorization": FIXTURE_TOKEN})
        # Crash without close(): manifest remains complete=false.
        self.assertFalse(self.manifest(pack)["complete"])
        with self.assertRaises(Exception):
            load_manifest(pack)
        leftovers, incomplete = __import__(
            "harvest.pack", fromlist=["list_partial_artifacts"]
        ).list_partial_artifacts(pack)
        # No leftover tmp after a clean per-file write, but pack is incomplete.
        self.assertTrue(incomplete)
        self.assertEqual(leftovers, [])
        result = cleanup_partial(pack)
        self.assertEqual(result["action"], "removed-incomplete-pack")
        self.assertFalse(Path(pack).exists())

    def test_complete_pack_is_not_removed_by_cleanup(self):
        pack = self.pack_path("full")
        record_full_batch(pack, generation=1)
        result = cleanup_partial(pack)
        self.assertEqual(result["action"], "none")
        self.assertTrue(Path(pack).exists())
        manifest, exchanges = load_pack(pack, self.policy)
        self.assertTrue(manifest["complete"])
        self.assertEqual(len(exchanges), 5)

    def test_stray_temp_file_beside_complete_pack_is_removed_and_blocks_loading(self):
        from harvest.pack import load_manifest
        from harvest.errors import IncompletePackError

        pack = self.pack_path("stray")
        record_full_batch(pack, generation=1)
        stray = Path(pack) / "exchanges" / "9999-stray.json.tmp"
        stray.write_text("{\"interrupted\": true}")
        with self.assertRaises(IncompletePackError):
            load_manifest(pack)
        result = cleanup_partial(pack)
        self.assertEqual(result["action"], "removed-temp-files")
        self.assertFalse(stray.exists())
        # The complete pack itself stays intact and usable.
        self.assertTrue(load_manifest(pack)["complete"])

    def test_crash_during_exchange_write_leaves_temp_file_and_fails_closed(self):
        from harvest import pack as pack_module
        from harvest.errors import IncompletePackError

        pack = self.pack_path("crash")
        transport = open_transport(
            Mode.RECORD, self.policy, pack, inner=SyntheticSource(1)
        )

        def boom(_path, _text):
            raise OSError("simulated disk failure during atomic replace")

        original = pack_module.os.replace
        pack_module.os.replace = boom
        try:
            with self.assertRaises(OSError):
                transport.request(
                    "POST", "/session", headers={"Authorization": FIXTURE_TOKEN}
                )
        finally:
            pack_module.os.replace = original

        leftovers, incomplete = pack_module.list_partial_artifacts(pack)
        self.assertTrue(leftovers)
        self.assertTrue(incomplete)
        with self.assertRaises(IncompletePackError):
            load_manifest(pack)
        cleanup_partial(pack)
        self.assertFalse(Path(pack).exists())

    def test_policy_upgrade_rejects_old_pack_when_version_not_accepted(self):
        pack = self.pack_path("old")
        record_full_batch(pack, generation=1)
        compatible = build_policy(
            version="synthetic-v2", accepts=("synthetic-v1", "synthetic-v2")
        )
        self.assertTrue(validate_pack(pack, compatible)["ok"])
        incompatible = build_incompatible_policy()
        report = validate_pack(pack, incompatible)
        self.assertFalse(report["ok"])
        self.assertTrue(any("does not accept" in err for err in report["errors"]))

    def test_hash_tampering_is_detected(self):
        pack = self.pack_path("tamper")
        record_full_batch(pack, generation=1)
        exchange = next((Path(pack) / "exchanges").iterdir())
        payload = json.loads(exchange.read_text())
        payload["response"]["status"] = 500
        exchange.write_text(json.dumps(payload))
        report = validate_pack(pack, self.policy)
        self.assertTrue(any("hash mismatch" in err for err in report["errors"]))


class VerifyOnlyTests(HarvestTestBase):
    def test_verify_transport_never_executes_requests(self):
        pack = self.pack_path("v")
        record_full_batch(pack, generation=1)
        verifier = open_transport(Mode.VERIFY, self.policy, pack)
        self.assertTrue(verifier.ok)
        with self.assertRaises(RuntimeError):
            verifier.request("GET", "/items")
        verifier.close()


class DemoTests(unittest.TestCase):
    def test_full_demo_report_satisfies_every_scenario(self):
        report = run()
        self.assertTrue(report["1_recording"]["secret_absent_from_disk"])
        self.assertTrue(report["1_recording"]["contact_redacted_on_disk"])
        self.assertTrue(report["1_recording"]["verify"])
        self.assertNotEqual(
            report["2_session_values_change"]["recorded_session"],
            report["2_session_values_change"]["replayed_session"],
        )
        self.assertTrue(
            report["2_session_values_change"]["final_page_next_is_none"]
        )
        self.assertEqual(
            report["3_out_of_order_replay"]["statuses_in_arrival_order"],
            [200, 200, 200],
        )
        self.assertIn(
            "legacy_api_token", report["4_sensitive_structure_rejected"]["failure"]["location"]
        )
        self.assertEqual(
            report["4_sensitive_structure_rejected"]["partial_material_cleaned"],
            "removed-incomplete-pack",
        )
        self.assertIn("attempt limit", report["5_attempt_budgets"]["third_call"])
        self.assertIn("no recorded exchange matches", report["6_unknown_request_explained"]["message"])
        self.assertTrue(
            report["7_interrupted_recording"]["directory_gone_after_cleanup"]
        )
        self.assertTrue(report["8_policy_upgrade"]["compatible_policy_verifies"])
        self.assertTrue(report["8_policy_upgrade"]["incompatible_policy_errors"])
        self.assertIn("strict replay", report["9_strict_unused_exchange"])
        self.assertTrue(report["10_verify_only"]["ok"])

    def test_demo_cli_runs_offline_and_prints_the_same_report(self):
        import subprocess
        import sys

        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "offline_demo.py"],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        cli_report = json.loads(result.stdout)
        self.assertEqual(set(cli_report), set(run()))


if __name__ == "__main__":
    unittest.main()
