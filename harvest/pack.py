"""On-disk pack format, atomic writing and validation.

A pack directory contains::

    manifest.json            # inventory, policy id, completion flag, hashes
    exchanges/0001-*.json    # one sanitized, symbolized exchange
    exchanges/*.tmp          # leftovers of a crash (never loaded)

Writes are atomic per file (temp file + ``os.replace``). The manifest is
rewritten after every finalized exchange with ``complete: false`` and only
flipped to ``complete: true`` when the recording is closed normally. Half
written material therefore always fails closed.
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from .correlation import is_symbol_ref, looks_like_ephemeral
from .errors import IncompletePackError, PackValidationError, PolicyCompatibilityError

MANIFEST_NAME = "manifest.json"
EXCHANGE_DIR = "exchanges"
SCHEMA = "harvest-pack/1"
RAW_SECRET_FRAGMENTS = (
    "SYNTHETIC-NOT-A-SECRET",
    "BEARER ",
)


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _write_json_atomic(path, payload):
    _atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


class PackWriter:
    """Incrementally records exchanges into a pack directory."""

    def __init__(self, pack_dir, policy):
        self.pack_dir = os.path.abspath(pack_dir)
        self.policy = policy
        self.exchange_dir = os.path.join(self.pack_dir, EXCHANGE_DIR)
        self.manifest_path = os.path.join(self.pack_dir, MANIFEST_NAME)
        os.makedirs(self.exchange_dir, exist_ok=True)
        if os.path.exists(self.manifest_path):
            manifest = _read_json(self.manifest_path)
            if manifest.get("complete"):
                raise IncompletePackError(
                    f"{self.pack_dir} already contains a complete pack; refuse to overwrite it"
                )
        self.entries = []
        self._flush_manifest(complete=False)

    def write_exchange(self, exchange):
        index = len(self.entries) + 1
        fingerprint = exchange["fingerprint"]
        name = f"{index:04d}-{fingerprint}.json"
        target = os.path.join(self.exchange_dir, name)
        text = json.dumps(exchange, ensure_ascii=False, indent=2, sort_keys=True)
        _atomic_write(target, text)
        self.entries.append(
            {"file": f"{EXCHANGE_DIR}/{name}", "sha256": _sha256_text(text), "fingerprint": fingerprint}
        )
        # Make every finalized exchange recoverable: the manifest on disk
        # always reflects exactly the completed files.
        self._flush_manifest(complete=False)
        return target

    def upsert_exchange(self, exchange):
        """Create one exchange file per match key, updating it on repeats.

        The attempt budget (``exchange['attempts']``) therefore lives in a
        single file instead of in arrival-ordered duplicate files.
        """
        fingerprint = exchange["fingerprint"]
        for position, entry in enumerate(self.entries):
            if entry["fingerprint"] == fingerprint:
                target = os.path.join(self.pack_dir, entry["file"])
                text = json.dumps(exchange, ensure_ascii=False, indent=2, sort_keys=True)
                _atomic_write(target, text)
                self.entries[position] = {
                    "file": entry["file"],
                    "sha256": _sha256_text(text),
                    "fingerprint": fingerprint,
                }
                self._flush_manifest(complete=False)
                return target
        return self.write_exchange(exchange)

    def _flush_manifest(self, complete):
        manifest = {
            "schema": SCHEMA,
            "source": self.policy.source,
            "policy_version": self.policy.policy_version,
            "rules_hash": self.policy.rules_hash,
            "created_at": _utc_now(),
            "complete": complete,
            "exchange_count": len(self.entries),
            "exchanges": self.entries,
        }
        _write_json_atomic(self.manifest_path, manifest)

    def finish(self):
        self._flush_manifest(complete=True)
        return self.manifest_path


def list_partial_artifacts(pack_dir):
    """Return temp files and incomplete-pack markers left by a crash."""
    leftovers = []
    for root, _dirs, files in os.walk(pack_dir):
        for name in files:
            if name.endswith(".tmp"):
                leftovers.append(os.path.join(root, name))
    manifest = os.path.join(pack_dir, MANIFEST_NAME)
    incomplete = os.path.exists(manifest) and not _read_json(manifest).get("complete", False)
    return sorted(leftovers), incomplete


def cleanup_partial(pack_dir):
    """Remove interrupted recording material.

    A complete pack is never touched. For an incomplete pack the whole
    directory is removed; stray temp files next to a complete pack are
    removed individually. Returns an explainable cleanup report.
    """
    if not os.path.isdir(pack_dir):
        return {"action": "none", "reason": "directory does not exist", "removed": []}
    leftovers, incomplete = list_partial_artifacts(pack_dir)
    removed = []
    if incomplete:
        for root, dirs, files in os.walk(pack_dir, topdown=False):
            for name in files:
                removed.append(os.path.join(root, name))
            for name in dirs:
                removed.append(os.path.join(root, name))
        removed.append(os.path.abspath(pack_dir))
        import shutil

        shutil.rmtree(pack_dir)
        return {"action": "removed-incomplete-pack", "removed": sorted(removed)}
    for leftover in leftovers:
        os.remove(leftover)
        removed.append(leftover)
    return {
        "action": "removed-temp-files" if removed else "none",
        "reason": "pack is complete" if not leftovers else "",
        "removed": removed,
    }


def load_manifest(pack_dir):
    manifest_path = os.path.join(pack_dir, MANIFEST_NAME)
    if not os.path.exists(manifest_path):
        raise IncompletePackError(f"{pack_dir} has no manifest; the recording never finalized")
    manifest = _read_json(manifest_path)
    if not manifest.get("complete"):
        raise IncompletePackError(
            f"{pack_dir} manifest is marked incomplete; a crashed recording is not a usable scenario"
        )
    leftovers, _ = list_partial_artifacts(pack_dir)
    if leftovers:
        raise IncompletePackError(f"{pack_dir} still contains temp files: {leftovers}")
    return manifest


def load_pack(pack_dir, policy=None):
    """Load a complete pack, optionally enforcing current-policy reuse."""
    report = validate_pack(pack_dir, policy)
    if report["errors"]:
        raise PackValidationError(report["errors"])
    manifest = _read_json(os.path.join(pack_dir, MANIFEST_NAME))
    exchanges = [
        _read_json(os.path.join(pack_dir, entry["file"])) for entry in manifest["exchanges"]
    ]
    return manifest, exchanges


def validate_pack(pack_dir, policy=None):
    """Validate a pack without serving any request (verify-only foundation).

    Returns a structured report; never raises for content problems so callers
    can present every reason at once. Structural access problems are reported
    as errors too.
    """
    report = {"pack": os.path.abspath(pack_dir), "ok": False, "errors": [], "warnings": [], "summary": {}}
    manifest_path = os.path.join(pack_dir, MANIFEST_NAME)
    if not os.path.isdir(pack_dir):
        report["errors"].append("pack directory does not exist")
        return report
    if not os.path.exists(manifest_path):
        report["errors"].append("manifest missing: recording was interrupted")
        return report
    manifest = _read_json(manifest_path)
    if not manifest.get("complete"):
        report["errors"].append("manifest complete=false: interrupted recording cannot be used")
    if manifest.get("schema") != SCHEMA:
        report["errors"].append(f"unsupported schema {manifest.get('schema')!r}")

    leftovers, _ = list_partial_artifacts(pack_dir)
    for leftover in leftovers:
        report["errors"].append(f"unfinished temp file present: {os.path.basename(leftover)}")

    seen_fingerprints = set()
    emitted_symbols = set()
    used_symbols = set()
    exchanges_checked = 0
    for entry in manifest.get("exchanges", []):
        path = os.path.join(pack_dir, entry["file"])
        if not os.path.exists(path):
            report["errors"].append(f"missing exchange file {entry['file']}")
            continue
        text = None
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        if _sha256_text(text) != entry.get("sha256"):
            report["errors"].append(f"hash mismatch for {entry['file']}")
            continue
        exchange = json.loads(text)
        exchanges_checked += 1
        fingerprint = exchange.get("fingerprint")
        if fingerprint in seen_fingerprints:
            report["errors"].append(f"duplicate match key fingerprint {fingerprint}")
        seen_fingerprints.add(fingerprint)
        _scan_exchange(exchange, entry["file"], report, emitted_symbols, used_symbols)

    orphan = sorted(used_symbols - emitted_symbols)
    if orphan:
        report["errors"].append(
            "requests reference symbols never emitted by a recorded response: " + ", ".join(orphan)
        )

    if policy is not None:
        _check_policy_compatibility(manifest, policy, report)

    report["summary"] = {
        "exchanges": exchanges_checked,
        "emitted_symbols": sorted(emitted_symbols),
        "used_symbols": sorted(used_symbols),
        "policy_version": manifest.get("policy_version"),
    }
    report["ok"] = not report["errors"]
    return report


def _check_policy_compatibility(manifest, policy, report):
    recorded_version = manifest.get("policy_version")
    if recorded_version not in policy.accepts_versions:
        report["errors"].append(
            f"policy {policy.policy_version} does not accept packs written by {recorded_version}; "
            "the old material must be re-recorded"
        )
        return
    if manifest.get("rules_hash") and policy.rules_hash and manifest["rules_hash"] != policy.rules_hash:
        report["warnings"].append(
            f"rules hash differs (pack={manifest['rules_hash'][:10]} "
            f"current={policy.rules_hash[:10]}) but version {recorded_version} remains accepted"
        )


def _scan_exchange(exchange, file_name, report, emitted_symbols, used_symbols):
    """Leak scan: secrets, unredacted sensitive keys, raw ephemeral values."""

    def walk(node, location):
        if isinstance(node, dict):
            for key, value in node.items():
                child = f"{location}.{key}"
                if is_symbol_ref(value):
                    used_symbols.add(value["symbol"])
                    walk(value, child)
                    continue
                if isinstance(value, str):
                    for fragment in RAW_SECRET_FRAGMENTS:
                        if fragment in value:
                            report["errors"].append(
                                f"{file_name}: raw secret fragment {fragment!r} at {child}"
                            )
                    if looks_like_ephemeral(value):
                        report["errors"].append(
                            f"{file_name}: unsymbolized ephemeral value {value!r} at {child}"
                        )
                walk(value, child)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{location}[{index}]")

    walk(exchange.get("request", {}), f"{file_name}.request")
    walk(exchange.get("response", {}), f"{file_name}.response")

    for symbol in exchange.get("emits", ()):
        emitted_symbols.add(symbol)


def ensure_policy_accepts(manifest, policy):
    """Raise explicitly when an upgraded policy cannot reuse an old pack."""
    version = manifest.get("policy_version")
    if version not in policy.accepts_versions:
        raise PolicyCompatibilityError(
            f"current policy {policy.policy_version} rejects pack policy {version}; "
            "re-record under the new rules"
        )
