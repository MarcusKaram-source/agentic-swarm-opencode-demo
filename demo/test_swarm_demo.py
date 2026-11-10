"""Tests for the public demonstration of the swarm trust chain.

These tests assert the *properties* that matter, not the narration:

  - the tree digest binds an attestation to exact bytes;
  - a signature from a different identity never verifies;
  - a payload edited after signing never verifies;
  - an attestation for other bytes never satisfies the digest binding;
  - the merge gate refuses a moved branch head, an unknown branch and an
    advanced base, and only then applies the compare-and-swap update.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from swarm_demo import (  # noqa: E402
    BASE_BRANCH,
    SCHEMA_VERSION,
    Attestation,
    audit_attestation,
    canonical_json,
    cas_merge,
    generate_ci_keypair,
    now_iso,
    sign_attestation,
    tree_fingerprint,
)


class CanonicalJsonTests(unittest.TestCase):
    def test_keys_are_sorted_and_stable(self):
        self.assertEqual(canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_insertion_order_does_not_change_the_bytes(self):
        first = canonical_json({"decision": "PASS", "checks": [], "revision": "abc"})
        second = canonical_json({"revision": "abc", "checks": [], "decision": "PASS"})
        self.assertEqual(first, second)


class TreeFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="swarm-fingerprint-"))

    def test_digest_changes_when_content_changes(self):
        target = self.root / "module.py"
        target.write_text("x = 1\n", encoding="utf-8")
        before = tree_fingerprint(self.root)
        target.write_text("x = 2\n", encoding="utf-8")
        self.assertNotEqual(before, tree_fingerprint(self.root))

    def test_digest_ignores_vcs_and_cache_directories(self):
        (self.root / "module.py").write_text("x = 1\n", encoding="utf-8")
        before = tree_fingerprint(self.root)
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_text("[core]\n", encoding="utf-8")
        (self.root / "__pycache__").mkdir()
        (self.root / "__pycache__" / "module.pyc").write_bytes(b"\x00")
        self.assertEqual(before, tree_fingerprint(self.root))

    def test_digest_is_path_sensitive(self):
        (self.root / "a").mkdir()
        (self.root / "a" / "x.py").write_text("x = 1\n", encoding="utf-8")
        first = tree_fingerprint(self.root)
        (self.root / "b").mkdir()
        (self.root / "b" / "x.py").write_text("x = 1\n", encoding="utf-8")
        self.assertNotEqual(first, tree_fingerprint(self.root))


class AuditAttestationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="swarm-audit-"))
        self.private = self.root / "ci_private.pem"
        self.public = self.root / "ci_public.pem"
        self.other_private = self.root / "other_private.pem"
        self.other_public = self.root / "other_public.pem"
        generate_ci_keypair(self.private, self.public)
        generate_ci_keypair(self.other_private, self.other_public)
        self.digest = "a" * 64
        self.payload = {
            "schema_version": SCHEMA_VERSION,
            "created_at": now_iso(),
            "revision": "deadbeef",
            "source_tree_sha256": self.digest,
            "decision": "PASS",
            "checks": [{"name": "unit_tests", "exit_code": 0}],
        }
        self.document = dict(self.payload, signature_hex=sign_attestation(self.payload, self.private))

    def test_a_valid_attestation_is_accepted(self):
        self.assertEqual(audit_attestation(self.document, self.public, self.digest), {})

    def test_a_forged_identity_is_refused(self):
        forged = dict(self.payload, signature_hex=sign_attestation(self.payload, self.other_private))
        problems = audit_attestation(forged, self.public, self.digest)
        self.assertIn("signature", problems)

    def test_a_payload_edited_after_signing_is_refused(self):
        tampered = dict(self.document)
        tampered["decision"] = "PASS"
        tampered["checks"] = [{"name": "unit_tests", "exit_code": 0}]
        tampered["source_tree_sha256"] = "b" * 64
        problems = audit_attestation(tampered, self.public, self.digest)
        self.assertIn("signature", problems)

    def test_an_attestation_for_other_bytes_is_refused(self):
        problems = audit_attestation(self.document, self.public, "c" * 64)
        self.assertIn("source_binding", problems)

    def test_a_stale_attestation_is_refused(self):
        stale = dict(self.payload)
        stale["created_at"] = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        document = dict(stale, signature_hex=sign_attestation(stale, self.private))
        problems = audit_attestation(document, self.public, self.digest)
        self.assertIn("freshness", problems)

    def test_a_failed_check_cannot_claim_pass(self):
        failed = dict(self.payload)
        failed["checks"] = [{"name": "unit_tests", "exit_code": 1}]
        document = dict(failed, signature_hex=sign_attestation(failed, self.private))
        problems = audit_attestation(document, self.public, self.digest)
        self.assertIn("checks", problems)
        self.assertIn("decision_consistency", problems)

    def test_an_unknown_schema_is_refused(self):
        other = dict(self.payload, schema_version="9.9.9")
        document = dict(other, signature_hex=sign_attestation(other, self.private))
        problems = audit_attestation(document, self.public, self.digest)
        self.assertIn("schema_version", problems)

    def test_the_audit_identity_only_needs_the_public_key(self):
        """The audit side must never require the CI private key."""
        source = Path(__file__).resolve().parent / "swarm_demo.py"
        text = source.read_text(encoding="utf-8")
        audit_block = text.split("def audit_attestation(")[1].split("def ")[0]
        self.assertNotIn("private", audit_block)


class MergeGateTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="swarm-merge-"))
        self.origin = self.root / "origin.git"
        self.work = self.root / "work"
        subprocess.run(["git", "init", "--bare", str(self.origin)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.work.mkdir()
        for args in (["init", "-q"], ["symbolic-ref", "HEAD", f"refs/heads/{BASE_BRANCH}"],
                     ["config", "user.name", "Swarm"], ["config", "user.email", "swarm@example.invalid"],
                     ["config", "core.autocrlf", "false"],
                     ["remote", "add", "origin", str(self.origin)]):
            subprocess.run(["git", *args], cwd=self.work, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (self.work / "README.md").write_text("base\n", encoding="utf-8")
        self.base = self._commit("base")
        self._push(BASE_BRANCH)
        (self.work / "README.md").write_text("feature\n", encoding="utf-8")
        self.feature = self._commit("feature")
        self._push("feature/demo")

    def _commit(self, message: str) -> str:
        subprocess.run(["git", "add", "-A"], cwd=self.work, check=True)
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=self.work, check=True)
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.work, check=True,
                              stdout=subprocess.PIPE, text=True).stdout.strip()

    def _push(self, branch: str) -> None:
        subprocess.run(["git", "push", "-q", "origin", f"HEAD:refs/heads/{branch}"],
                       cwd=self.work, check=True)

    def _origin_head(self, branch: str) -> str:
        return subprocess.run(["git", "--git-dir", str(self.origin), "rev-parse", branch],
                              check=True, stdout=subprocess.PIPE, text=True).stdout.strip()

    def test_the_verified_revision_is_merged(self):
        merged, reason = cas_merge(self.origin, "feature/demo", BASE_BRANCH, self.feature, self.base)
        self.assertTrue(merged, reason)
        self.assertEqual(self._origin_head(BASE_BRANCH), self.feature)

    def test_a_moved_branch_head_is_refused(self):
        (self.work / "README.md").write_text("moved\n", encoding="utf-8")
        moved = self._commit("moved")
        self._push("feature/demo")
        merged, reason = cas_merge(self.origin, "feature/demo", BASE_BRANCH, self.feature, self.base)
        self.assertFalse(merged)
        self.assertIn("moved", reason)

    def test_an_unknown_branch_is_refused(self):
        merged, reason = cas_merge(self.origin, "feature/nope", BASE_BRANCH, self.feature, self.base)
        self.assertFalse(merged)
        self.assertIn("does not exist", reason)

    def test_an_advanced_base_is_refused(self):
        merged, reason = cas_merge(self.origin, "feature/demo", BASE_BRANCH, self.feature, "0" * 40)
        self.assertFalse(merged)
        self.assertIn("base", reason)

    def test_a_concurrent_base_move_is_refused_by_the_ref_update(self):
        """The compare-and-swap protects against a base that moves after the check."""
        merged, _ = cas_merge(self.origin, "feature/demo", BASE_BRANCH, self.feature, self.base)
        self.assertTrue(merged)
        # the second attempt used the now stale base head and must be refused
        again, reason = cas_merge(self.origin, "feature/demo", BASE_BRANCH, self.feature, self.base)
        self.assertFalse(again)
        self.assertIn("base", reason)


if __name__ == "__main__":
    unittest.main()
