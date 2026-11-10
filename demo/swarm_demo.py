"""Public demonstration of the OpenCode Swarm trust chain.

This is a self-contained re-implementation of the *trust properties* of the
private engineering foundation. It is deliberately not the production code: the
full implementation runs Temporal workers, LangGraph activities, a PostgreSQL
control plane and real OpenCode CLI agents, and it stays private.

What this script demonstrates, end to end and with real cryptography:

  1. A seeded defect is written into a sample project by the "engineering" phase.
  2. An independent CI identity clones the exact pushed branch, runs the tests,
     digests the tree and signs an Ed25519 attestation over canonical JSON.
  3. An independent audit identity - which holds only the CI *public* key -
     verifies signature, digest binding, freshness and decision. A failing
     verdict opens a repair round that is driven by the *observed CI output*.
  4. The repair round is stacked on top of the previous revision and re-audited.
  5. The merge gate refuses a branch whose head moved after the attestation was
     verified, refuses a base branch that advanced underneath it, and only then
     applies a compare-and-swap ref update.
  6. The run stops at the owner approval gate. Nothing is deployed.

Run it with:  python demo/swarm_demo.py
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_VERSION = "1.0.0"
IGNORE_DIRS = {".git", "__pycache__", ".swarm", ".venv", "venv", "node_modules", ".pytest_cache"}
BASE_BRANCH = "main"
FEATURE_BRANCH = "feature/demo"


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def canonical_json(value) -> str:
    """Canonical JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_fingerprint(root: Path) -> str:
    """Content digest of every source file under `root` (no symlink following).

    The digest binds an attestation to the exact bytes that were verified.
    """
    root = root.resolve(strict=True)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in IGNORE_DIRS for part in relative.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        digest.update(relative.as_posix().encode("utf-8") + b"\0" + sha256_file(path).encode("ascii") + b"\n")
    return digest.hexdigest()


def run(argv: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        argv, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(argv)}\n{completed.stdout}")
    return completed


def git(workspace: Path, *args: str, check: bool = True) -> str:
    completed = run(["git", *args], workspace, check=check)
    return completed.stdout.strip()


def git_in_origin(origin: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Runs a git command against the bare origin; stderr is merged into stdout."""
    return run(["git", "--git-dir", str(origin), *args], origin, check=check)


# --------------------------------------------------------------------------
# phase 1 - the engineering identity writes a revision
# --------------------------------------------------------------------------
BASE_MODULE = '''\
"""Sample library used by the demo."""


def add(a, b):
    """Sum of two numbers."""
    return a + b
'''

BASE_TEST = '''\
import unittest

from mathlib import add


class AddTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_add_negative(self):
        self.assertEqual(add(-2, -3), -5)


if __name__ == "__main__":
    unittest.main()
'''

SEEDED_MODULE = '''\
"""Sample library used by the demo."""


def add(a, b):
    """Sum of two numbers."""
    return a + b


def moving_average(values, window):
    """Mean of the last `window` samples."""
    if window <= 0:
        raise ValueError("window must be positive")
    if len(values) < window:
        raise ValueError("not enough samples")
    total = 0
    for index in range(window - 1):
        total += values[index]
    return total / (window - 1)
'''

FIXED_MODULE = '''\
"""Sample library used by the demo."""


def add(a, b):
    """Sum of two numbers."""
    return a + b


def moving_average(values, window):
    """Mean of the last `window` samples."""
    if window <= 0:
        raise ValueError("window must be positive")
    if len(values) < window:
        raise ValueError("not enough samples")
    total = 0
    for index in range(len(values) - window, len(values)):
        total += values[index]
    return total / window
'''

SAMPLE_TEST = '''\
import unittest

from mathlib import add, moving_average


class AddTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)


class MovingAverageTests(unittest.TestCase):
    def test_two_sample_window(self):
        self.assertEqual(moving_average([1, 2, 3, 4], 2), 3.5)

    def test_three_sample_window(self):
        self.assertEqual(moving_average([2, 4, 6, 8], 3), 6.0)

    def test_rejects_empty_window(self):
        with self.assertRaises(ValueError):
            moving_average([1, 2], 0)


if __name__ == "__main__":
    unittest.main()
'''


def seed_project(workspace: Path, module_source: str, test_source: str = SAMPLE_TEST) -> None:
    (workspace / "mathlib.py").write_text(module_source, encoding="utf-8")
    tests = workspace / "tests"
    tests.mkdir(exist_ok=True)
    (tests / "test_mathlib.py").write_text(test_source, encoding="utf-8")
    (tests / "__init__.py").write_text("", encoding="utf-8")


def commit(workspace: Path, message: str) -> str:
    git(workspace, "add", "-A")
    git(workspace, "-c", "user.name=Swarm Engineer", "-c", "user.email=engineer@swarm.invalid",
        "commit", "-q", "-m", message)
    return git(workspace, "rev-parse", "HEAD")


# --------------------------------------------------------------------------
# phase 2 - the CI service identity signs an attestation
# --------------------------------------------------------------------------
@dataclass
class Attestation:
    payload: dict
    signature_hex: str

    def as_document(self) -> dict:
        return dict(self.payload, signature_hex=self.signature_hex)


def generate_ci_keypair(private_path: Path, public_path: Path) -> None:
    """The CI private key lives only with the CI identity."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def sign_attestation(payload: dict, private_path: Path) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    return key.sign(canonical_json(payload).encode("utf-8")).hex()


def ci_verify(clone: Path, private_key: Path, revision: str) -> Attestation:
    """Runs as the CI identity: fresh clone, fixed test command, signed verdict."""
    result = run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], clone, check=False)
    output = result.stdout or ""
    failed = "FAILED" in output or result.returncode != 0
    payload = {
        "schema_version": SCHEMA_VERSION,
        "created_at": now_iso(),
        "revision": revision,
        "source_tree_sha256": tree_fingerprint(clone),
        "decision": "FAIL" if failed else "PASS",
        "checks": [{
            "name": "unit_tests",
            "exit_code": result.returncode,
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }],
        "observation": _extract_failure(output),
    }
    return Attestation(payload, sign_attestation(payload, private_key))


def _extract_failure(output: str) -> str:
    """The repair round is driven by the observed CI output, not by prose."""
    for line in output.splitlines():
        if "AssertionError" in line or line.startswith("FAIL:"):
            return line.strip()
    return ""


# --------------------------------------------------------------------------
# phase 3 - the audit identity verifies (public key only)
# --------------------------------------------------------------------------
def audit_attestation(document: dict, public_key: Path, expected_digest: str | None,
                      stale_seconds: int = 24 * 3600) -> dict[str, str]:
    """Returns {} when the attestation is fully valid, else problems by category."""
    from cryptography.hazmat.primitives import serialization

    problems: dict[str, str] = {}
    signature_hex = document.get("signature_hex", "")
    payload = {k: v for k, v in document.items() if k != "signature_hex"}
    if document.get("schema_version") != SCHEMA_VERSION:
        problems["schema_version"] = "attestation schema version mismatch"
    if not signature_hex:
        problems["signature"] = "missing signature"
    else:
        try:
            key = serialization.load_pem_public_key(public_key.read_bytes())
            key.verify(bytes.fromhex(signature_hex), canonical_json(payload).encode("utf-8"))
        except Exception:
            problems["signature"] = "signature does not verify against the CI identity"
    attested = str(document.get("source_tree_sha256", "")).lower()
    if expected_digest is not None and attested != expected_digest.lower():
        problems["source_binding"] = (
            f"attested digest {attested[:16]}... != current tree digest {expected_digest[:16]}...")
    try:
        created = datetime.fromisoformat(str(document.get("created_at", "")))
        now = datetime.now(timezone.utc)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if abs(now - created) > timedelta(seconds=stale_seconds):
            problems["freshness"] = "attestation is stale or has a future timestamp"
    except ValueError:
        problems["created_at"] = "missing or malformed created_at"
    checks = document.get("checks") or []
    if not checks:
        problems["checks"] = "attestation contains no verification checks"
    elif any(not isinstance(c.get("exit_code"), int) or c["exit_code"] != 0 for c in checks):
        problems["checks"] = "one or more CI checks failed"
    if document.get("decision") not in ("PASS", "FAIL"):
        problems["decision"] = "decision missing or malformed"
    if problems and document.get("decision") == "PASS":
        problems["decision_consistency"] = "cannot claim PASS while verification problems exist"
    return problems


# --------------------------------------------------------------------------
# phase 5 - the merge gate (compare-and-swap ref update)
# --------------------------------------------------------------------------
def cas_merge(origin: Path, branch: str, base: str, expected_branch_head: str,
              expected_base_head: str) -> tuple[bool, str]:
    """Updates `base` to `branch` only when both refs still point where the gate expects.

    Returns (merged, reason).
    """
    branch_head_result = git_in_origin(origin, "rev-parse", "--verify", branch, check=False)
    if branch_head_result.returncode != 0:
        return False, f"branch {branch} does not exist in the origin"
    branch_head = branch_head_result.stdout.strip()
    if branch_head != expected_branch_head:
        return False, (f"refused: branch head {branch_head[:12]}... moved after the attestation "
                       f"covered {expected_branch_head[:12]}...")
    current_base_result = git_in_origin(origin, "rev-parse", "--verify", base, check=False)
    current_base = current_base_result.stdout.strip() if current_base_result.returncode == 0 else ""
    if current_base != expected_base_head:
        return False, (f"refused: base {base} is at {current_base[:12] or 'absent'}..., "
                       f"expected {expected_base_head[:12]}...")
    updated = git_in_origin(origin, "update-ref", f"refs/heads/{base}", branch_head,
                             expected_base_head, check=False)
    if updated.returncode != 0:
        return False, f"refused: compare-and-swap ref update failed ({updated.stdout.strip()})"
    return True, f"merged {branch_head[:12]}... into {base} (compare-and-swap)"


# --------------------------------------------------------------------------
# the demo
# --------------------------------------------------------------------------
@dataclass
class Demo:
    root: Path = field(init=False)
    origin: Path = field(init=False)
    agent: Path = field(init=False)
    keys: Path = field(init=False)
    ci_private: Path = field(init=False)
    ci_public: Path = field(init=False)

    def __post_init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="swarm-demo-"))
        self.origin = self.root / "origin.git"
        self.agent = self.root / "agent-workspace"
        self.keys = self.root / "ci-identity"
        self.ci_private = self.keys / "ci_ed25519_private.pem"
        self.ci_public = self.keys / "ci_ed25519_public.pem"

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    # -- setup ------------------------------------------------------------
    def setup(self) -> None:
        run(["git", "init", "--bare", str(self.origin)], self.root)
        git_in_origin(self.origin, "symbolic-ref", "HEAD", f"refs/heads/{BASE_BRANCH}")
        git_in_origin(self.origin, "config", "core.autocrlf", "false")
        self.agent.mkdir()
        git(self.agent, "init", "-q")
        git(self.agent, "symbolic-ref", "HEAD", f"refs/heads/{BASE_BRANCH}")
        git(self.agent, "config", "core.autocrlf", "false")
        git(self.agent, "remote", "add", "origin", str(self.origin))
        generate_ci_keypair(self.ci_private, self.ci_public)
        print(f"[setup]  origin        {self.origin}")
        print(f"[setup]  workspace     {self.agent}")
        print("[setup]  CI identity   ed25519 keypair (private key held only by the CI phase)")

    def publish_base_branch(self) -> str:
        """The pristine snapshot is published once as the base branch."""
        seed_project(self.agent, BASE_MODULE, BASE_TEST)
        head = commit(self.agent, "base snapshot")
        git(self.agent, "push", "-q", "origin", f"HEAD:refs/heads/{BASE_BRANCH}")
        print(f"[setup]  base branch   {BASE_BRANCH} published at {head[:12]}...")
        return head

    # -- phases -----------------------------------------------------------
    def engineering_revision(self, module_source: str, test_source: str, message: str,
                             branch: str, parent: str | None) -> str:
        git(self.agent, "checkout", "-q", "-B", branch, parent or BASE_BRANCH)
        seed_project(self.agent, module_source, test_source)
        head = commit(self.agent, message)
        git(self.agent, "push", "-q", "origin", f"HEAD:refs/heads/{branch}")
        print(f"[engineering] revision {head[:12]}... pushed to {branch}: {message}")
        return head

    def independent_ci(self, branch: str, revision: str) -> Attestation:
        clone = self.root / f"ci-clone-{revision[:8]}"
        run(["git", "clone", "-q", "--branch", branch, str(self.origin), str(clone)], self.root)
        git(clone, "config", "core.autocrlf", "false")
        attestation = ci_verify(clone, self.ci_private, revision)
        verdict = attestation.payload["decision"]
        print(f"[ci]          independent clone of {branch} @ {revision[:12]}...")
        print(f"[ci]          verdict {verdict}: {attestation.payload['observation'] or 'all checks passed'}")
        print(f"[ci]          signed source digest {attestation.payload['source_tree_sha256'][:16]}...")
        return attestation

    def audit(self, attestation: Attestation, workspace: Path) -> dict[str, str]:
        problems = audit_attestation(attestation.as_document(), self.ci_public,
                                     tree_fingerprint(workspace))
        if problems:
            print("[audit]       REFUSED the release gate:")
            for category, detail in problems.items():
                print(f"[audit]         - {category}: {detail}")
        else:
            print("[audit]       accepted: signature, digest binding, freshness and checks all verified")
        return problems

    def merge_gate(self, branch: str, expected_branch_head: str, expected_base_head: str) -> bool:
        merged, reason = cas_merge(self.origin, branch, BASE_BRANCH, expected_branch_head, expected_base_head)
        print(f"[merge-gate]  {reason}")
        return merged


def main() -> int:
    demo = Demo()
    try:
        print("=" * 78)
        print("OpenCode Swarm - public demonstration of the autonomous trust chain")
        print("=" * 78)
        demo.setup()
        base_head = demo.publish_base_branch()

        # --- round 1: the engineering agent introduces a defect ------------
        print("\n--- round 1: engineering -> CI -> audit ---------------------------")
        revision_1 = demo.engineering_revision(
            SEEDED_MODULE, SAMPLE_TEST, "feature: add moving_average (seeded defect)",
            FEATURE_BRANCH, base_head)
        attestation_1 = demo.independent_ci(FEATURE_BRANCH, revision_1)
        problems_1 = demo.audit(attestation_1, demo.agent)
        if not problems_1:
            print("[demo]        unexpected: a failing revision passed the gate")
            return 1

        # the repair round is driven by the observed CI failure
        observation = attestation_1.payload["observation"]
        print(f"[repair]      input is the observed CI output, not the agent's prose: {observation}")

        # --- round 2: repair, stacked on the previous revision --------------
        print("\n--- round 2: repair -> CI -> audit -------------------------------")
        revision_2 = demo.engineering_revision(
            FIXED_MODULE, SAMPLE_TEST, "fix: include the newest sample in the window",
            FEATURE_BRANCH, revision_1)
        ancestry = run(["git", "merge-base", "--is-ancestor", revision_1, revision_2], demo.agent, check=False)
        print(f"[repair]      repair stacked on {revision_1[:12]}...: lineage_ok={ancestry.returncode == 0}")
        attestation_2 = demo.independent_ci(FEATURE_BRANCH, revision_2)
        problems_2 = demo.audit(attestation_2, demo.agent)
        if problems_2:
            print("[demo]        the repaired revision did not pass the gate")
            return 1

        # --- forged and tampered attestations are refused -------------------
        print("\n--- forged / tampered attestations ------------------------------")
        forged_key = demo.root / "forged_private.pem"
        forged_public = demo.root / "forged_public.pem"
        generate_ci_keypair(forged_key, forged_public)
        forged = Attestation(dict(attestation_2.payload), sign_attestation(attestation_2.payload, forged_key))
        forged_problems = audit_attestation(forged.as_document(), demo.ci_public,
                                            tree_fingerprint(demo.agent))
        print(f"[audit]       forged by an unrelated identity -> "
              f"{'REFUSED' if forged_problems else 'ACCEPTED (BUG!)'}: {forged_problems.get('signature', '')}")
        tampered = dict(attestation_2.as_document())
        tampered["decision"] = "PASS"
        tampered["checks"] = [{"name": "unit_tests", "exit_code": 0}]
        tampered_problems = audit_attestation(tampered, demo.ci_public, tree_fingerprint(demo.agent))
        print(f"[audit]       payload edited after signing -> "
              f"{'REFUSED' if tampered_problems else 'ACCEPTED (BUG!)'}: {tampered_problems.get('signature', '')}")

        # --- the merge gate -------------------------------------------------
        print("\n--- merge gate ---------------------------------------------------")
        moved_head = demo.engineering_revision(
            FIXED_MODULE + "\n# touched after the attestation was signed\n", SAMPLE_TEST,
            "chore: touch the file after the attestation was signed", FEATURE_BRANCH, revision_2)
        print(f"[demo]        the branch head moved to {moved_head[:12]}... after the attestation "
              f"covered {revision_2[:12]}...")
        refused_moved = demo.merge_gate(FEATURE_BRANCH, revision_2, base_head)
        print(f"[merge-gate]  merge of a moved head refused: {not refused_moved}")
        refused_unrelated = demo.merge_gate("feature/does-not-exist", revision_2, base_head)
        print(f"[merge-gate]  merge of an unrelated branch refused: {not refused_unrelated}")
        refused_base = demo.merge_gate(FEATURE_BRANCH, moved_head, "0" * 40)
        print(f"[merge-gate]  merge against an advanced base refused: {not refused_base}")

        # the head that is actually verified gets attested and merged
        attestation_3 = demo.independent_ci(FEATURE_BRANCH, moved_head)
        problems_3 = demo.audit(attestation_3, demo.agent)
        if problems_3:
            print("[demo]        the final revision did not pass the gate")
            return 1
        merged = demo.merge_gate(FEATURE_BRANCH, moved_head, base_head)
        if not merged:
            print("[demo]        the verified revision was not merged")
            return 1
        final = git_in_origin(demo.origin, "rev-parse", BASE_BRANCH).stdout.strip()
        print(f"[merge-gate]  {BASE_BRANCH} now points at {final[:12]}... "
              f"(the verified revision {moved_head[:12]}...)")

        # --- owner gate -----------------------------------------------------
        print("\n--- owner approval gate ------------------------------------------")
        print("[gate]        the release gate is open, but production deployment still")
        print("[gate]        requires an explicit owner approval. This demo deploys nothing.")
        print("[gate]        In the private foundation that approval is recorded in the")
        print("[gate]        server-side control plane, and the deploy activity refuses to")
        print("[gate]        run without it.")

        print("\n" + "=" * 78)
        print("demonstration complete: build -> test -> audit -> fix -> re-audit -> merge")
        print("=" * 78)
        return 0
    finally:
        demo.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
