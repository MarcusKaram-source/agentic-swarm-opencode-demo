# Trust model

Each property below states what must hold, how it is enforced, and **how it
fails** - the failure modes are the point, because an autonomous system that
only looks correct on the happy path is not a gate.

## 1. Independence of verifier and author

**Must hold:** the entity that decides "the tests pass" is not the entity that
wrote the code.

**Enforced by:** separate workers, separate task queues, separate key
material. The audit identity only ever receives the CI *public* key.

**Fails when:** a shared secret, a shared process, or an agent that is asked
to run its own checks. The demo's `audit_attestation()` is written so that it
cannot accept a private key path at all.

## 2. Authenticity of the verdict

**Must hold:** the verdict was produced by the CI identity and has not been
edited since.

**Enforced by:** Ed25519 signature over canonical JSON, verified against the
CI public key.

**Fails when:** the payload is edited after signing, or the signature comes
from a different key. Both are refused with a `signature` problem, and the
demo asserts both cases.

**Why canonical JSON:** signature verification compares bytes. Two encodings of
the same object would otherwise produce two different signatures for the same
logical content. `sort_keys=True` and no insignificant whitespace make the
encoding deterministic.

## 3. Binding of the verdict to exact bytes

**Must hold:** the verdict applies to the tree that is being merged, not to
some other tree.

**Enforced by:** `source_tree_sha256` inside the signed payload, recomputed by
the audit identity from the tree it is asked about.

**Fails when:** the workspace changed after CI ran - including a change nobody
re-verified. This is the classic "verified a commit, merged a different
commit" failure, and it is exactly what a digest binding prevents.

## 4. Freshness

**Must hold:** the verdict is recent.

**Enforced by:** signed `created_at`, rejected when outside the freshness
window.

**Fails when:** an old attestation is replayed after the code changed.
Freshness alone would not be enough (property 3 covers that), but a stale
verdict is never acceptable.

## 5. Consistency of the verdict

**Must hold:** a `PASS` cannot coexist with a failing check.

**Enforced by:** the audit recomputes the checks from the payload and adds a
`decision_consistency` problem when a `PASS` hides a non-zero exit code.

**Fails when:** a signing or transport bug flips a decision field without
flipping the underlying check result.

## 6. Linear history

**Must hold:** revisions form a chain; each repair builds on the revision it
repairs.

**Enforced by:** every revision is committed on top of its predecessor, and the
lineage is checked with `git merge-base --is-ancestor`.

**Fails when:** a repair is applied to a different base, producing a history
where the "fix" does not contain the "break".

## 7. No lost updates at merge

**Must hold:** merging a branch never silently overwrites concurrent work.

**Enforced by:** compare-and-swap ref update - `git update-ref <ref> <new>
<old>` - with the branch head re-read and compared against the attested
revision immediately before the update.

**Fails when:** two merges race, or a branch is pushed to between verification
and merge. The demo asserts all three refusals: moved head, advanced base,
unrelated branch.

## 8. Human promotion

**Must hold:** production deployment requires a recorded human approval.

**Enforced by:** the deploy activity refuses to run without an approval
recorded in the server-side control plane. A model message, a prompt, or a
writable local file is not an approval.

**Fails when:** the approval check is advisory, or when "the CI was green" is
treated as a deployment decision.

## What the trust chain does *not* prove

A green chain proves that a specific tree passed specific checks under a
specific identity. It does not prove that the checks are the right checks,
that the code is correct, that the code is safe to run, or that the operator
wanted it. Those need review, sandboxing and human judgement - the chain only
makes the mechanical part trustworthy enough to build on.
