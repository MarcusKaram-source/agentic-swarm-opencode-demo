# The OpenCode Swarm runs a real engineering loop, but the interesting part is
# not the loop - it is the trust chain around it.
#
# These documents describe the public demo and the properties it proves. The
# full implementation (Temporal workers, LangGraph activities, PostgreSQL
# control plane, real OpenCode CLI agents, staging deploy and rollback) stays
# private.
#
# Component map of the private foundation, and what each part is responsible
# for. The demo reproduces the trust-relevant parts of this map.

## Roles

| Role | Responsibility | May not |
|---|---|---|
| engineering | write revisions in an isolated workspace | run its own checks, approve its own work |
| CI | clone the exact branch, run the fixed quality plan, sign an attestation | write code |
| audit | verify the attestation, open or refuse the release gate | sign anything |
| deploy | stage and promote an immutable artifact | run before a recorded owner approval |
| owner | approve consequential decisions and production promotion | be simulated by an agent |

Each role runs in a separate process with separate key material and a separate
Temporal task queue. The separation is the point: an agent that can both write
code and declare it verified has no gate at all.

## Data flow of one task

```
owner-approved task
        |
        v
  engineering worker  --writes-->  isolated workspace  --push-->  feature branch
        |                                                   |
        |                                          (branch head is the unit of truth)
        v                                                   |
  step ledger (run, phase, round, attempt)                  v
        |                                            CI worker (separate identity)
        |                                                   |
        |                                        signed attestation over
        |                                        canonical JSON + tree digest
        |                                                   |
        v                                                   v
  audit worker (separate identity, public key only)  --verify-->
        |
        |  FAIL -> repair round, driven by the observed CI output
        |            (a new revision on top of the previous one)
        |
        v  PASS -> release gate opens -> owner approval -> staging -> rollback drill
```

## The three trust boundaries

**1. Control plane.** Durable, transactional state (PostgreSQL in the private
foundation). The step ledger is keyed by `(run, phase, round, attempt)`, so a
redelivered activity replays its recorded outcome instead of re-running side
effects. This is what makes a killed worker recoverable rather than merely
retryable.

**2. Independent verifier.** The CI identity clones the pushed branch itself
and runs a fixed argv quality plan. It never trusts the engineering agent's
report of what it did. The CI private key exists only inside the CI worker.

**3. Provenance.** The attestation binds the verdict to the exact bytes:

- the signature is Ed25519 over canonical JSON (`sort_keys`, no insignificant
  whitespace), so the same logical payload always produces the same bytes;
- the payload carries `source_tree_sha256`, a SHA256 digest over every source
  file in the verified tree;
- the audit identity recomputes the digest of the tree it is asked about and
  refuses a mismatch.

Without the digest, a valid signature over a *different* tree would be
meaningless; without the signature, a digest proves nothing about who checked
it.

## Branch lineage

The base branch is published once from the pristine snapshot. Every feature
revision is committed **on top of** it, and each repair round on top of its
own previous revision. A merge is therefore a real fast-forward, and the
"base" a reviewer sees is the base the feature was actually built on.

The merge itself is a compare-and-swap:

```
git update-ref refs/heads/main <new-head> <old-head>
```

`old-head` must still be the current value of the ref, so a base that moved
underneath the gate makes the update fail instead of silently overwriting it.
The branch head is re-read immediately before the update and compared with the
revision the attestation covered, which closes the window where a branch moves
between verification and merge.

## Deliberate non-goals

- the demo does not deploy anything, and nothing in it is an approval;
- a passing local test suite is not a release approval;
- the model is never allowed to decide that it succeeded.
