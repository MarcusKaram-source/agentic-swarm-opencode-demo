# OpenCode Swarm - public demo

[![Demo verification](https://github.com/MarcusKaram-source/agentic-swarm-opencode-demo/actions/workflows/demo-ci.yml/badge.svg)](https://github.com/MarcusKaram-source/agentic-swarm-opencode-demo/actions/workflows/demo-ci.yml)

A runnable demonstration of the **trust chain** behind an autonomous multi-agent
engineering swarm: build -> test -> independent audit -> repair -> re-audit ->
protected merge -> owner approval gate.

This repository contains the **public demo only** - a small, readable,
self-contained re-implementation of the trust properties. The full engineering
foundation (Temporal workers, LangGraph activities, a PostgreSQL control plane,
real OpenCode CLI agents, signed CI attestations, staging deploy and rollback)
stays **private**, and nothing here is a mock of it: the cryptography, the
digests and the git ref updates below are real.

```
python -m pip install -r requirements.txt
python demo/swarm_demo.py
```

The demo takes about ten seconds, needs only Python 3.10+ and `git`, and never
touches the network.

---

## What the demo does

| Phase | What happens | Why it matters |
|---|---|---|
| engineering | an agent writes a revision with a seeded defect onto a feature branch | work is isolated per task |
| CI | a **separate identity** clones the exact pushed branch, runs the tests, digests the tree and signs an Ed25519 attestation over canonical JSON | the verifier is not the author |
| audit | a **separate identity** that holds only the CI *public* key verifies signature, digest binding, freshness and decision | the verdict is bound to exact bytes |
| repair | a new revision is stacked on the previous one, driven by the *observed CI output* | the repair is evidence-driven, not self-asserted |
| re-audit | CI and audit run again on the repaired revision | the gate only opens on fresh evidence |
| merge | the base branch is updated with a compare-and-swap ref update | no lost updates, no TOCTOU |
| owner gate | the run stops and reports that deployment needs a human | an agent cannot promote itself |

The demo also proves the **negative** cases, because that is where an
autonomous system actually breaks:

- an attestation signed by an unrelated identity is **refused**;
- a payload edited after signing is **refused**;
- an attestation for different bytes is **refused** (digest binding);
- a merge whose branch head moved **after** the attestation was verified is
  **refused**;
- a merge against a base branch that advanced underneath it is **refused**;
- a merge of an unrelated branch is **refused**.

## Sample output

```
--- round 1: engineering -> CI -> audit ---------------------------
[engineering] revision 873169daa7e3... pushed to feature/demo: feature: add moving_average (seeded defect)
[ci]          independent clone of feature/demo @ 873169daa7e3...
[ci]          verdict FAIL: FAIL: test_three_sample_window (test_mathlib.MovingAverageTests.test_three_sample_window)
[audit]       REFUSED the release gate:
[audit]         - checks: one or more CI checks failed
[repair]      input is the observed CI output, not the agent's prose: FAIL: test_three_sample_window (...)

--- round 2: repair -> CI -> audit -------------------------------
[engineering] revision ebe178b2a5e2... pushed to feature/demo: fix: include the newest sample in the window
[repair]      repair stacked on 873169daa7e3...: lineage_ok=True
[ci]          verdict PASS: all checks passed
[audit]       accepted: signature, digest binding, freshness and checks all verified

--- forged / tampered attestations ------------------------------
[audit]       forged by an unrelated identity -> REFUSED: signature does not verify against the CI identity
[audit]       payload edited after signing -> REFUSED: signature does not verify against the CI identity

--- merge gate ---------------------------------------------------
[merge-gate]  refused: branch head 4d57ba751d41... moved after the attestation covered ebe178b2a5e2...
[merge-gate]  refused: base main is at 9d257c75572b..., expected 000000000000...
[merge-gate]  merged 2d3b97fc328f... into main (compare-and-swap)

--- owner approval gate ------------------------------------------
[gate]        the release gate is open, but production deployment still
[gate]        requires an explicit owner approval. This demo deploys nothing.
```

## The trust model in one table

| Property | Mechanism | Enforced by |
|---|---|---|
| Independence | CI and audit run as separate identities with separate key material | the audit side only ever holds the public key |
| Authenticity | Ed25519 signature over canonical JSON | `audit_attestation()` |
| Binding | SHA256 tree fingerprint in the signed payload | `tree_fingerprint()` |
| Freshness | signed `created_at`, rejected when stale | `audit_attestation()` |
| Consistency | a `PASS` verdict with failing checks is impossible | `audit_attestation()` |
| Linear history | every revision is committed on top of the previous one | branch lineage, `git merge-base --is-ancestor` |
| No lost updates | compare-and-swap `git update-ref <ref> <new> <old>` | `cas_merge()` |
| Human promotion | production deploy requires a recorded owner approval | the deploy activity refuses to run without it |

## Tests

```
python -m unittest discover -s demo
```

18 tests assert the properties above rather than the narration: digest
sensitivity, forged/tampered/stale/mismatched attestations, and every merge
gate refusal path.

## What is *not* demonstrated here

Honesty about scope matters more than a good demo:

- this is a **local trust anchor**. Ed25519 keys on a developer's machine are
  not keyless provenance; production needs Sigstore / OIDC attestation and a
  protected CI identity;
- workers are **not sandboxed** here. The private foundation isolates
  workspaces, but real isolation needs a container or microVM per task with
  egress control and resource caps;
- the model is a **deterministic patch** here. In the private foundation the
  repair round is driven by a real OpenCode agent that only sees the observed
  CI output and the pinned spec;
- there is **no production deployment** in this repository, and none is
  authorized by it.

See [`docs/VALIDATION-SUMMARY.md`](docs/VALIDATION-SUMMARY.md) for what the
private foundation actually executed against real services, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the component map.

## Documents

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - components and data flow
- [`docs/TRUST-MODEL.md`](docs/TRUST-MODEL.md) - the properties and their failure modes
- [`docs/VALIDATION-SUMMARY.md`](docs/VALIDATION-SUMMARY.md) - recorded results, including the failures
- [`SECURITY.md`](SECURITY.md) - reporting and trust boundaries
