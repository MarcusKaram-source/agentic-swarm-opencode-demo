# Validation summary (public extract)

This is a **public extract** of the private foundation's validation record. The
full record - with every command, log path, commit hash and defect - stays
private with the implementation.

Everything below was executed against **real locally-running services**
(Dockerized PostgreSQL 16.15, Temporal Server 1.28, OpenTelemetry Collector
0.114, Jaeger 1.62) and the **real OpenCode CLI v2.2.5**. There were no mocks
in the final integration evidence.

The runs that failed are included on purpose. Every defect listed was found by
running the system rather than by reading it, and each one is now covered by a
regression test.

## Recorded runs

| Run | Scenario | Outcome |
|---|---|---|
| `3c536137-b383-4b3e-9205-595ca856d1aa` | full loop, seeded defect | `RELEASE_AUTHORIZED` in 255.8 s |
| `25f6b1a8-9185-4d2a-9410-723d43148b62` | engineering worker SIGKILLed mid-run | killed at 44.0 s, restarted at 49.0 s, `recovery_proven: true` |
| `039e9a8e-1edb-4ff8-9f26-967979aa2f38` | bounded retries (`max_rounds=1`) | `BLOCKED` - the seeded defect was found, the audit failed, and the workflow escalated instead of looping |
| merge | protected merge of the audited revision | **MERGED** as a fast-forward, `merged_by owner-console` |

## The autonomous loop, as recorded in the step ledger

| Round | Phase | Result |
|---|---|---|
| 1 | execute | completed - new revision with `mean()` and `tests/test_mean.py` |
| 1 | CI gate | **FAIL** attestation (`unit_tests:0`, `security_scan:1`), signed by the CI identity |
| 1 | audit | **FAIL** - `SECURITY_SCAN` + `AUDIT_VERIFICATION` findings |
| 2 | fix | completed - new revision with a safe AST evaluator; the seeded `eval` removed |
| 2 | CI gate | **PASS** attestation (`unit_tests:0`, `security_scan:0`) |
| 2 | audit | **PASS** - release gate opened, owner approval recorded, staging deployed |

The repair round consumed four agent steps (read the flagged file, read the
pinned spec and the scanner, one edit, one report) and changed exactly one
file. The recorded session shows it did not touch the tests, the scanner, the
quality plan or the CI configuration - the repair was driven by the *observed*
CI output, not by the finished feature task.

## Worker-restart recovery

The engineering worker was SIGKILLed mid-run. Temporal redelivered the
interrupted activity, the ledger recorded it as attempt 2
(`...:execute:1:2`), the restarted worker re-executed it in a **new** isolated
workspace, and the run still completed `RELEASE_AUTHORIZED`. This is the
difference between a retry and a recovery: the ledger key
`(run, phase, round, attempt)` is what makes the redelivery replayable.

## Protected merge

The merge refused unless there was a signature-verified `PASS` attestation
bound to the current head commit. The base branch update was a
compare-and-swap (`git update-ref <ref> <new> <old>`) and the verified head
had to still be the branch head when the merge ran. The recorded branch
history was `repair -> build -> base snapshot`, so the diff base-to-branch
contained the agent's work only. Sixteen regression tests cover the refusals:
unrelated branch, advanced base, concurrently moved base, and a branch head
that moved after the attestation was verified.

## Staging and rollback

The staging deploy ran only after `RELEASE_AUTHORIZED` was recorded, deployed
an immutable artifact copy into a pinned image and ran the check suite as a
canary (`Ran 12 tests ... OK`). A rollback drill redeployed the approved
artifact, re-verified it and selected the previous verified artifact as the
rollback target. Production promotion stayed `BLOCKED_OWNER_GATE` throughout -
the canary evaluator requires an owner approval and never executed.

## Observability

OpenTelemetry spans were recorded for every activity (`execute_step`,
`run_ci_gate_step`, `audit_step`, `fix_step`, `deploy_staging_step`,
`verify_owner_approval`) and for the control-plane HTTP calls, in the
`swarm-control-plane` and `swarm` services. The collector strips prompt
attributes, so model content does not leak into traces. The exported trace
file contained 33 control-plane and 61 activity traces.

## Defects found by running the system

Fourteen defects were recorded in the private validation record, each with a
root cause, a fix and a regression test. The instructive ones:

| Symptom | Root cause |
|---|---|
| 11 PR merges were refused | feature branches were published as orphans instead of on top of the published base branch, so the merge was never a fast-forward |
| merge could overwrite concurrent work | the base branch was updated without a compare-and-swap |
| a branch could merge after it moved | the branch head was not re-read at merge time (a time-of-check/time-of-use gap) |
| CI broke on a fresh clone | the published CI installed only the kit requirements, so the test suite could not import the runtime |
| dependency audit failed closed | the declared `cryptography` ceiling excluded every patched release |

That last two were found only when the project was published and its CI ran on
a clean machine - which is the argument for publishing early and often.

## What remains open

These are the reasons the private foundation is **not** production-ready, and
they are not solved by this demo either:

- workers are not sandboxed (no container or microVM per task, no egress
  control, no resource caps);
- no OIDC/JWKS identities, per-tenant isolation, rate limits or off-box audit
  sink;
- no keyless provenance (Sigstore), no SBOM publication, no SLSA target;
- the DAST, browser and mutation gates are not yet wired into a protected
  branch as mandatory checks;
- no real staging or production topology, no backup/restore drill, no incident
  drill;
- the OpenCode provider quota for the worker is an operational cost decision
  that has not been made.

Production promotion therefore remains `BLOCKED_OWNER_GATE`.
