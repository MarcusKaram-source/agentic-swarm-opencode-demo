# Security

## Reporting

Report a vulnerability in the **private** foundation through the private
repository's security advisory flow, not as a public issue. For this public
demo repository, open a normal issue only for a defect in the demonstration
code itself - it has no privileged behaviour and holds no credentials.

## Trust boundaries

- The CI **private** key is generated in a temporary directory at run time and
  is never written to the repository. The audit side is written so that it
  cannot accept a private key path at all.
- The demo performs no network access, contacts no service and reads no
  credential store. Its only inputs are the repository and `git`.
- The demo creates its origin, workspaces and key material inside a
  temporary directory and removes it on exit.
- Nothing here is an approval. A green local run is not a release approval and
  not a deployment authorisation.

## What the demo does not protect against

The local Ed25519 keypair is a **local trust anchor**: anyone who can replace
the public key can sign anything. A production deployment needs keyless
provenance (Sigstore / OIDC), a protected CI identity and a trusted reviewer -
see the open items in [`docs/VALIDATION-SUMMARY.md`](docs/VALIDATION-SUMMARY.md).

The demonstration also does not sandbox anything: the "engineering agent" is a
deterministic patch function, not a model, and the workspace isolation it shows
is a directory, not a security boundary.
