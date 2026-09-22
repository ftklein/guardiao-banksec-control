# Security policy

This repository is **public**. Treat every commit as permanently disclosed.

## Never commit

- credentials of any kind — access tokens, API keys, passwords, session tokens;
- private source code from GuardiãoSystem or any other private repository;
- database contents, dumps, connection strings or query output;
- customer information or any personal data;
- legal data, case material or client documents;
- private BankSec reports, findings or remediation detail;
- any other private Guardião artifact, including CI logs and build output from
  the private system;
- environment files, PEM-encoded key material, certificate bundles or keystores
  (`.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`).

No GitHub secret, environment or repository variable is configured here, and
none should be created while the control plane is in its bootstrap phase.

## Automated guard

`src/public-safety-check.mjs` runs in CI and fails the build on unmistakable
markers of credential material (PEM private-key headers, GitHub personal access
token prefixes, Anthropic API key prefixes, PostgreSQL connection URLs) and on
forbidden file types. It is a last line of defence, not a substitute for
judgement: it detects the obvious, not the clever.

Test fixtures only ever use synthetic, structurally inert values assembled at
runtime. No fixture in this repository contains a reusable or plausibly valid
credential.

## If private material is committed by accident

1. **Stop publishing.** Do not push further commits and do not merge.
2. **Revoke the exposed credential immediately**, if one is involved. Assume it
   is compromised from the moment it was pushed — rotation comes before cleanup.
3. **Remove it from history**, not just from the tip commit. A revert leaves the
   content reachable.
4. **Assess the exposure** — what was disclosed, for how long, to whom it may
   have been visible, and whether any downstream system must be rotated too —
   and record the outcome before any further work continues.

## Data read from the target repository

The executor treats every byte it reads from the governed repository as
untrusted data. It is hashed and compared, and nothing else: it is never
executed, imported, evaluated, interpreted as a shell command or as SQL, run as
a package script, or loaded as a workflow, git hook or submodule, and no
checkout of the target is ever performed. Tests assert these properties against
the sources directly, so the guarantee cannot quietly decay.

A read that does not conclude is never resolved optimistically. An HTTP 404 is
treated as inconclusive rather than as proof of absence, because a 404 can also
mean the wrong ref, the wrong repository or insufficient access.

## Reporting

Report a suspected exposure or a weakness in this control plane privately to the
repository owner. Do not open a public issue containing the material itself.
