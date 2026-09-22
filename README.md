# guardiao-banksec-control

Independent trust control plane for Guardião BankSec.

**Current trust state: `BOOTSTRAP_PENDING` — nothing is trusted, nothing is approved.**

## What this repository is

This is the *root of trust* for the BankSec security gate: a small, public,
dependency-free control plane that declares which target repository is governed,
which commit (if any) has been explicitly approved, and which files make up the
trust surface. It is deliberately separate from the system it governs, so the
gate cannot be moved by the thing being gated.

It holds declarations and the code that validates them. It does not hold, and
will never hold, the thing it protects.

## What this repository is **not**

- It is **public** — assume every byte here is world-readable, forever.
- It contains **no proprietary GuardiãoSystem source code**. GuardiãoSystem
  remains a private repository.
- It contains **no secrets**: no tokens, no API keys, no database URLs, no
  environment files, no certificates, no private keys. None are configured for
  this repository either.
- It **does not execute code that comes from private pull requests**, and its CI
  has `contents: read` only.
- It **does not contain BankSec reports, customer data, legal data, database
  contents or CI output** from the private system.

## Trust states

The manifest in [`targets/guardiao.json`](targets/guardiao.json) is validated
against [`schemas/target.schema.json`](schemas/target.schema.json) and may only
be in one of two states:

| State | `approvedCommit` | `trustedFiles` | Meaning |
| --- | --- | --- | --- |
| `BOOTSTRAP_PENDING` | must be `null` | must be empty | No trust has been granted. **Never authorizes a merge.** |
| `ACTIVE` | 40 lowercase hex characters | **exactly these four paths**, each once, each with a SHA-256 digest | An operator has explicitly approved one commit and the complete trust surface. |

The trust surface is closed: only these paths may ever appear in `trustedFiles`.

```
security/banksec/security-cycle.sh
security/banksec/ci-review.md
security/banksec/baseline.md
security/banksec/postgres-banksec-readonly.sql
```

Arbitrary paths coming from a manifest are rejected by the schema, not by
convention. An `ACTIVE` manifest must pin **all four** — a partial surface is
never legitimate, because an unpinned file is an unverified file. The schema
bounds the count; `src/validate-target.mjs` additionally enforces exact set
equality and rejects a duplicated path even when its digests differ.

The governed target is fixed too: `owner`, `repository` and `statusContext` are
schema constants. This control plane cannot be pointed at another repository by
editing a manifest.

## The trusted executor core

`src/executor/` decides whether the pinned trust surface is intact. It is
deterministic, dependency-free and entirely driven by injected components.

| Module | Responsibility |
| --- | --- |
| `constants.mjs` | The four public constants. Never a token, URL or secret. |
| `github-reader.mjs` | Reads one pinned file at one exact commit. HTTPS only, `api.github.com` only, no redirects, base64 only, 4 MiB cap, and only paths inside the trust surface at the approved commit. The HTTP transport is always injected. |
| `trust-verifier.mjs` | Hashes the bytes and compares them, in constant time, against the pinned digests. |
| `status-policy.mjs` | Decides offline whether a status *would* be permitted. Publishes nothing. |
| `executor-core.mjs` | Orchestrates the above. No ambient credentials, no environment reads, no import-time side effects. |

Trust states, and what each permits:

| State | Meaning | Gate success |
| --- | --- | --- |
| `NOT_TRUSTED` | `BOOTSTRAP_PENDING`, an invalid manifest, or the wrong target. No file is ever read. | prohibited |
| `TRUST_UNDETERMINED` | A read did not conclude — transport error, non-2xx, unexpected or malformed payload. | prohibited |
| `TRUST_MISMATCH` | A pinned file is absent, or its bytes do not hash to the pinned digest. | prohibited |
| `TRUST_VERIFIED` | All four files match. | **still prohibited in this phase** |

`TRUST_VERIFIED` is a *precondition*, not a verdict. It is deliberately not the
`banksec/trusted-gate` status, which stays reserved for a later phase combining
the trusted executor with deterministic BankSec, semantic BankSec and HEAD
binding. No function in this repository can turn one into the other, and
`canPublishTrustedGateSuccess()` refuses for every input.

### Bytes from the target are data, never code

Everything read from the target repository is hashed and nothing else. It is
never executed, imported, sourced, evaluated, interpreted as shell or SQL, run
as a package script, loaded as a workflow or a git hook, or checked out. No
`child_process`, no `eval`, no `Function()`, no dynamic import, no filesystem
write — each of these is asserted by a test over the sources themselves.

### Phase 2A has made no call against the target

The reader has never been pointed at the real repository. Every test drives it
through an injected transport with synthetic fixtures, no credential exists in
this repository, and none is read from the environment.

## Phase 1 scope

This is the bootstrap phase. On purpose:

- the initial and only state is `BOOTSTRAP_PENDING`;
- **no commit of the target repository is approved**, and no file digest is
  recorded;
- `verify-trust.mjs` **never contacts the target repository**. The remote
  verification executor is not installed yet and will be delivered in a later,
  separately authorized phase;
- `BOOTSTRAP_PENDING` exits with status `2`. That is the expected, designed
  outcome — it is a refusal to grant trust, and CI asserts it as such. It is
  never converted into a pass.

## Tools

```bash
node --test                                      # unit tests
node src/validate-target.mjs targets/guardiao.json   # schema validation (exit 0 = valid manifest)
node src/verify-trust.mjs targets/guardiao.json      # trust state (exit 2 = BOOTSTRAP_PENDING)
node src/public-safety-check.mjs                     # refuse to publish private material
```

Exit codes of `verify-trust.mjs`: `0` reserved for a future verified pass (no
code path returns it today), `1` invalid manifest, `2` `BOOTSTRAP_PENDING`,
`3` `ACTIVE` but structure-only because the executor is not installed, `64`
usage.

## Dependencies

None. Node.js built-ins only (`node:test`, `node:fs`, `node:path`,
`node:url`). `package.json` declares no `dependencies` and no
`devDependencies`, and a test asserts that this stays true. Requires Node 20+.

## Security

See [SECURITY.md](SECURITY.md).
