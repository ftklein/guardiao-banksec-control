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
| `ACTIVE` | 40 lowercase hex characters | at least one entry, each with a SHA-256 digest | An operator has explicitly approved one commit and one trust surface. |

The trust surface is closed: only these paths may ever appear in `trustedFiles`.

```
security/banksec/security-cycle.sh
security/banksec/ci-review.md
security/banksec/baseline.md
security/banksec/postgres-banksec-readonly.sql
```

Arbitrary paths coming from a manifest are rejected by the schema, not by
convention.

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
