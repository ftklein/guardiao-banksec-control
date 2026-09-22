import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateTarget, loadSchema } from '../src/validate-target.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCHEMA = loadSchema();

const COMMIT = 'a'.repeat(40);
const DIGEST = 'b'.repeat(64);

// An ACTIVE manifest is only structurally valid with the complete four-file
// trust surface, so the shared helper builds exactly that. Each test then
// injects the single defect it is about, and asserts that the manifest is
// rejected *for that defect* — never incidentally for a wrong file count.
const TRUST_SURFACE = [
  'security/banksec/security-cycle.sh',
  'security/banksec/ci-review.md',
  'security/banksec/baseline.md',
  'security/banksec/postgres-banksec-readonly.sql'
];
const SYNTHETIC_DIGESTS = ['b', 'c', 'd', 'e'].map((character) => character.repeat(64));
const completeSurface = () => TRUST_SURFACE.map((path, index) => ({ path, sha256: SYNTHETIC_DIGESTS[index] }));

function manifest(trust) {
  return {
    schemaVersion: 1,
    target: { owner: 'ftklein', repository: 'GuardiaoSystem' },
    statusContext: 'banksec/trusted-gate',
    trust
  };
}

const bootstrap = () => manifest({ state: 'BOOTSTRAP_PENDING', approvedCommit: null, trustedFiles: [] });
const active = (overrides = {}) =>
  manifest({
    state: 'ACTIVE',
    approvedCommit: COMMIT,
    trustedFiles: completeSurface(),
    ...overrides
  });

const assertValid = (value) => {
  const result = validateTarget(value, SCHEMA);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
};
const assertInvalid = (value) => assert.equal(validateTarget(value, SCHEMA).valid, false);

// Proves the rejection is caused by the defect under test and not by an
// unrelated, incidental violation such as an incomplete trust surface.
const assertInvalidBecause = (value, pattern) => {
  const result = validateTarget(value, SCHEMA);
  assert.equal(result.valid, false);
  const reported = result.errors.join('\n');
  assert.match(reported, pattern);
  assert.doesNotMatch(reported, /must pin exactly|trust surface is incomplete|duplicate path/);
};

test('CP1: BOOTSTRAP_PENDING manifest is valid', () => {
  assertValid(bootstrap());
});

test('CP2: BOOTSTRAP_PENDING with an approved commit is rejected', () => {
  const value = bootstrap();
  value.trust.approvedCommit = COMMIT;
  assertInvalid(value);
});

test('CP3: BOOTSTRAP_PENDING with a non-empty trust surface is rejected', () => {
  const value = bootstrap();
  value.trust.trustedFiles = [{ path: 'security/banksec/baseline.md', sha256: DIGEST }];
  assertInvalid(value);
});

test('CP4: ACTIVE with a null approved commit is rejected', () => {
  assertInvalidBecause(active({ approvedCommit: null }), /approvedCommit/);
});

test('CP5: ACTIVE with a short commit is rejected', () => {
  assertInvalidBecause(active({ approvedCommit: 'a'.repeat(39) }), /approvedCommit/);
});

test('CP6: ACTIVE with an uppercase commit is rejected', () => {
  assertInvalidBecause(active({ approvedCommit: 'A'.repeat(40) }), /approvedCommit/);
});

test('CP7: ACTIVE with an empty trust surface is rejected', () => {
  assertInvalid(active({ trustedFiles: [] }));
});

test('CP8: an invalid sha256 digest is rejected', () => {
  for (const bad of ['b'.repeat(63), 'B'.repeat(64), `${'b'.repeat(64)}c`, 'not-a-digest']) {
    const surface = completeSurface();
    surface[1].sha256 = bad;
    assertInvalidBecause(active({ trustedFiles: surface }), /sha256/);
  }
});

test('CP9: a path outside the allowlist is rejected', () => {
  for (const bad of [
    '.github/workflows/banksec-post-merge.yml',
    'security/banksec/../../etc/passwd',
    'security/banksec/security-cycle.sh ',
    'server/routes/auth.ts'
  ]) {
    const surface = completeSurface();
    surface[2] = { path: bad, sha256: DIGEST };
    assertInvalid(active({ trustedFiles: surface }));
  }
});

test('CP9b: the complete allowlisted trust surface is accepted', () => {
  // Exactly the four allowlisted paths, each once. A partial ACTIVE surface is
  // never legitimate, so this test asserts completeness, not per-path acceptance.
  const surface = completeSurface();
  assert.deepEqual(surface.map((entry) => entry.path), TRUST_SURFACE);
  assertValid(active({ trustedFiles: surface }));
  assertValid(active());

  // Removing any single path must break it.
  for (let index = 0; index < TRUST_SURFACE.length; index += 1) {
    assertInvalid(active({ trustedFiles: completeSurface().filter((_, position) => position !== index) }));
  }
});

test('CP10: unknown properties are rejected at every level', () => {
  const topLevel = bootstrap();
  topLevel.extra = true;
  assertInvalid(topLevel);

  const insideTrust = bootstrap();
  insideTrust.trust.bypass = true;
  assertInvalid(insideTrust);

  const insideTarget = bootstrap();
  insideTarget.target.token = 'x';
  assertInvalid(insideTarget);

  const insideFile = active();
  insideFile.trust.trustedFiles[0].executable = true;
  assertInvalidBecause(insideFile, /unknown property "executable"/);
});

test('CP10b: an unknown trust state is rejected', () => {
  assertInvalid(manifest({ state: 'TRUSTED', approvedCommit: COMMIT, trustedFiles: completeSurface() }));
});

test('CP18: the committed manifest is BOOTSTRAP_PENDING and grants nothing', () => {
  const committed = JSON.parse(readFileSync(join(ROOT, 'targets', 'guardiao.json'), 'utf8'));
  assertValid(committed);
  assert.equal(committed.trust.state, 'BOOTSTRAP_PENDING');
  assert.equal(committed.trust.approvedCommit, null);
  assert.deepEqual(committed.trust.trustedFiles, []);
  assert.equal(committed.target.owner, 'ftklein');
  assert.equal(committed.target.repository, 'GuardiaoSystem');
});

test('the validator fails closed on a schema keyword it does not implement', () => {
  const unsupported = { type: 'object', propertyNames: { pattern: '^x$' } };
  assert.equal(validateTarget({}, unsupported).valid, false);
});
