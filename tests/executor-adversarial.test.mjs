import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateTarget, loadSchema, CONTROL_PLANE_SCHEMA_ID, SCHEMA_PATH } from '../src/validate-target.mjs';
import { runExecutorCore } from '../src/executor/executor-core.mjs';
import { verifyTrust, TRUST_STATES } from '../src/executor/trust-verifier.mjs';
import * as constants from '../src/executor/constants.mjs';
import { TRUSTED_PATHS } from '../src/executor/constants.mjs';
import { scanRepository } from '../src/public-safety-check.mjs';
import {
  activeManifest,
  bootstrapManifest,
  completeTrustSurface,
  stubReader,
  honestContents,
  syntheticBytes,
  sha256Hex,
  SYNTHETIC_COMMIT,
  SYNTHETIC_HEAD
} from './executor-fixtures.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIGEST = 'b'.repeat(64);
const invalid = (manifest) => assert.equal(validateTarget(manifest).valid, false);
const valid = (manifest) => {
  const outcome = validateTarget(manifest);
  assert.deepEqual(outcome.errors, []);
};

function sourceFiles(directory) {
  const found = [];
  for (const entry of readdirSync(directory).sort()) {
    const child = join(directory, entry);
    if (statSync(child).isDirectory()) found.push(...sourceFiles(child));
    else if (child.endsWith('.mjs')) found.push(child);
  }
  return found;
}

const SOURCES = sourceFiles(join(ROOT, 'src')).map((file) => ({
  file: file.slice(ROOT.length + 1),
  text: readFileSync(file, 'utf8')
}));

// ---------------------------------------------------------------- manifest --

test('E04: another owner is rejected', () => {
  for (const owner of ['someone-else', 'ftkleinx', 'FTKLEIN', '']) {
    const manifest = bootstrapManifest();
    manifest.target.owner = owner;
    invalid(manifest);
  }
});

test('E05: another repository is rejected', () => {
  for (const repository of ['guardiaosystem', 'GuardiaoSystem2', 'other-repo', '']) {
    const manifest = bootstrapManifest();
    manifest.target.repository = repository;
    invalid(manifest);
  }
});

test('E06: another status context is rejected', () => {
  for (const context of ['banksec/other-gate', 'ci/tests', 'banksec/trusted-gate ', '']) {
    const manifest = bootstrapManifest();
    manifest.statusContext = context;
    invalid(manifest);
  }
});

test('E07: ACTIVE with one file is rejected', () => {
  invalid(activeManifest([{ path: TRUSTED_PATHS[0], sha256: DIGEST }]));
});

test('E08: ACTIVE with three files is rejected', () => {
  invalid(activeManifest(completeTrustSurface().slice(0, 3)));
});

test('E09: ACTIVE with five files is rejected', () => {
  const surface = completeTrustSurface();
  surface.push({ path: TRUSTED_PATHS[0], sha256: DIGEST });
  invalid(activeManifest(surface));
});

test('E10: ACTIVE with a duplicated path is rejected, even with different digests', () => {
  const surface = completeTrustSurface();
  surface[3] = { path: surface[0].path, sha256: 'c'.repeat(64) };
  assert.equal(surface.length, 4);
  assert.notEqual(surface[3].sha256, surface[0].sha256);
  invalid(activeManifest(surface));
});

test('E11: ACTIVE missing one of the four paths is rejected', () => {
  for (let index = 0; index < TRUSTED_PATHS.length; index += 1) {
    const surface = completeTrustSurface().filter((_, position) => position !== index);
    surface.push({ path: TRUSTED_PATHS[(index + 1) % TRUSTED_PATHS.length], sha256: DIGEST });
    assert.equal(surface.length, 4);
    invalid(activeManifest(surface));
  }
});

test('E12: ACTIVE with an extra path outside the surface is rejected', () => {
  const surface = completeTrustSurface();
  surface[2] = { path: 'security/banksec/extra.md', sha256: DIGEST };
  invalid(activeManifest(surface));
  const withWorkflow = completeTrustSurface();
  withWorkflow[1] = { path: '.github/workflows/banksec-post-merge.yml', sha256: DIGEST };
  invalid(activeManifest(withWorkflow));
});

test('E13: a short approved commit is rejected', () => {
  for (const commit of [SYNTHETIC_COMMIT.slice(0, 39), SYNTHETIC_COMMIT.slice(0, 7), '']) {
    const manifest = activeManifest();
    manifest.trust.approvedCommit = commit;
    invalid(manifest);
  }
});

test('E14: an uppercase approved commit is rejected', () => {
  const manifest = activeManifest();
  manifest.trust.approvedCommit = SYNTHETIC_COMMIT.toUpperCase();
  invalid(manifest);
});

test('E15: a short sha256 is rejected', () => {
  const surface = completeTrustSurface();
  surface[1].sha256 = 'b'.repeat(63);
  invalid(activeManifest(surface));
});

test('E16: an uppercase sha256 is rejected', () => {
  const surface = completeTrustSurface();
  surface[2].sha256 = surface[2].sha256.toUpperCase();
  invalid(activeManifest(surface));
});

test('a complete, well formed ACTIVE manifest is accepted', () => {
  valid(activeManifest());
});

test('the committed manifest is still BOOTSTRAP_PENDING and still valid', () => {
  const committed = JSON.parse(readFileSync(join(ROOT, 'targets', 'guardiao.json'), 'utf8'));
  valid(committed);
  assert.equal(committed.trust.state, 'BOOTSTRAP_PENDING');
  assert.equal(committed.trust.approvedCommit, null);
  assert.deepEqual(committed.trust.trustedFiles, []);
});

// ---------------------------------------------------------------- hygiene ---

test('E35: no executor source uses a child process', () => {
  for (const { file, text } of SOURCES) {
    for (const forbidden of ['child_process', 'execSync', 'spawnSync', 'execFile']) {
      assert.equal(text.includes(forbidden), false, `${file} must not reference ${forbidden}`);
    }
  }
});

test('E36: no executor source uses eval', () => {
  for (const { file, text } of SOURCES) {
    assert.doesNotMatch(text, /(^|[^A-Za-z0-9_.])eval\s*\(/m, `${file} must not use eval`);
  }
});

test('E37: no executor source constructs functions from strings', () => {
  for (const { file, text } of SOURCES) {
    assert.doesNotMatch(text, /new\s+Function\s*\(/, `${file} must not use new Function`);
    // A bare `Function(...)` call is only dangerous when it is actually given
    // something to compile; the pattern is written so that prose mentioning
    // "Function()" in a comment is not a false positive.
    assert.doesNotMatch(text, /(^|[^A-Za-z0-9_.])Function\s*\(\s*[^)\s]/m, `${file} must not compile code at runtime`);
    assert.doesNotMatch(text, /\.constructor\s*\(\s*['"`]/, `${file} must not reach a constructor with a string`);
    assert.doesNotMatch(text, /AsyncFunction|GeneratorFunction/, `${file} must not reach the Function constructor`);
  }
});

test('E38: bytes from the target are only hashed, never executed or imported', async () => {
  const hostile = new Map(honestContents());
  // Synthetic hostile payloads: shell, JS and SQL shaped, deliberately inert.
  const payloads = {
    [TRUSTED_PATHS[0]]: '#!/bin/sh\nrm -rf /tmp/should-never-run\n',
    [TRUSTED_PATHS[1]]: 'globalThis.__banksec_pwned = true;\n',
    [TRUSTED_PATHS[2]]: 'export default () => { throw new Error("imported"); }\n',
    [TRUSTED_PATHS[3]]: 'DROP TABLE users; -- should never be executed\n'
  };
  const surface = [];
  for (const [path, payload] of Object.entries(payloads)) {
    const bytes = Buffer.from(payload, 'utf8');
    hostile.set(path, bytes);
    surface.push({ path, sha256: sha256Hex(bytes) });
  }

  const outcome = await verifyTrust({ manifest: activeManifest(surface), reader: stubReader(hostile) });
  // The digests match, so the surface verifies — and nothing ran.
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_VERIFIED);
  assert.equal(globalThis.__banksec_pwned, undefined);
  for (const { file, text } of SOURCES) {
    assert.doesNotMatch(text, /import\s*\(/, `${file} must not use dynamic import`);
    assert.equal(text.includes('vm.runIn'), false, `${file} must not use the vm module`);
  }
});

test('E39: BOOTSTRAP_PENDING triggers no network request at all', async () => {
  let transportCalls = 0;
  const transport = async () => {
    transportCalls += 1;
    return { status: 200, redirected: false, body: {} };
  };
  const reader = async (request) => transport(request);
  const outcome = await runExecutorCore({
    manifest: bootstrapManifest(),
    reader,
    targetHeadSha: SYNTHETIC_HEAD
  });
  assert.equal(transportCalls, 0);
  assert.equal(outcome.readerCallCount, 0);
  assert.equal(outcome.trustState, TRUST_STATES.NOT_TRUSTED);
});

test('E39b: no executor source performs a network call of its own', () => {
  for (const { file, text } of SOURCES) {
    if (file.endsWith('github-reader.mjs')) {
      // The reader only ever calls the transport it was handed.
      assert.equal(text.includes('globalThis.fetch'), false);
      assert.doesNotMatch(text, /(^|[^.\w])fetch\s*\(/m, `${file} must only use the injected transport`);
    }
    for (const forbidden of ['node:http', 'node:https', 'node:net', 'node:dgram', 'undici']) {
      assert.equal(text.includes(forbidden), false, `${file} must not reference ${forbidden}`);
    }
  }
});

test('E40: no filesystem write is provoked by target bytes', async () => {
  const sandbox = mkdtempSync(join(tmpdir(), 'banksec-fs-'));
  try {
    const before = readdirSync(sandbox);
    const hostile = new Map(honestContents());
    hostile.set(TRUSTED_PATHS[0], Buffer.from(`require('fs').writeFileSync('${sandbox}/pwned', 'x')\n`, 'utf8'));
    const surface = completeTrustSurface();
    surface[0].sha256 = sha256Hex(hostile.get(TRUSTED_PATHS[0]));
    const outcome = await runExecutorCore({
      manifest: activeManifest(surface),
      reader: stubReader(hostile),
      targetHeadSha: SYNTHETIC_HEAD
    });
    assert.equal(outcome.trustState, TRUST_STATES.TRUST_VERIFIED);
    assert.deepEqual(readdirSync(sandbox), before);
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }

  for (const { file, text } of SOURCES) {
    if (file.startsWith('src/executor/')) {
      assert.equal(text.includes('node:fs'), false, `${file} must not touch the filesystem`);
    }
    for (const forbidden of ['writeFileSync', 'appendFileSync', 'createWriteStream', 'mkdirSync', 'rmSync']) {
      assert.equal(text.includes(forbidden), false, `${file} must not write to disk`);
    }
  }
});

test('E41: no external npm dependency is declared or installed', () => {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  for (const field of [
    'dependencies',
    'devDependencies',
    'peerDependencies',
    'optionalDependencies',
    'bundledDependencies'
  ]) {
    assert.equal(Object.prototype.hasOwnProperty.call(manifest, field), false, `${field} must not be declared`);
  }
  for (const { file, text } of SOURCES) {
    for (const match of text.matchAll(/from\s+'([^']+)'/g)) {
      const specifier = match[1];
      assert.ok(
        specifier.startsWith('node:') || specifier.startsWith('./') || specifier.startsWith('../'),
        `${file} imports a non built-in, non relative module: ${specifier}`
      );
    }
  }
});

test('E42: the publication safety check still passes on the whole repository', () => {
  assert.deepEqual(scanRepository(ROOT), []);
});

test('constants expose only the four public values, and no secret', () => {
  assert.deepEqual(Object.keys(constants).sort(), [
    'STATUS_CONTEXT',
    'TARGET_OWNER',
    'TARGET_REPOSITORY',
    'TRUSTED_PATHS'
  ]);
  assert.equal(constants.TARGET_OWNER, 'ftklein');
  assert.equal(constants.TARGET_REPOSITORY, 'GuardiaoSystem');
  assert.equal(constants.STATUS_CONTEXT, 'banksec/trusted-gate');
  assert.deepEqual([...constants.TRUSTED_PATHS], [
    'security/banksec/security-cycle.sh',
    'security/banksec/ci-review.md',
    'security/banksec/baseline.md',
    'security/banksec/postgres-banksec-readonly.sql'
  ]);
  assert.ok(Object.isFrozen(constants.TRUSTED_PATHS));
});

test('no executor source reads the environment or holds a credential', () => {
  for (const { file, text } of SOURCES) {
    if (!file.startsWith('src/executor/')) continue;
    for (const forbidden of ['process.env', 'Authorization', 'Bearer ']) {
      assert.equal(text.includes(forbidden), false, `${file} must not reference ${forbidden}`);
    }
    // A credential would have to be bound to something; prose about tokens in a
    // comment is not a credential.
    assert.doesNotMatch(text, /\b(token|apiKey|api_key|secret|password)\s*[:=]/i, `${file} must not bind a credential`);
  }
});

test('importing the executor has no side effect', async () => {
  const before = { ...globalThis };
  await import('../src/executor/executor-core.mjs');
  assert.deepEqual(Object.keys(globalThis).sort(), Object.keys(before).sort());
});

test('synthetic fixtures never resemble a real digest of a real file', () => {
  // Fixture bytes are self-describing placeholders, and the approved commit is
  // an obvious counting pattern, not a commit of any repository.
  assert.match(syntheticBytes(TRUSTED_PATHS[0]).toString('utf8'), /^synthetic fixture content/);
  assert.equal(SYNTHETIC_COMMIT, '0123456789abcdef0123456789abcdef01234567');
});

// Regression for Codex finding 4 (PR #1): the semantic invariants were gated on
// the presence of `oneOf`, so any caller-supplied schema with a `oneOf` branch
// received BankSec-specific owner, repository, status and trust-surface errors.
test('R4: BankSec invariants never leak into a caller-supplied schema', () => {
  const custom = { oneOf: [{ type: 'object' }] };
  const result = validateTarget({ target: { owner: 'acme', repository: 'anything' } }, custom);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);

  const anotherShape = validateTarget(
    { statusContext: 'ci/build', trust: { state: 'ACTIVE', trustedFiles: [] } },
    { oneOf: [{ type: 'object' }] }
  );
  assert.deepEqual(anotherShape.errors, []);

  // The control plane's own schema still applies them in full.
  const schema = loadSchema();
  assert.equal(schema.$id, CONTROL_PLANE_SCHEMA_ID);
  const wrongOwner = activeManifest();
  wrongOwner.target.owner = 'acme';
  assert.match(validateTarget(wrongOwner, schema).errors.join('\n'), /governs only ftklein/);
});

test('R4b: a schema without the control plane identity is refused outright', () => {
  const schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8'));
  assert.equal(schema.$id, CONTROL_PLANE_SCHEMA_ID);

  const sandbox = mkdtempSync(join(tmpdir(), 'banksec-schema-'));
  try {
    const stripped = join(sandbox, 'target.schema.json');
    const { $id, ...withoutId } = schema;
    writeFileSync(stripped, JSON.stringify(withoutId));
    assert.throws(() => loadSchema(stripped), /missing the control plane \$id/);
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
});
