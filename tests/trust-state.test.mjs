import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  describe as describeTrust,
  EXIT_BOOTSTRAP_PENDING,
  EXIT_EXECUTOR_NOT_INSTALLED,
  EXIT_INVALID,
  EXIT_TRUSTED
} from '../src/verify-trust.mjs';
import { validateTargetFile } from '../src/validate-target.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'src', 'verify-trust.mjs');
const MANIFEST = join(ROOT, 'targets', 'guardiao.json');

function runVerify(manifestPath) {
  const run = spawnSync(process.execPath, [SCRIPT, manifestPath], { encoding: 'utf8' });
  return { code: run.status, output: `${run.stdout}${run.stderr}` };
}

function withTempManifest(contents, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'banksec-trust-'));
  try {
    const path = join(dir, 'target.json');
    writeFileSync(path, JSON.stringify(contents, null, 2));
    return fn(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('CP11: verify-trust on the committed BOOTSTRAP_PENDING manifest exits 2', () => {
  const { code, output } = runVerify(MANIFEST);
  assert.equal(code, EXIT_BOOTSTRAP_PENDING);
  assert.equal(code, 2);
  assert.match(output, /TRUST STATE: BOOTSTRAP_PENDING/);
  assert.match(output, /TRUST RESULT: NOT TRUSTED/);
});

test('CP12: BOOTSTRAP_PENDING never reports a trust pass', () => {
  const { code, output } = runVerify(MANIFEST);
  assert.notEqual(code, EXIT_TRUSTED);
  assert.doesNotMatch(output, /\bPASS\b/);
  for (const line of output.split('\n')) {
    if (line.includes('TRUSTED')) assert.match(line, /NOT TRUSTED/);
  }

  const result = validateTargetFile(MANIFEST);
  assert.equal(describeTrust(result).code, EXIT_BOOTSTRAP_PENDING);
});

test('CP12b: a structurally valid ACTIVE manifest still does not report a trust pass', () => {
  const activeManifest = {
    schemaVersion: 1,
    target: { owner: 'ftklein', repository: 'GuardiaoSystem' },
    statusContext: 'banksec/trusted-gate',
    trust: {
      state: 'ACTIVE',
      approvedCommit: 'c'.repeat(40),
      // The complete four-file trust surface: an ACTIVE manifest is only
      // structurally valid with all of it, and this test needs a valid one.
      trustedFiles: [
        { path: 'security/banksec/security-cycle.sh', sha256: 'd'.repeat(64) },
        { path: 'security/banksec/ci-review.md', sha256: 'e'.repeat(64) },
        { path: 'security/banksec/baseline.md', sha256: 'f'.repeat(64) },
        { path: 'security/banksec/postgres-banksec-readonly.sql', sha256: '0'.repeat(64) }
      ]
    }
  };
  withTempManifest(activeManifest, (path) => {
    const { code, output } = runVerify(path);
    assert.equal(code, EXIT_EXECUTOR_NOT_INSTALLED);
    assert.notEqual(code, EXIT_TRUSTED);
    assert.match(output, /executor is NOT installed/);
    assert.doesNotMatch(output, /\bPASS\b/);
  });
});

test('an invalid manifest is reported as not trusted', () => {
  withTempManifest({ schemaVersion: 1 }, (path) => {
    const { code, output } = runVerify(path);
    assert.equal(code, EXIT_INVALID);
    assert.match(output, /NOT TRUSTED/);
  });
});

test('verify-trust never contacts the target repository in this phase', () => {
  const source = spawnSync(process.execPath, ['-e', `process.stdout.write(require('fs').readFileSync(${JSON.stringify(SCRIPT)}, 'utf8'))`], { encoding: 'utf8' }).stdout;
  for (const forbidden of ['node:http', 'node:https', 'fetch(', 'node:child_process', 'api.github.com']) {
    assert.equal(source.includes(forbidden), false, `verify-trust.mjs must not reference ${forbidden}`);
  }
});
