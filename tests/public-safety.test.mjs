import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanFiles, scanRepository, listFiles, REPO_ROOT } from '../src/public-safety-check.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Fixtures are assembled from fragments so that no scannable literal marker and
// no reusable credential value ever exists in this repository's source.
const j = (...parts) => parts.join('');
const SYNTHETIC = 'SYNTHETIC_FIXTURE_NOT_A_CREDENTIAL';

function withFixture(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'banksec-safety-'));
  try {
    const relativePaths = [];
    for (const [relativePath, contents] of Object.entries(files)) {
      const absolute = join(dir, relativePath);
      mkdirSync(dirname(absolute), { recursive: true });
      writeFileSync(absolute, contents);
      relativePaths.push(relativePath);
    }
    return fn(dir, relativePaths);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const findingsFor = (files) => withFixture(files, (dir, paths) => scanFiles(dir, paths));

test('CP13: a PEM private key marker fails the safety check', () => {
  for (const header of [j('-----BEGIN PRIVATE', ' KEY-----'), j('-----BEGIN RSA PRIVATE', ' KEY-----')]) {
    const findings = findingsFor({ 'notes.md': `${header}\n${SYNTHETIC}\n` });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].kind, 'forbidden-content');
  }
});

test('CP14: GitHub token markers fail the safety check', () => {
  for (const prefix of [j('ghp', '_'), j('github', '_pat_')]) {
    const findings = findingsFor({ 'notes.md': `token: ${prefix}${SYNTHETIC}\n` });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].kind, 'forbidden-content');
  }
});

test('CP14b: an Anthropic API key marker fails the safety check', () => {
  const findings = findingsFor({ 'notes.md': `key: ${j('sk', '-ant-')}${SYNTHETIC}\n` });
  assert.equal(findings.length, 1);
});

test('CP15: a Postgres connection URL fails the safety check', () => {
  for (const scheme of [j('postgres', '://'), j('postgresql', '://')]) {
    const findings = findingsFor({ 'config.md': `${scheme}user:${SYNTHETIC}@host:5432/db\n` });
    assert.ok(findings.length >= 1);
    assert.equal(findings[0].kind, 'forbidden-content');
  }
});

test('CP16: dotenv files fail the safety check', () => {
  for (const name of ['.env', '.env.local', '.env.production']) {
    const findings = findingsFor({ [name]: `EXAMPLE=${SYNTHETIC}\n` });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].rule, 'dotenv');
  }
});

test('CP17: certificate and key files fail the safety check', () => {
  for (const [name, rule] of [
    ['server.pem', 'pem-file'],
    ['server.key', 'key-file'],
    ['bundle.p12', 'pkcs12-file'],
    ['bundle.pfx', 'pkcs12-file']
  ]) {
    const findings = findingsFor({ [name]: `${SYNTHETIC}\n` });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].rule, rule);
  }
});

test('ordinary public content passes the safety check', () => {
  assert.deepEqual(findingsFor({ 'README.md': '# public control plane\n' }), []);
});

test('CP19: this repository carries no credential, dotenv or key material', () => {
  assert.deepEqual(scanRepository(ROOT), []);
  assert.equal(resolve(REPO_ROOT), ROOT);

  const run = spawnSync(process.execPath, [join(ROOT, 'src', 'public-safety-check.mjs')], { encoding: 'utf8' });
  assert.equal(run.status, 0);
  assert.match(run.stdout, /PUBLICATION SAFETY CHECK: PASS/);

  const tracked = spawnSync('git', ['-C', ROOT, 'ls-files'], { encoding: 'utf8' });
  if (tracked.status === 0) {
    const files = tracked.stdout.split('\n').filter(Boolean);
    assert.deepEqual(scanFiles(ROOT, files), []);
  }
});

test('CP20: no npm dependency of any kind is declared', () => {
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
  const repoFiles = listFiles(ROOT);
  assert.equal(repoFiles.includes('package-lock.json'), false);
  assert.equal(
    repoFiles.some((file) => file.startsWith('node_modules')),
    false
  );
});
