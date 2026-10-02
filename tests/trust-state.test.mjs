import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, cpSync, mkdirSync } from 'node:fs';
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
const WORKFLOW = join(ROOT, '.github', 'workflows', 'control-plane-tests.yml');
const GATE_STEP = 'Trust gate must be state-aware and is never a trust pass';

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

// The exact transcript verify-trust prints for each lifecycle state. This is
// an allowlist: anything else on the output is a failure, not a style choice.
const sha = (character) => character.repeat(40);
function transcript(state, commit = sha('1')) {
  const lines =
    state === 'ACTIVE'
      ? [
          'TRUST STATE: ACTIVE',
          'TRUST RESULT: UNDETERMINED (structure only)',
          `Manifest structure is well formed: approved commit ${commit}, 4 trusted file(s).`,
          'The remote verification executor is NOT installed in this phase, so the target',
          'repository was not contacted and no file digest was compared. This result must',
          'not be treated as a verified trust decision.'
        ]
      : [
          'TRUST STATE: BOOTSTRAP_PENDING',
          'TRUST RESULT: NOT TRUSTED',
          'No commit is approved and the trust surface is empty.',
          'BOOTSTRAP_PENDING never authorizes a merge in the target repository.'
        ];
  return lines.map((line) => `${line}\n`).join('');
}

// The committed manifest may legitimately be in either lifecycle state. What
// must hold in both is the security property, not the lifecycle: the static
// control plane never produces a trust pass.
function committedManifest() {
  const result = validateTargetFile(MANIFEST);
  assert.equal(result.valid, true, 'the committed manifest must be structurally valid');
  return result.manifest;
}

test('CP11: verify-trust on the committed manifest reports the exit code of its lifecycle state', () => {
  const { trust } = committedManifest();
  const { code, output } = runVerify(MANIFEST);

  assert.equal(EXIT_TRUSTED, 0, 'exit 0 stays reserved for a future executor');
  assert.equal(EXIT_BOOTSTRAP_PENDING, 2);
  assert.equal(EXIT_EXECUTOR_NOT_INSTALLED, 3);
  assert.notEqual(code, EXIT_TRUSTED);

  if (trust.state === 'BOOTSTRAP_PENDING') {
    assert.equal(code, EXIT_BOOTSTRAP_PENDING);
    assert.equal(code, 2);
    assert.equal(output, transcript('BOOTSTRAP_PENDING'));
  } else if (trust.state === 'ACTIVE') {
    assert.equal(code, EXIT_EXECUTOR_NOT_INSTALLED);
    assert.equal(code, 3);
    assert.equal(output, transcript('ACTIVE', trust.approvedCommit));
  } else {
    assert.fail(`unexpected lifecycle state: ${trust.state}`);
  }
});

test('CP12: the committed manifest never reports a trust pass, in any lifecycle state', () => {
  const { trust } = committedManifest();
  const { code, output } = runVerify(MANIFEST);
  assert.notEqual(code, EXIT_TRUSTED);

  // Allowlist first: the output is exactly the expected transcript, so no
  // success-looking line of any wording can be present alongside it.
  assert.equal(output, transcript(trust.state, trust.approvedCommit ?? undefined));

  // Belt and braces, kept from the original assertions.
  assert.doesNotMatch(output, /\bPASS\b/);
  for (const line of output.split('\n')) {
    if (line.includes('TRUSTED')) assert.match(line, /NOT TRUSTED/);
  }

  const expected = trust.state === 'ACTIVE' ? EXIT_EXECUTOR_NOT_INSTALLED : EXIT_BOOTSTRAP_PENDING;
  assert.equal(describeTrust(validateTargetFile(MANIFEST)).code, expected);
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

test('CP12c: a synthetic ACTIVE manifest validates, yet verify-trust is UNDETERMINED with exit 3', () => {
  const synthetic = {
    schemaVersion: 1,
    target: { owner: 'ftklein', repository: 'GuardiaoSystem' },
    statusContext: 'banksec/trusted-gate',
    trust: {
      state: 'ACTIVE',
      approvedCommit: '1'.repeat(40),
      trustedFiles: [
        { path: 'security/banksec/security-cycle.sh', sha256: '2'.repeat(64) },
        { path: 'security/banksec/ci-review.md', sha256: '3'.repeat(64) },
        { path: 'security/banksec/baseline.md', sha256: '4'.repeat(64) },
        { path: 'security/banksec/postgres-banksec-readonly.sql', sha256: '5'.repeat(64) }
      ]
    }
  };
  withTempManifest(synthetic, (path) => {
    // Form is valid ...
    const validation = validateTargetFile(path);
    assert.deepEqual(validation.errors, []);
    assert.equal(validation.valid, true);

    // ... and that validity is not trust.
    const { code, output } = runVerify(path);
    assert.equal(code, EXIT_EXECUTOR_NOT_INSTALLED);
    assert.equal(code, 3);
    assert.notEqual(code, EXIT_TRUSTED);
    assert.match(output, /TRUST STATE: ACTIVE/);
    assert.match(output, /TRUST RESULT: UNDETERMINED/);
    assert.match(output, /executor is NOT installed/);
    assert.doesNotMatch(output, /\bPASS\b/);
    assert.doesNotMatch(output, /TRUST RESULT: TRUSTED/);
    assert.equal(output, transcript('ACTIVE', '1'.repeat(40)));
  });
});

// --- The CI gate itself ---------------------------------------------------
// These tests run the REAL `run:` block of the workflow step under bash, so a
// weakened gate fails here, not only in CI.

function extractGateScript() {
  const lines = readFileSync(WORKFLOW, 'utf8').split('\n');
  const nameIndex = lines.findIndex((line) => line.includes(`- name: ${GATE_STEP}`));
  assert.notEqual(nameIndex, -1, 'the gate step must exist in the workflow');
  const runIndex = lines.findIndex((line, index) => index > nameIndex && /^\s+run: \|\s*$/.test(line));
  assert.notEqual(runIndex, -1, 'the gate step must have a run block');
  const runIndent = lines[runIndex].match(/^\s*/)[0].length;
  const body = [];
  for (let index = runIndex + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim() === '') {
      body.push('');
      continue;
    }
    if (line.match(/^\s*/)[0].length <= runIndent) break;
    body.push(line.slice(runIndent + 2));
  }
  return `${body.join('\n')}\n`;
}

function runGate(prepare) {
  const dir = mkdtempSync(join(tmpdir(), 'banksec-gate-'));
  try {
    mkdirSync(join(dir, 'src'));
    mkdirSync(join(dir, 'targets'));
    prepare(dir);
    writeFileSync(join(dir, 'gate.sh'), extractGateScript());
    const run = spawnSync('bash', ['-e', 'gate.sh'], { cwd: dir, encoding: 'utf8' });
    return { code: run.status, output: `${run.stdout}${run.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// A stand-in verifier that prints `text` verbatim on stderr and exits `exitCode`.
function gateAgainstStub(text, exitCode) {
  return runGate((dir) => {
    writeFileSync(join(dir, 'targets', 'guardiao.json'), '{}');
    writeFileSync(
      join(dir, 'src', 'verify-trust.mjs'),
      `process.stderr.write(${JSON.stringify(text)});\nprocess.exit(${exitCode});\n`
    );
  });
}

// The real verifier and schema, against a manifest of our choosing.
function gateAgainstRealVerifier(manifestPath) {
  return runGate((dir) => {
    cpSync(join(ROOT, 'src'), join(dir, 'src'), { recursive: true });
    cpSync(join(ROOT, 'schemas'), join(dir, 'schemas'), { recursive: true });
    cpSync(manifestPath, join(dir, 'targets', 'guardiao.json'));
  });
}

const SYNTHETIC_ACTIVE = {
  schemaVersion: 1,
  target: { owner: 'ftklein', repository: 'GuardiaoSystem' },
  statusContext: 'banksec/trusted-gate',
  trust: {
    state: 'ACTIVE',
    approvedCommit: '1'.repeat(40),
    trustedFiles: [
      { path: 'security/banksec/security-cycle.sh', sha256: '2'.repeat(64) },
      { path: 'security/banksec/ci-review.md', sha256: '3'.repeat(64) },
      { path: 'security/banksec/baseline.md', sha256: '4'.repeat(64) },
      { path: 'security/banksec/postgres-banksec-readonly.sql', sha256: '5'.repeat(64) }
    ]
  }
};

const STATES = [
  { state: 'BOOTSTRAP_PENDING', exit: 2 },
  { state: 'ACTIVE', exit: 3 }
];

test('gate: accepts the exact allowed transcript of each lifecycle state with its own exit code', () => {
  for (const { state, exit } of STATES) {
    const outcome = gateAgainstStub(transcript(state), exit);
    assert.equal(outcome.code, 0, `${state}: ${outcome.output}`);
  }
});

test('gate: accepts the real verifier output for the committed manifest and for a synthetic ACTIVE', () => {
  const committed = gateAgainstRealVerifier(MANIFEST);
  assert.equal(committed.code, 0, committed.output);

  withTempManifest(SYNTHETIC_ACTIVE, (path) => {
    const outcome = gateAgainstRealVerifier(path);
    assert.equal(outcome.code, 0, outcome.output);
  });
});

test('gate: rejects an otherwise valid transcript with a success-looking line added anywhere', () => {
  const extras = [
    'VERIFICATION PASSED',
    'RESULT: SUCCESS',
    'TRUST RESULT: VERIFIED',
    'VERIFIED',
    'SUCCESS',
    'PASSED',
    'PASS'
  ];
  for (const { state, exit } of STATES) {
    const lines = transcript(state).split('\n').slice(0, -1);
    for (const extra of extras) {
      const variants = {
        appended: [...lines, extra],
        prepended: [extra, ...lines],
        inserted: [lines[0], extra, ...lines.slice(1)]
      };
      for (const [where, variant] of Object.entries(variants)) {
        const outcome = gateAgainstStub(`${variant.join('\n')}\n`, exit);
        assert.equal(outcome.code, 1, `${state} + "${extra}" (${where}) must be rejected`);
        assert.match(outcome.output, /::error::/);
      }
    }
  }
});

test('gate: rejects any deviation from the exact transcript', () => {
  const active = transcript('ACTIVE').split('\n').slice(0, -1);
  const bootstrap = transcript('BOOTSTRAP_PENDING').split('\n').slice(0, -1);
  const join_ = (lines) => `${lines.join('\n')}\n`;
  const cases = [
    ['ACTIVE: a line is missing', join_(active.slice(0, -1)), 3],
    ['ACTIVE: the executor line is missing', join_(active.filter((l) => !l.includes('executor'))), 3],
    ['ACTIVE: lines are reordered', join_([active[1], active[0], ...active.slice(2)]), 3],
    ['ACTIVE: a trailing blank line', `${join_(active)}\n`, 3],
    ['ACTIVE: the verdict is rewritten', join_(active.map((l) => l.replace('UNDETERMINED (structure only)', 'VERIFIED'))), 3],
    ['ACTIVE: the verdict is NOT TRUSTED', join_(active.map((l) => l.replace('UNDETERMINED (structure only)', 'NOT TRUSTED'))), 3],
    ['ACTIVE: uppercase commit', join_(active.map((l) => l.replace(sha('1'), sha('A')))), 3],
    ['ACTIVE: short commit', join_(active.map((l) => l.replace(sha('1'), '1'.repeat(39)))), 3],
    ['ACTIVE: long commit', join_(active.map((l) => l.replace(sha('1'), '1'.repeat(41)))), 3],
    ['ACTIVE: three trusted files', join_(active.map((l) => l.replace('4 trusted', '3 trusted'))), 3],
    ['BOOTSTRAP_PENDING: a line is missing', join_(bootstrap.slice(0, -1)), 2],
    ['BOOTSTRAP_PENDING: the verdict is rewritten', join_(bootstrap.map((l) => l.replace('NOT TRUSTED', 'TRUSTED'))), 2],
    ['BOOTSTRAP_PENDING: a trailing blank line', `${join_(bootstrap)}\n`, 2],
    ['BOOTSTRAP_PENDING transcript with the ACTIVE exit code', transcript('BOOTSTRAP_PENDING'), 3],
    ['ACTIVE transcript with the BOOTSTRAP_PENDING exit code', transcript('ACTIVE'), 2],
    ['valid ACTIVE transcript with exit 0', transcript('ACTIVE'), 0],
    ['valid BOOTSTRAP_PENDING transcript with exit 0', transcript('BOOTSTRAP_PENDING'), 0],
    ['valid ACTIVE transcript with exit 1', transcript('ACTIVE'), 1],
    ['valid ACTIVE transcript with exit 4', transcript('ACTIVE'), 4],
    ['empty output with exit 3', '', 3],
    ['empty output with exit 2', '', 2]
  ];
  for (const [label, text, exit] of cases) {
    const outcome = gateAgainstStub(text, exit);
    assert.equal(outcome.code, 1, `${label} must be rejected`);
    assert.match(outcome.output, /::error::/, label);
  }
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
