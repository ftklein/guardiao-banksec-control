#!/usr/bin/env node
// Reports the trust state of a BankSec control plane target manifest.
//
// Phase 1 scope: this program NEVER contacts the target repository, never
// reads target files, and never grants trust. The remote executor is not
// installed yet; until it is, the only honest answers are "not trusted" and
// "cannot be verified here".

import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { validateTargetFile } from './validate-target.mjs';

export const EXIT_TRUSTED = 0;          // reserved: only a future executor may return it
export const EXIT_INVALID = 1;
export const EXIT_BOOTSTRAP_PENDING = 2;
export const EXIT_EXECUTOR_NOT_INSTALLED = 3;
export const EXIT_USAGE = 64;

export function describe(result) {
  if (!result.valid) {
    return {
      code: EXIT_INVALID,
      lines: ['TRUST RESULT: NOT TRUSTED (manifest invalid)', ...result.errors.map((e) => `  - ${e}`)]
    };
  }
  const state = result.manifest.trust.state;
  if (state === 'BOOTSTRAP_PENDING') {
    return {
      code: EXIT_BOOTSTRAP_PENDING,
      lines: [
        'TRUST STATE: BOOTSTRAP_PENDING',
        'TRUST RESULT: NOT TRUSTED',
        'No commit is approved and the trust surface is empty.',
        'BOOTSTRAP_PENDING never authorizes a merge in the target repository.'
      ]
    };
  }
  return {
    code: EXIT_EXECUTOR_NOT_INSTALLED,
    lines: [
      'TRUST STATE: ACTIVE',
      'TRUST RESULT: UNDETERMINED (structure only)',
      `Manifest structure is well formed: approved commit ${result.manifest.trust.approvedCommit}, ` +
        `${result.manifest.trust.trustedFiles.length} trusted file(s).`,
      'The remote verification executor is NOT installed in this phase, so the target',
      'repository was not contacted and no file digest was compared. This result must',
      'not be treated as a verified trust decision.'
    ]
  };
}

function main(argv) {
  const [, , target] = argv;
  if (!target) {
    process.stderr.write('usage: node src/verify-trust.mjs <targets/*.json>\n');
    return EXIT_USAGE;
  }
  const outcome = describe(validateTargetFile(resolve(target)));
  const stream = outcome.code === EXIT_TRUSTED ? process.stdout : process.stderr;
  for (const line of outcome.lines) stream.write(`${line}\n`);
  return outcome.code;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main(process.argv));
}
