// Shared synthetic fixtures. Nothing here is real: no credential, no digest of
// any real GuardiaoSystem file, no approved commit. Every value is invented for
// the tests and is useless outside them.
import { createHash } from 'node:crypto';
import { TRUSTED_PATHS } from '../src/executor/constants.mjs';

export const SYNTHETIC_COMMIT = '0123456789abcdef0123456789abcdef01234567';
export const SYNTHETIC_HEAD = 'fedcba9876543210fedcba9876543210fedcba98';

export const syntheticBytes = (path) => Buffer.from(`synthetic fixture content for ${path}\n`, 'utf8');
export const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function bootstrapManifest() {
  return {
    schemaVersion: 1,
    target: { owner: 'ftklein', repository: 'GuardiaoSystem' },
    statusContext: 'banksec/trusted-gate',
    trust: { state: 'BOOTSTRAP_PENDING', approvedCommit: null, trustedFiles: [] }
  };
}

export function activeManifest(trustedFiles = completeTrustSurface()) {
  return {
    schemaVersion: 1,
    target: { owner: 'ftklein', repository: 'GuardiaoSystem' },
    statusContext: 'banksec/trusted-gate',
    trust: { state: 'ACTIVE', approvedCommit: SYNTHETIC_COMMIT, trustedFiles }
  };
}

export function completeTrustSurface() {
  return TRUSTED_PATHS.map((path) => ({ path, sha256: sha256Hex(syntheticBytes(path)) }));
}

// A reader stub over an in-memory map. It never touches the network.
export function stubReader(contents, { absent = [], failWith = null } = {}) {
  const calls = [];
  const reader = async ({ path, ref }) => {
    calls.push({ path, ref });
    if (failWith) throw failWith;
    if (absent.includes(path)) return { present: false, path, ref };
    return { present: true, path, ref, bytes: contents.get(path) };
  };
  reader.calls = calls;
  return reader;
}

export function honestContents() {
  return new Map(TRUSTED_PATHS.map((path) => [path, syntheticBytes(path)]));
}
