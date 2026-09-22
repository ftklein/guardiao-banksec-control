// Decides whether the pinned trust surface of an ACTIVE manifest is intact.
//
// The verifier never builds a reader, never reads the environment and never
// touches the network itself: the reader is injected, so a caller cannot
// accidentally give it ambient credentials.

import { createHash, timingSafeEqual } from 'node:crypto';
import { TARGET_OWNER, TARGET_REPOSITORY, STATUS_CONTEXT, TRUSTED_PATHS } from './constants.mjs';
import { validateTarget } from '../validate-target.mjs';

export const TRUST_STATES = Object.freeze({
  NOT_TRUSTED: 'NOT_TRUSTED',
  TRUST_UNDETERMINED: 'TRUST_UNDETERMINED',
  TRUST_MISMATCH: 'TRUST_MISMATCH',
  TRUST_VERIFIED: 'TRUST_VERIFIED'
});

const result = (trustState, reason, extra = {}) => ({
  trustState,
  reason,
  verifiedFileCount: 0,
  readerCallCount: 0,
  ...extra
});

function digestsMatch(expectedHex, actualHex) {
  const expected = Buffer.from(expectedHex, 'hex');
  const actual = Buffer.from(actualHex, 'hex');
  if (expected.length !== actual.length || expected.length === 0) return false;
  return timingSafeEqual(expected, actual);
}

/**
 * @param {{ manifest: object, reader: Function }} options
 * @returns {Promise<{trustState: string, reason: string, verifiedFileCount: number, readerCallCount: number}>}
 */
export async function verifyTrust({ manifest, reader }) {
  const validation = validateTarget(manifest);
  if (!validation.valid) {
    // An unusable manifest can never grant trust, and must never reach a reader.
    return result(TRUST_STATES.NOT_TRUSTED, 'MANIFEST_INVALID', { errors: validation.errors });
  }

  if (manifest.trust.state !== 'ACTIVE') {
    // BOOTSTRAP_PENDING: fail closed without a single reader call.
    return result(TRUST_STATES.NOT_TRUSTED, `TRUST_STATE_${manifest.trust.state}`);
  }

  // Defence in depth: the schema already pinned these, check them again here so
  // the verifier is safe even if called with a manifest validated elsewhere.
  if (
    manifest.target.owner !== TARGET_OWNER ||
    manifest.target.repository !== TARGET_REPOSITORY ||
    manifest.statusContext !== STATUS_CONTEXT
  ) {
    return result(TRUST_STATES.NOT_TRUSTED, 'TARGET_MISMATCH');
  }

  const pinned = new Map();
  for (const entry of manifest.trust.trustedFiles) pinned.set(entry.path, entry.sha256);
  if (pinned.size !== TRUSTED_PATHS.length || !TRUSTED_PATHS.every((path) => pinned.has(path))) {
    return result(TRUST_STATES.NOT_TRUSTED, 'INCOMPLETE_TRUST_SURFACE');
  }

  if (typeof reader !== 'function') {
    return result(TRUST_STATES.TRUST_UNDETERMINED, 'NO_READER');
  }

  const approvedCommit = manifest.trust.approvedCommit;
  let readerCallCount = 0;
  let verifiedFileCount = 0;

  for (const path of TRUSTED_PATHS) {
    let read;
    readerCallCount += 1;
    try {
      read = await reader({ path, ref: approvedCommit });
    } catch (error) {
      // Transport, HTTP, encoding and payload failures are all inconclusive:
      // we do not know whether the surface is intact, so we must not guess.
      return result(TRUST_STATES.TRUST_UNDETERMINED, `READ_FAILED:${error.code || 'UNKNOWN'}`, {
        readerCallCount,
        verifiedFileCount,
        path
      });
    }

    if (!read || read.present !== true || !Buffer.isBuffer(read.bytes)) {
      // An authenticated, explicit statement that the pinned file is not there
      // is a broken trust surface, not an inconclusive read.
      return result(TRUST_STATES.TRUST_MISMATCH, 'FILE_ABSENT', { readerCallCount, verifiedFileCount, path });
    }

    const actual = createHash('sha256').update(read.bytes).digest('hex');
    if (!digestsMatch(pinned.get(path), actual)) {
      return result(TRUST_STATES.TRUST_MISMATCH, 'DIGEST_MISMATCH', { readerCallCount, verifiedFileCount, path });
    }
    verifiedFileCount += 1;
  }

  if (verifiedFileCount !== TRUSTED_PATHS.length) {
    return result(TRUST_STATES.TRUST_MISMATCH, 'INCOMPLETE_VERIFICATION', { readerCallCount, verifiedFileCount });
  }

  return result(TRUST_STATES.TRUST_VERIFIED, 'ALL_TRUSTED_FILES_MATCH', { readerCallCount, verifiedFileCount });
}
