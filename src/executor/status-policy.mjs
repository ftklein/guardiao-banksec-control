// Decides, deterministically and offline, whether a status *would* be allowed.
//
// This module publishes nothing. It performs no network call of any kind, in
// this phase or by accident: it is a pure function over a trust state.

import { TRUST_STATES } from './trust-verifier.mjs';

export { TRUST_STATES };

export const COMMIT_SHA_PATTERN = /^[0-9a-f]{40}$/;

// The final gate status is reserved for a later phase that combines the trusted
// executor with deterministic BankSec, semantic BankSec and HEAD binding.
// Nothing in Phase 2A may turn TRUST_VERIFIED into that status.
export const FINAL_STATUS_RESERVED_REASON = 'PHASE_2A_FINAL_STATUS_RESERVED';

export function validateHeadSha(value) {
  if (typeof value !== 'string' || value.length === 0) {
    return { valid: false, reason: 'HEAD_SHA_EMPTY' };
  }
  if (!COMMIT_SHA_PATTERN.test(value)) {
    return { valid: false, reason: 'HEAD_SHA_MALFORMED' };
  }
  return { valid: true, reason: 'HEAD_SHA_OK' };
}

/**
 * Head binding: the SHA a future run declares must be the SHA it actually
 * analysed. This is prepared here and enforced now, so a later phase cannot
 * forget it.
 */
export function bindHead({ targetHeadSha, analyzedHeadSha }) {
  const declared = validateHeadSha(targetHeadSha);
  if (!declared.valid) return { bound: false, reason: declared.reason };
  if (analyzedHeadSha !== undefined) {
    const analyzed = validateHeadSha(analyzedHeadSha);
    if (!analyzed.valid) return { bound: false, reason: `ANALYZED_${analyzed.reason}` };
    if (analyzed.valid && analyzedHeadSha !== targetHeadSha) {
      return { bound: false, reason: 'HEAD_SHA_DIVERGED' };
    }
  }
  return { bound: true, reason: 'HEAD_SHA_BOUND' };
}

export function isTrustPreconditionSatisfied(trustState) {
  return trustState === TRUST_STATES.TRUST_VERIFIED;
}

/**
 * The only function allowed to speak about the final gate status, and it always
 * says no in this phase.
 */
export function canPublishTrustedGateSuccess() {
  return { allowed: false, reason: FINAL_STATUS_RESERVED_REASON };
}

export function evaluateStatusPolicy({ trustState, targetHeadSha, analyzedHeadSha }) {
  const known = Object.values(TRUST_STATES).includes(trustState);
  const head = bindHead({ targetHeadSha, analyzedHeadSha });
  const finalStatus = canPublishTrustedGateSuccess();

  const trustPreconditionSatisfied = known && head.bound && isTrustPreconditionSatisfied(trustState);

  return {
    trustState: known ? trustState : TRUST_STATES.TRUST_UNDETERMINED,
    headBound: head.bound,
    headReason: head.reason,
    trustPreconditionSatisfied,
    // Never true in Phase 2A, whatever the trust state is.
    finalGateSuccessAllowed: false,
    finalStatusReason: finalStatus.reason,
    successProhibited: !trustPreconditionSatisfied || !finalStatus.allowed
  };
}
