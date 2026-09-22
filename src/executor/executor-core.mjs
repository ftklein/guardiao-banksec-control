// Orchestrates injected components only.
//
// No global credential singleton, no implicit environment read, no network side
// effect on import, no status write, no filesystem write.

import { verifyTrust, TRUST_STATES } from './trust-verifier.mjs';
import { evaluateStatusPolicy } from './status-policy.mjs';

export { TRUST_STATES };

/**
 * @param {{ manifest: object, reader?: Function, targetHeadSha: string }} input
 */
export async function runExecutorCore({ manifest, reader, targetHeadSha } = {}) {
  const trust = await verifyTrust({ manifest, reader });
  const policy = evaluateStatusPolicy({
    trustState: trust.trustState,
    targetHeadSha,
    analyzedHeadSha: targetHeadSha
  });

  return {
    trustState: trust.trustState,
    trustReason: trust.reason,
    trustVerified: trust.trustState === TRUST_STATES.TRUST_VERIFIED,
    verifiedFileCount: trust.verifiedFileCount,
    readerCallCount: trust.readerCallCount,
    targetHeadSha: policy.headBound ? targetHeadSha : null,
    headBound: policy.headBound,
    headReason: policy.headReason,
    // A precondition, nothing more: it authorizes running BankSec later, it
    // does not authorize the gate status and it never authorizes a merge.
    canProceedToBankSec: policy.trustPreconditionSatisfied,
    finalGateSuccessAllowed: false,
    finalStatusReason: policy.finalStatusReason,
    mergeAuthorized: false
  };
}
