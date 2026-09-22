// Orchestrates injected components only.
//
// No global credential singleton, no implicit environment read, no network side
// effect on import, no status write, no filesystem write.

import { verifyTrust, TRUST_STATES } from './trust-verifier.mjs';
import { evaluateStatusPolicy } from './status-policy.mjs';

export { TRUST_STATES };

/**
 * `analyzedHeadSha` is the SHA independently observed by whatever actually
 * analysed the target. It must be supplied by the caller and must match the
 * declared `targetHeadSha`: manufacturing that equality here would make the
 * binding vacuous, so an absent or diverging analysed SHA leaves the head
 * unbound and nothing may proceed.
 *
 * @param {{ manifest: object, reader?: Function, targetHeadSha: string, analyzedHeadSha?: string }} input
 */
export async function runExecutorCore({ manifest, reader, targetHeadSha, analyzedHeadSha } = {}) {
  const trust = await verifyTrust({ manifest, reader });
  const policy = evaluateStatusPolicy({
    trustState: trust.trustState,
    targetHeadSha,
    analyzedHeadSha,
    requireAnalyzed: true
  });

  return {
    trustState: trust.trustState,
    trustReason: trust.reason,
    trustVerified: trust.trustState === TRUST_STATES.TRUST_VERIFIED,
    verifiedFileCount: trust.verifiedFileCount,
    readerCallCount: trust.readerCallCount,
    targetHeadSha: policy.headBound ? targetHeadSha : null,
    analyzedHeadSha: policy.headBound ? analyzedHeadSha : null,
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
