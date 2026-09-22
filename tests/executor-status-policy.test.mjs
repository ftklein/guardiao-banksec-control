import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  evaluateStatusPolicy,
  canPublishTrustedGateSuccess,
  validateHeadSha,
  bindHead,
  isTrustPreconditionSatisfied,
  FINAL_STATUS_RESERVED_REASON,
  TRUST_STATES
} from '../src/executor/status-policy.mjs';
import { runExecutorCore } from '../src/executor/executor-core.mjs';
import { STATUS_CONTEXT } from '../src/executor/constants.mjs';
import {
  bootstrapManifest,
  activeManifest,
  stubReader,
  honestContents,
  SYNTHETIC_HEAD
} from './executor-fixtures.mjs';

test('E03: NOT_TRUSTED makes success impossible', () => {
  const policy = evaluateStatusPolicy({ trustState: TRUST_STATES.NOT_TRUSTED, targetHeadSha: SYNTHETIC_HEAD });
  assert.equal(policy.trustPreconditionSatisfied, false);
  assert.equal(policy.finalGateSuccessAllowed, false);
  assert.equal(policy.successProhibited, true);
});

test('E03b: TRUST_UNDETERMINED and TRUST_MISMATCH make success impossible', () => {
  for (const trustState of [TRUST_STATES.TRUST_UNDETERMINED, TRUST_STATES.TRUST_MISMATCH]) {
    const policy = evaluateStatusPolicy({ trustState, targetHeadSha: SYNTHETIC_HEAD });
    assert.equal(policy.trustPreconditionSatisfied, false);
    assert.equal(policy.finalGateSuccessAllowed, false);
    assert.equal(policy.successProhibited, true);
  }
});

test('E34: TRUST_VERIFIED alone never produces a gate success', () => {
  const policy = evaluateStatusPolicy({ trustState: TRUST_STATES.TRUST_VERIFIED, targetHeadSha: SYNTHETIC_HEAD });
  assert.equal(policy.trustPreconditionSatisfied, true);
  assert.equal(policy.finalGateSuccessAllowed, false);
  assert.equal(policy.successProhibited, true);
  assert.equal(policy.finalStatusReason, FINAL_STATUS_RESERVED_REASON);

  const final = canPublishTrustedGateSuccess();
  assert.equal(final.allowed, false);
  assert.equal(final.reason, FINAL_STATUS_RESERVED_REASON);
  assert.equal(isTrustPreconditionSatisfied(TRUST_STATES.TRUST_VERIFIED), true);
});

test('E34b: the policy module cannot publish anything, by construction', async () => {
  const source = readFileSync(new URL('../src/executor/status-policy.mjs', import.meta.url), 'utf8');
  for (const forbidden of ['fetch(', 'node:http', 'node:https', 'XMLHttpRequest', 'api.github.com', 'node:fs']) {
    assert.equal(source.includes(forbidden), false, `status-policy.mjs must not reference ${forbidden}`);
  }
  // The one function that speaks about the final gate status always refuses,
  // for every trust state, with no argument able to change that.
  for (const trustState of Object.values(TRUST_STATES)) {
    assert.equal(canPublishTrustedGateSuccess(trustState).allowed, false);
    assert.equal(canPublishTrustedGateSuccess({ trustState, force: true }).allowed, false);
  }
  assert.equal(STATUS_CONTEXT, 'banksec/trusted-gate');
});

test('an unknown trust state degrades to TRUST_UNDETERMINED, never to a pass', () => {
  for (const trustState of ['SUCCESS', 'TRUSTED', '', null, undefined, 'trust_verified']) {
    const policy = evaluateStatusPolicy({ trustState, targetHeadSha: SYNTHETIC_HEAD });
    assert.equal(policy.trustState, TRUST_STATES.TRUST_UNDETERMINED);
    assert.equal(policy.trustPreconditionSatisfied, false);
    assert.equal(policy.finalGateSuccessAllowed, false);
  }
});

test('E31: an empty target head is rejected', () => {
  assert.equal(validateHeadSha('').valid, false);
  assert.equal(validateHeadSha(undefined).valid, false);
  assert.equal(validateHeadSha(null).valid, false);
  const policy = evaluateStatusPolicy({ trustState: TRUST_STATES.TRUST_VERIFIED, targetHeadSha: '' });
  assert.equal(policy.headBound, false);
  assert.equal(policy.trustPreconditionSatisfied, false);
});

test('E32: an uppercase target head is rejected', () => {
  assert.equal(validateHeadSha(SYNTHETIC_HEAD.toUpperCase()).valid, false);
  const policy = evaluateStatusPolicy({
    trustState: TRUST_STATES.TRUST_VERIFIED,
    targetHeadSha: SYNTHETIC_HEAD.toUpperCase()
  });
  assert.equal(policy.headBound, false);
  assert.equal(policy.trustPreconditionSatisfied, false);
});

test('E33: a short target head is rejected', () => {
  for (const sha of [SYNTHETIC_HEAD.slice(0, 39), SYNTHETIC_HEAD.slice(0, 7), `${SYNTHETIC_HEAD}0`]) {
    assert.equal(validateHeadSha(sha).valid, false);
    assert.equal(evaluateStatusPolicy({ trustState: TRUST_STATES.TRUST_VERIFIED, targetHeadSha: sha }).headBound, false);
  }
});

test('E33b: a head that differs from the analysed head is rejected', () => {
  const other = 'a'.repeat(40);
  assert.equal(bindHead({ targetHeadSha: SYNTHETIC_HEAD, analyzedHeadSha: other }).bound, false);
  assert.equal(bindHead({ targetHeadSha: SYNTHETIC_HEAD, analyzedHeadSha: SYNTHETIC_HEAD }).bound, true);
  const policy = evaluateStatusPolicy({
    trustState: TRUST_STATES.TRUST_VERIFIED,
    targetHeadSha: SYNTHETIC_HEAD,
    analyzedHeadSha: other
  });
  assert.equal(policy.headReason, 'HEAD_SHA_DIVERGED');
  assert.equal(policy.trustPreconditionSatisfied, false);
});

test('executor core on the real bootstrap manifest: nothing is authorized', async () => {
  const reader = stubReader(honestContents());
  const outcome = await runExecutorCore({
    manifest: bootstrapManifest(),
    reader,
    targetHeadSha: SYNTHETIC_HEAD
  });
  assert.equal(outcome.trustState, TRUST_STATES.NOT_TRUSTED);
  assert.equal(outcome.trustVerified, false);
  assert.equal(outcome.canProceedToBankSec, false);
  assert.equal(outcome.finalGateSuccessAllowed, false);
  assert.equal(outcome.mergeAuthorized, false);
  assert.equal(reader.calls.length, 0);
});

test('executor core with a verified surface: precondition only, never a merge', async () => {
  const outcome = await runExecutorCore({
    manifest: activeManifest(),
    reader: stubReader(honestContents()),
    targetHeadSha: SYNTHETIC_HEAD
  });
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_VERIFIED);
  assert.equal(outcome.trustVerified, true);
  assert.equal(outcome.verifiedFileCount, 4);
  assert.equal(outcome.canProceedToBankSec, true);
  assert.equal(outcome.finalGateSuccessAllowed, false);
  assert.equal(outcome.mergeAuthorized, false);
  assert.equal(outcome.targetHeadSha, SYNTHETIC_HEAD);
});

test('executor core refuses a verified surface presented with a malformed head', async () => {
  const outcome = await runExecutorCore({
    manifest: activeManifest(),
    reader: stubReader(honestContents()),
    targetHeadSha: 'HEAD'
  });
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_VERIFIED);
  assert.equal(outcome.headBound, false);
  assert.equal(outcome.targetHeadSha, null);
  assert.equal(outcome.canProceedToBankSec, false);
  assert.equal(outcome.mergeAuthorized, false);
});

test('executor core called with no arguments fails closed', async () => {
  const outcome = await runExecutorCore();
  assert.equal(outcome.trustState, TRUST_STATES.NOT_TRUSTED);
  assert.equal(outcome.canProceedToBankSec, false);
  assert.equal(outcome.finalGateSuccessAllowed, false);
});
