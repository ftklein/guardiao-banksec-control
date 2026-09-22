import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyTrust, TRUST_STATES } from '../src/executor/trust-verifier.mjs';
import { TRUSTED_PATHS } from '../src/executor/constants.mjs';
import {
  bootstrapManifest,
  activeManifest,
  completeTrustSurface,
  stubReader,
  honestContents,
  syntheticBytes,
  sha256Hex
} from './executor-fixtures.mjs';

test('E01: BOOTSTRAP_PENDING is NOT_TRUSTED', async () => {
  const outcome = await verifyTrust({ manifest: bootstrapManifest(), reader: stubReader(honestContents()) });
  assert.equal(outcome.trustState, TRUST_STATES.NOT_TRUSTED);
  assert.equal(outcome.reason, 'TRUST_STATE_BOOTSTRAP_PENDING');
});

test('E02: BOOTSTRAP_PENDING never calls the reader', async () => {
  const reader = stubReader(honestContents());
  const outcome = await verifyTrust({ manifest: bootstrapManifest(), reader });
  assert.equal(reader.calls.length, 0);
  assert.equal(outcome.readerCallCount, 0);
  assert.equal(outcome.verifiedFileCount, 0);
});

test('E17: four matching digests yield TRUST_VERIFIED', async () => {
  const reader = stubReader(honestContents());
  const outcome = await verifyTrust({ manifest: activeManifest(), reader });
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_VERIFIED);
  assert.equal(outcome.verifiedFileCount, 4);
  assert.equal(reader.calls.length, 4);
  assert.deepEqual(reader.calls.map((call) => call.path), [...TRUSTED_PATHS]);
});

test('E18: a wrong digest on the first file yields TRUST_MISMATCH', async () => {
  const surface = completeTrustSurface();
  surface[0].sha256 = sha256Hex(Buffer.from('tampered', 'utf8'));
  const reader = stubReader(honestContents());
  const outcome = await verifyTrust({ manifest: activeManifest(surface), reader });
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_MISMATCH);
  assert.equal(outcome.verifiedFileCount, 0);
});

test('E19: a wrong digest on the last file yields TRUST_MISMATCH', async () => {
  const surface = completeTrustSurface();
  surface[surface.length - 1].sha256 = sha256Hex(Buffer.from('tampered', 'utf8'));
  const reader = stubReader(honestContents());
  const outcome = await verifyTrust({ manifest: activeManifest(surface), reader });
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_MISMATCH);
  assert.equal(outcome.verifiedFileCount, 3);
});

test('E19b: tampered bytes under a pinned digest yield TRUST_MISMATCH', async () => {
  const contents = honestContents();
  contents.set(TRUSTED_PATHS[2], Buffer.from('#!/bin/sh\necho tampered\n', 'utf8'));
  const outcome = await verifyTrust({ manifest: activeManifest(), reader: stubReader(contents) });
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_MISMATCH);
  assert.equal(outcome.path, TRUSTED_PATHS[2]);
});

test('E20: an absent pinned file yields TRUST_MISMATCH', async () => {
  const reader = stubReader(honestContents(), { absent: [TRUSTED_PATHS[1]] });
  const outcome = await verifyTrust({ manifest: activeManifest(), reader });
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_MISMATCH);
  assert.equal(outcome.reason, 'FILE_ABSENT');
});

test('a reader failure yields TRUST_UNDETERMINED, never a pass', async () => {
  const failure = Object.assign(new Error('transport down'), { code: 'TRANSPORT' });
  const outcome = await verifyTrust({ manifest: activeManifest(), reader: stubReader(honestContents(), { failWith: failure }) });
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_UNDETERMINED);
  assert.equal(outcome.verifiedFileCount, 0);
});

test('a missing reader yields TRUST_UNDETERMINED for an ACTIVE manifest', async () => {
  const outcome = await verifyTrust({ manifest: activeManifest() });
  assert.equal(outcome.trustState, TRUST_STATES.TRUST_UNDETERMINED);
  assert.equal(outcome.reason, 'NO_READER');
});

test('an invalid manifest is NOT_TRUSTED and never reaches the reader', async () => {
  const reader = stubReader(honestContents());
  const broken = activeManifest();
  broken.target.owner = 'someone-else';
  const outcome = await verifyTrust({ manifest: broken, reader });
  assert.equal(outcome.trustState, TRUST_STATES.NOT_TRUSTED);
  assert.equal(reader.calls.length, 0);
});

test('the verifier asks only for the approved commit and only for pinned paths', async () => {
  const reader = stubReader(honestContents());
  const manifest = activeManifest();
  await verifyTrust({ manifest, reader });
  for (const call of reader.calls) {
    assert.equal(call.ref, manifest.trust.approvedCommit);
    assert.ok(TRUSTED_PATHS.includes(call.path));
  }
});

test('digest comparison is not short-circuited by string identity alone', async () => {
  // Same bytes, digest written in a different (invalid) case must not pass.
  const surface = completeTrustSurface();
  surface[0].sha256 = sha256Hex(syntheticBytes(TRUSTED_PATHS[0])).toUpperCase();
  const outcome = await verifyTrust({ manifest: activeManifest(surface), reader: stubReader(honestContents()) });
  assert.notEqual(outcome.trustState, TRUST_STATES.TRUST_VERIFIED);
});
