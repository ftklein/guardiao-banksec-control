import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createGithubContentReader,
  buildContentUrl,
  assertApiOrigin,
  decodeStrictBase64,
  ReaderError,
  READER_ERROR_CODES,
  MAX_FILE_BYTES,
  API_ORIGIN
} from '../src/executor/github-reader.mjs';
import { TRUSTED_PATHS } from '../src/executor/constants.mjs';
import { verifyTrust, TRUST_STATES } from '../src/executor/trust-verifier.mjs';
import { SYNTHETIC_COMMIT, syntheticBytes, activeManifest } from './executor-fixtures.mjs';

const OTHER_COMMIT = '89abcdef0123456789abcdef0123456789abcdef';

function fileResponse(bytes, overrides = {}) {
  return {
    status: 200,
    redirected: false,
    body: { type: 'file', encoding: 'base64', size: bytes.byteLength, content: bytes.toString('base64'), ...overrides }
  };
}

function reader(transport, options = {}) {
  return createGithubContentReader({ transport, approvedCommit: SYNTHETIC_COMMIT, ...options });
}

const rejects = (promise, code) =>
  assert.rejects(promise, (error) => error instanceof ReaderError && error.code === code);

test('a well formed response is decoded into opaque bytes', async () => {
  const bytes = syntheticBytes(TRUSTED_PATHS[0]);
  const seen = [];
  const read = reader(async (request) => {
    seen.push(request);
    return fileResponse(bytes);
  });
  const result = await read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT });
  assert.equal(result.present, true);
  assert.ok(Buffer.isBuffer(result.bytes));
  assert.equal(result.bytes.toString('utf8'), bytes.toString('utf8'));
  assert.equal(seen.length, 1);
  assert.equal(seen[0].method, 'GET');
  assert.equal(seen[0].redirect, 'error');
  assert.ok(seen[0].url.startsWith('https://api.github.com/repos/ftklein/GuardiaoSystem/contents/'));
  assert.ok(seen[0].url.includes(`ref=${SYNTHETIC_COMMIT}`));
});

test('E21: HTTP 404 is inconclusive, never a silent absence', async () => {
  await rejects(
    reader(async () => ({ status: 404, redirected: false, body: { message: 'Not Found' } }))({
      path: TRUSTED_PATHS[0],
      ref: SYNTHETIC_COMMIT
    }),
    READER_ERROR_CODES.HTTP_STATUS
  );
});

test('E22: HTTP 500 is rejected', async () => {
  await rejects(
    reader(async () => ({ status: 500, redirected: false, body: {} }))({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
    READER_ERROR_CODES.HTTP_STATUS
  );
});

test('E23: a redirect is rejected, by flag and by status', async () => {
  const bytes = syntheticBytes(TRUSTED_PATHS[0]);
  await rejects(
    reader(async () => ({ ...fileResponse(bytes), redirected: true }))({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
    READER_ERROR_CODES.REDIRECT
  );
  for (const status of [301, 302, 307, 308]) {
    await rejects(
      reader(async () => ({ status, redirected: false, body: {} }))({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
      READER_ERROR_CODES.REDIRECT
    );
  }
});

test('E24: any host other than api.github.com is rejected', () => {
  for (const base of [
    'https://api.github.com.evil.example',
    'https://raw.githubusercontent.com',
    'https://github.com',
    'https://api.github.com:8443'
  ]) {
    assert.throws(() => assertApiOrigin(base), (error) => error.code === READER_ERROR_CODES.BAD_BASE_URL);
    assert.throws(
      () => createGithubContentReader({ transport: async () => ({}), approvedCommit: SYNTHETIC_COMMIT, baseUrl: base }),
      (error) => error.code === READER_ERROR_CODES.BAD_BASE_URL
    );
  }
});

test('E25: plain HTTP and non-HTTPS schemes are rejected', () => {
  for (const base of ['http://api.github.com', 'ftp://api.github.com', 'file:///etc/passwd']) {
    assert.throws(() => assertApiOrigin(base), (error) => error.code === READER_ERROR_CODES.BAD_BASE_URL);
  }
  assert.equal(assertApiOrigin(API_ORIGIN).protocol, 'https:');
});

test('E26: an encoding other than base64 is rejected', async () => {
  for (const encoding of ['none', 'utf-8', '', null, undefined]) {
    await rejects(
      reader(async () => fileResponse(Buffer.from('x'), { encoding }))({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
      READER_ERROR_CODES.BAD_ENCODING
    );
  }
});

test('E27: malformed base64 is rejected instead of silently coerced', async () => {
  for (const content of ['!!!!', 'YWJj', 'YWJjZA=', 'ab', 'AAAA=', '****']) {
    const promise = reader(async () => fileResponse(Buffer.from('ignored'), { content }))({
      path: TRUSTED_PATHS[0],
      ref: SYNTHETIC_COMMIT
    });
    if (content === 'YWJj') {
      // canonical: must decode cleanly
      const result = await promise;
      assert.equal(result.bytes.toString('utf8'), 'abc');
    } else {
      await rejects(promise, READER_ERROR_CODES.BAD_BASE64);
    }
  }
  assert.throws(() => decodeStrictBase64(123), (error) => error.code === READER_ERROR_CODES.BAD_BASE64);
  assert.equal(decodeStrictBase64('YWJj\nZA==').toString('utf8'), 'abcd');
});

test('E28: payloads over 4 MiB are rejected, declared or actual', async () => {
  await rejects(
    reader(async () => fileResponse(Buffer.from('small'), { size: MAX_FILE_BYTES + 1 }))({
      path: TRUSTED_PATHS[0],
      ref: SYNTHETIC_COMMIT
    }),
    READER_ERROR_CODES.TOO_LARGE
  );
  const oversized = Buffer.alloc(MAX_FILE_BYTES + 16, 0x61);
  await rejects(
    reader(async () => ({
      status: 200,
      redirected: false,
      body: { type: 'file', encoding: 'base64', content: oversized.toString('base64') }
    }))({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
    READER_ERROR_CODES.TOO_LARGE
  );
});

test('E29: a path outside the trust surface is refused before any transport call', async () => {
  let called = 0;
  const read = reader(async () => {
    called += 1;
    return fileResponse(Buffer.from('x'));
  });
  for (const path of ['README.md', 'server/routes/auth.ts', 'security/banksec/../../.env', '', null]) {
    await rejects(read({ path, ref: SYNTHETIC_COMMIT }), READER_ERROR_CODES.BAD_PATH);
  }
  assert.equal(called, 0);
});

test('E30: a ref other than the approved commit is refused before any transport call', async () => {
  let called = 0;
  const read = reader(async () => {
    called += 1;
    return fileResponse(Buffer.from('x'));
  });
  for (const ref of [OTHER_COMMIT, SYNTHETIC_COMMIT.toUpperCase(), SYNTHETIC_COMMIT.slice(0, 39), 'main', '', null]) {
    await rejects(read({ path: TRUSTED_PATHS[0], ref }), READER_ERROR_CODES.BAD_REF);
  }
  assert.equal(called, 0);
});

test('the reader itself refuses to be built on a malformed approved commit', () => {
  for (const commit of ['', 'main', SYNTHETIC_COMMIT.toUpperCase(), SYNTHETIC_COMMIT.slice(0, 39)]) {
    assert.throws(
      () => createGithubContentReader({ transport: async () => ({}), approvedCommit: commit }),
      (error) => error.code === READER_ERROR_CODES.BAD_REF
    );
  }
  assert.throws(() => createGithubContentReader({ approvedCommit: SYNTHETIC_COMMIT }), TypeError);
});

test('a non-file payload or a broken transport is rejected, never trusted', async () => {
  for (const overrides of [{ type: 'dir' }, { type: 'submodule' }, { type: 'symlink' }]) {
    await rejects(
      reader(async () => fileResponse(Buffer.from('x'), overrides))({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
      READER_ERROR_CODES.UNEXPECTED_PAYLOAD
    );
  }
  await rejects(
    reader(async () => ({ status: 200, redirected: false, body: ['not', 'an', 'object'] }))({
      path: TRUSTED_PATHS[0],
      ref: SYNTHETIC_COMMIT
    }),
    READER_ERROR_CODES.UNEXPECTED_PAYLOAD
  );
  await rejects(
    reader(async () => undefined)({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
    READER_ERROR_CODES.UNEXPECTED_PAYLOAD
  );
  await rejects(
    reader(async () => {
      throw new Error('socket hang up');
    })({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
    READER_ERROR_CODES.TRANSPORT
  );
});

test('the request URL cannot be steered by the target', () => {
  const url = buildContentUrl(TRUSTED_PATHS[3], SYNTHETIC_COMMIT);
  assert.equal(
    url,
    `https://api.github.com/repos/ftklein/GuardiaoSystem/contents/${TRUSTED_PATHS[3]}?ref=${SYNTHETIC_COMMIT}`
  );
});

// -------------------------------------------------------------------------
// Codex corrective-02 (PR #1): the status gate and the transport catch.
// -------------------------------------------------------------------------

// A body whose `content` records the moment it is read, so a test can prove
// that an invalid status is rejected before any decoding is attempted.
function watchedBody(bytes) {
  const state = { contentRead: false };
  const body = {
    type: 'file',
    encoding: 'base64',
    size: bytes.byteLength,
    get content() {
      state.contentRead = true;
      return bytes.toString('base64');
    }
  };
  return { body, state };
}

const statusResponse = (status, bytes = syntheticBytes(TRUSTED_PATHS[0])) => {
  const { body, state } = watchedBody(bytes);
  return { response: { status, redirected: false, body }, state };
};

async function readWithStatus(status) {
  const { response, state } = statusResponse(status);
  const read = reader(async () => response);
  return { promise: read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }), state };
}

test('C14: a NaN status is rejected before the payload', async () => {
  const { promise, state } = await readWithStatus(Number.NaN);
  await rejects(promise, READER_ERROR_CODES.INVALID_STATUS);
  assert.equal(state.contentRead, false);
});

test('C15: an Infinity status is rejected', async () => {
  for (const status of [Infinity, -Infinity]) {
    const { promise, state } = await readWithStatus(status);
    await rejects(promise, READER_ERROR_CODES.INVALID_STATUS);
    assert.equal(state.contentRead, false);
  }
});

test('C16: a non-integer status is rejected', async () => {
  for (const status of [200.5, 299.999, -0.5]) {
    const { promise, state } = await readWithStatus(status);
    await rejects(promise, READER_ERROR_CODES.INVALID_STATUS);
    assert.equal(state.contentRead, false);
  }
});

test('C17: a string status is rejected', async () => {
  for (const status of ['200', '404', '']) {
    const { promise, state } = await readWithStatus(status);
    await rejects(promise, READER_ERROR_CODES.INVALID_STATUS);
    assert.equal(state.contentRead, false);
  }
});

test('C18: a missing or non-numeric status is rejected', async () => {
  for (const status of [undefined, null, true, {}, []]) {
    const { promise, state } = await readWithStatus(status);
    await rejects(promise, READER_ERROR_CODES.INVALID_STATUS);
    assert.equal(state.contentRead, false);
  }
});

test('C19: an integer 2xx status still succeeds', async () => {
  const bytes = syntheticBytes(TRUSTED_PATHS[1]);
  for (const status of [200, 201, 299]) {
    const { body } = watchedBody(bytes);
    const read = reader(async () => ({ status, redirected: false, body }));
    const result = await read({ path: TRUSTED_PATHS[1], ref: SYNTHETIC_COMMIT });
    assert.equal(result.present, true);
    assert.equal(result.bytes.toString('utf8'), bytes.toString('utf8'));
  }
  // A 4xx or 5xx integer keeps its own, distinct classification.
  for (const status of [404, 500]) {
    const { promise } = await readWithStatus(status);
    await rejects(promise, READER_ERROR_CODES.HTTP_STATUS);
  }
});

test('C20: an integer 3xx status is still classified as a redirect', async () => {
  for (const status of [300, 301, 302, 307, 308, 399]) {
    const { promise, state } = await readWithStatus(status);
    await rejects(promise, READER_ERROR_CODES.REDIRECT);
    assert.equal(state.contentRead, false);
  }
  // The redirected flag keeps priority over any status value.
  const { body } = watchedBody(syntheticBytes(TRUSTED_PATHS[0]));
  await rejects(
    reader(async () => ({ status: 200, redirected: true, body }))({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
    READER_ERROR_CODES.REDIRECT
  );
});

const rejectsWithTransport = async (rejection) => {
  const read = reader(async () => {
    throw rejection;
  });
  await assert.rejects(
    read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }),
    (error) => {
      assert.ok(error instanceof ReaderError, `expected a ReaderError, got ${error?.constructor?.name}`);
      assert.equal(error.code, READER_ERROR_CODES.TRANSPORT);
      assert.equal(error instanceof TypeError, false);
      return true;
    }
  );
};

test('C21: a transport rejecting with null gives a ReaderError, not a TypeError', async () => {
  await rejectsWithTransport(null);
});

test('C22: a transport rejecting with undefined gives a ReaderError', async () => {
  await rejectsWithTransport(undefined);
});

test('C23: a transport rejecting with a string, number or boolean gives a ReaderError', async () => {
  for (const rejection of ['socket hang up', 42, false, 0n]) {
    await rejectsWithTransport(rejection);
  }
});

test('C24: a transport rejecting with a plain object gives a ReaderError', async () => {
  for (const rejection of [{}, { message: 42 }, { code: 'X' }, Object.create(null), []]) {
    await rejectsWithTransport(rejection);
  }
  // A real Error keeps its own message.
  const read = reader(async () => {
    throw new Error('connection reset');
  });
  await assert.rejects(read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }), (error) => {
    assert.equal(error.code, READER_ERROR_CODES.TRANSPORT);
    assert.match(error.message, /connection reset/);
    return true;
  });
});

test('C25: a non-Error transport rejection reaches the verifier as READ_FAILED:TRANSPORT', async () => {
  for (const rejection of [null, undefined, 'boom', { nope: true }]) {
    const read = reader(async () => {
      throw rejection;
    });
    const outcome = await verifyTrust({ manifest: activeManifest(), reader: read });
    assert.equal(outcome.trustState, TRUST_STATES.TRUST_UNDETERMINED);
    assert.equal(outcome.reason, 'READ_FAILED:TRANSPORT');
    assert.equal(outcome.verifiedFileCount, 0);
  }
});

test('C26: no payload behind an invalid status is ever decoded', async () => {
  // The content is deliberately not valid base64: reaching the decoder would
  // surface BAD_BASE64 instead of the status rejection.
  for (const status of [Number.NaN, Infinity, 200.5, '200', undefined, null, 302, 404]) {
    const state = { contentRead: false };
    const body = {
      type: 'file',
      encoding: 'base64',
      get content() {
        state.contentRead = true;
        return '!!!! not base64 !!!!';
      }
    };
    const read = reader(async () => ({ status, redirected: false, body }));
    await assert.rejects(read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }), (error) => {
      assert.notEqual(error.code, READER_ERROR_CODES.BAD_BASE64);
      return true;
    });
    assert.equal(state.contentRead, false, `content was read for status ${String(status)}`);
  }
});

// -------------------------------------------------------------------------
// Codex corrective-03 (PR #1): explicit evidence that no redirect occurred.
// `redirect: 'error'` is only an instruction to the adapter; since the
// transport is injectable and need not be a native fetch, the reader requires
// `redirected === false` in the response as positive evidence.
// -------------------------------------------------------------------------

// Values that are NOT the boolean false. Deliberately mixes falsy and truthy
// so a future `if (!response.redirected)` regression is caught: that form
// would wrongly accept 0, '', null and undefined.
const NON_EVIDENCE_REDIRECT_VALUES = [
  ['absent', undefined],
  ['undefined', undefined],
  [' null', null],
  ["string 'false'", 'false'],
  ["string 'true'", 'true'],
  ['empty string', ''],
  ['number 0', 0],
  ['number 1', 1],
  ['NaN', Number.NaN],
  ['empty object', {}],
  ['empty array', []],
  ['Boolean object', new Boolean(false)]
];

function redirectEvidenceResponse(value, { omit = false, status = 200 } = {}) {
  const state = { contentRead: false };
  const body = {
    type: 'file',
    encoding: 'base64',
    get content() {
      state.contentRead = true;
      return syntheticBytes(TRUSTED_PATHS[0]).toString('base64');
    }
  };
  const response = omit ? { status, body } : { status, redirected: value, body };
  return { response, state };
}

async function rejectsRedirectEvidence(value, options) {
  const { response, state } = redirectEvidenceResponse(value, options);
  const read = reader(async () => response);
  await rejects(read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }), READER_ERROR_CODES.REDIRECT_EVIDENCE_MISSING);
  assert.equal(state.contentRead, false);
}

test('C27: a response without the redirected flag is refused', async () => {
  await rejectsRedirectEvidence(undefined, { omit: true });
});

test('C28: redirected undefined is refused', async () => {
  await rejectsRedirectEvidence(undefined);
});

test('C29: redirected null is refused', async () => {
  await rejectsRedirectEvidence(null);
});

test("C30: the string 'false' is not the boolean false", async () => {
  await rejectsRedirectEvidence('false');
});

test('C31: redirected 0 is refused', async () => {
  await rejectsRedirectEvidence(0);
});

test('C32: redirected 1 is refused', async () => {
  await rejectsRedirectEvidence(1);
});

test('C33: redirected true is a REDIRECT, distinct from missing evidence', async () => {
  const { response, state } = redirectEvidenceResponse(true);
  const read = reader(async () => response);
  await rejects(read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }), READER_ERROR_CODES.REDIRECT);
  assert.equal(state.contentRead, false);
  assert.notEqual(READER_ERROR_CODES.REDIRECT, READER_ERROR_CODES.REDIRECT_EVIDENCE_MISSING);
});

test('C34: redirected false with a 3xx status is still a REDIRECT', async () => {
  for (const status of [300, 302, 307, 308, 399]) {
    const { response, state } = redirectEvidenceResponse(false, { status });
    const read = reader(async () => response);
    await rejects(read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }), READER_ERROR_CODES.REDIRECT);
    assert.equal(state.contentRead, false);
  }
});

test('C35: redirected false with an integer 2xx status still succeeds', async () => {
  const bytes = syntheticBytes(TRUSTED_PATHS[0]);
  for (const status of [200, 201, 299]) {
    const read = reader(async () => ({
      status,
      redirected: false,
      body: { type: 'file', encoding: 'base64', size: bytes.byteLength, content: bytes.toString('base64') }
    }));
    const result = await read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT });
    assert.equal(result.present, true);
    assert.equal(result.bytes.toString('utf8'), bytes.toString('utf8'));
  }
});

test('C36: only the boolean false is accepted, and no payload is ever read', async () => {
  for (const [label, value] of NON_EVIDENCE_REDIRECT_VALUES) {
    const omit = label === 'absent';
    const { response, state } = redirectEvidenceResponse(value, { omit });
    const read = reader(async () => response);
    await assert.rejects(read({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT }), (error) => {
      assert.ok(error instanceof ReaderError, `${label}: expected a ReaderError`);
      assert.equal(error.code, READER_ERROR_CODES.REDIRECT_EVIDENCE_MISSING, `${label} must not be accepted`);
      return true;
    });
    assert.equal(state.contentRead, false, `${label}: the payload must never be read`);
  }

  // And the one accepted value is the boolean false, nothing else.
  const accepted = NON_EVIDENCE_REDIRECT_VALUES.filter(([, value]) => value === false);
  assert.deepEqual(accepted, []);
  const { response } = redirectEvidenceResponse(false);
  const result = await reader(async () => response)({ path: TRUSTED_PATHS[0], ref: SYNTHETIC_COMMIT });
  assert.equal(result.present, true);
});
