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
import { SYNTHETIC_COMMIT, syntheticBytes } from './executor-fixtures.mjs';

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
