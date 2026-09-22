// Reads a single trusted file from the target repository at one exact commit.
//
// Phase 2A: this module performs NO real call against the private target. The
// HTTP transport is always injected, never constructed here, and no credential
// is ever read from the environment by this file. Its job in this phase is to
// be the place where every defensive precondition lives, proven by tests.
//
// Everything it returns is DATA. It is never executed, imported, sourced,
// interpreted as shell, or handed to any runtime. No checkout is performed and
// no git binary is invoked.

import { TARGET_OWNER, TARGET_REPOSITORY, TRUSTED_PATHS } from './constants.mjs';

export const API_ORIGIN = 'https://api.github.com';
export const MAX_FILE_BYTES = 4 * 1024 * 1024; // 4 MiB defensive cap
export const COMMIT_SHA_PATTERN = /^[0-9a-f]{40}$/;

export const READER_ERROR_CODES = Object.freeze({
  BAD_BASE_URL: 'BAD_BASE_URL',
  BAD_PATH: 'BAD_PATH',
  BAD_REF: 'BAD_REF',
  REDIRECT: 'REDIRECT',
  TRANSPORT: 'TRANSPORT',
  HTTP_STATUS: 'HTTP_STATUS',
  UNEXPECTED_PAYLOAD: 'UNEXPECTED_PAYLOAD',
  BAD_ENCODING: 'BAD_ENCODING',
  BAD_BASE64: 'BAD_BASE64',
  TOO_LARGE: 'TOO_LARGE'
});

export class ReaderError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ReaderError';
    this.code = code;
  }
}

export function assertApiOrigin(baseUrl) {
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new ReaderError(READER_ERROR_CODES.BAD_BASE_URL, 'base URL is not a URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new ReaderError(READER_ERROR_CODES.BAD_BASE_URL, `only https is allowed, got ${parsed.protocol}`);
  }
  if (parsed.host !== 'api.github.com') {
    throw new ReaderError(READER_ERROR_CODES.BAD_BASE_URL, `only api.github.com is allowed, got ${parsed.host}`);
  }
  return parsed;
}

export function buildContentUrl(path, ref, baseUrl = API_ORIGIN) {
  assertApiOrigin(baseUrl);
  // The path comes from the closed allowlist, never from the target, so no
  // target-controlled value can ever steer the request.
  const url = new URL(
    `/repos/${TARGET_OWNER}/${TARGET_REPOSITORY}/contents/${path}`,
    baseUrl
  );
  url.searchParams.set('ref', ref);
  return assertApiOrigin(url.toString()).toString();
}

// Strict base64: GitHub wraps the payload at 60 characters, so newlines are
// stripped first; anything else that is not canonical base64 is rejected
// instead of being silently coerced by a lenient decoder.
export function decodeStrictBase64(value) {
  if (typeof value !== 'string') {
    throw new ReaderError(READER_ERROR_CODES.BAD_BASE64, 'content is not a string');
  }
  const compact = value.replace(/[\r\n]/g, '');
  if (compact.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact)) {
    throw new ReaderError(READER_ERROR_CODES.BAD_BASE64, 'content is not canonical base64');
  }
  const bytes = Buffer.from(compact, 'base64');
  if (bytes.toString('base64') !== compact) {
    throw new ReaderError(READER_ERROR_CODES.BAD_BASE64, 'content is not canonical base64');
  }
  return bytes;
}

/**
 * Builds a reader bound to one approved commit. The returned reader refuses any
 * path outside the trust surface and any ref other than that approved commit,
 * so neither a caller bug nor a manipulated manifest can widen what is fetched.
 *
 * @param {{ transport: Function, approvedCommit: string, baseUrl?: string }} options
 */
export function createGithubContentReader({ transport, approvedCommit, baseUrl = API_ORIGIN }) {
  if (typeof transport !== 'function') {
    throw new TypeError('transport must be an injected function');
  }
  if (typeof approvedCommit !== 'string' || !COMMIT_SHA_PATTERN.test(approvedCommit)) {
    throw new ReaderError(READER_ERROR_CODES.BAD_REF, 'approvedCommit must be 40 lowercase hex characters');
  }
  assertApiOrigin(baseUrl);

  return async function readTrustedFile({ path, ref }) {
    if (!TRUSTED_PATHS.includes(path)) {
      throw new ReaderError(READER_ERROR_CODES.BAD_PATH, `path is outside the trust surface: ${String(path)}`);
    }
    if (typeof ref !== 'string' || !COMMIT_SHA_PATTERN.test(ref)) {
      throw new ReaderError(READER_ERROR_CODES.BAD_REF, 'ref must be 40 lowercase hex characters');
    }
    if (ref !== approvedCommit) {
      throw new ReaderError(READER_ERROR_CODES.BAD_REF, 'ref does not match the approved commit');
    }

    const url = buildContentUrl(path, ref, baseUrl);

    let response;
    try {
      response = await transport({
        url,
        method: 'GET',
        redirect: 'error',
        headers: {
          accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28'
        }
      });
    } catch (error) {
      throw new ReaderError(READER_ERROR_CODES.TRANSPORT, `transport failed: ${error.message}`);
    }

    if (!response || typeof response !== 'object') {
      throw new ReaderError(READER_ERROR_CODES.UNEXPECTED_PAYLOAD, 'transport returned no response');
    }
    if (response.redirected === true || (response.status >= 300 && response.status < 400)) {
      throw new ReaderError(READER_ERROR_CODES.REDIRECT, 'redirects are not allowed');
    }
    if (typeof response.status !== 'number' || response.status < 200 || response.status >= 300) {
      throw new ReaderError(READER_ERROR_CODES.HTTP_STATUS, `unexpected HTTP status ${String(response.status)}`);
    }

    const body = response.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw new ReaderError(READER_ERROR_CODES.UNEXPECTED_PAYLOAD, 'response body is not a content object');
    }
    if (body.type !== 'file') {
      throw new ReaderError(READER_ERROR_CODES.UNEXPECTED_PAYLOAD, `expected a regular file, got ${String(body.type)}`);
    }
    if (body.encoding !== 'base64') {
      throw new ReaderError(READER_ERROR_CODES.BAD_ENCODING, `expected base64 encoding, got ${String(body.encoding)}`);
    }
    if (typeof body.size === 'number' && body.size > MAX_FILE_BYTES) {
      throw new ReaderError(READER_ERROR_CODES.TOO_LARGE, 'declared size exceeds the 4 MiB cap');
    }
    if (typeof body.content === 'string' && body.content.length > MAX_FILE_BYTES * 2) {
      throw new ReaderError(READER_ERROR_CODES.TOO_LARGE, 'encoded content exceeds the 4 MiB cap');
    }

    const bytes = decodeStrictBase64(body.content);
    if (bytes.byteLength > MAX_FILE_BYTES) {
      throw new ReaderError(READER_ERROR_CODES.TOO_LARGE, 'decoded content exceeds the 4 MiB cap');
    }

    // `present: true` plus opaque bytes. Nothing here is ever interpreted.
    return { present: true, path, ref, bytes };
  };
}
