#!/usr/bin/env node
// Refuses to let obviously private material live in this PUBLIC repository.
//
// This is a last-line guard, not a secret scanner: it looks for unmistakable
// markers of credentials and for file types that never belong here. Every
// marker below is assembled from fragments at runtime, so this file can be
// scanned by itself without matching its own source.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve, basename } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(join(HERE, '..'));

const j = (...parts) => parts.join('');

export const CONTENT_MARKERS = [
  { id: 'pem-private-key', marker: j('-----BEGIN PRIVATE', ' KEY-----') },
  { id: 'pem-rsa-private-key', marker: j('-----BEGIN RSA PRIVATE', ' KEY-----') },
  { id: 'github-fine-grained-token', marker: j('github', '_pat_') },
  { id: 'github-classic-token', marker: j('ghp', '_') },
  { id: 'anthropic-api-key', marker: j('sk', '-ant-') },
  { id: 'postgres-url', marker: j('postgres', '://') },
  { id: 'postgresql-url', marker: j('postgresql', '://') }
];

const FORBIDDEN_NAME_TESTS = [
  { id: 'dotenv', test: (name) => name === '.env' || name.startsWith('.env.') },
  { id: 'pem-file', test: (name) => name.endsWith('.pem') },
  { id: 'key-file', test: (name) => name.endsWith('.key') },
  { id: 'pkcs12-file', test: (name) => name.endsWith('.p12') || name.endsWith('.pfx') }
];

const SKIP_DIRECTORIES = new Set(['.git', 'node_modules']);

export function listFiles(root) {
  const found = [];
  const walk = (absolute) => {
    for (const entry of readdirSync(absolute).sort()) {
      if (SKIP_DIRECTORIES.has(entry)) continue;
      const child = join(absolute, entry);
      if (statSync(child).isDirectory()) walk(child);
      else found.push(relative(root, child));
    }
  };
  walk(root);
  return found;
}

function isProbablyBinary(buffer) {
  return buffer.includes(0);
}

export function scanFiles(root, relativePaths) {
  const findings = [];
  for (const relativePath of relativePaths) {
    const name = basename(relativePath);
    for (const rule of FORBIDDEN_NAME_TESTS) {
      if (rule.test(name)) {
        findings.push({ path: relativePath, rule: rule.id, kind: 'forbidden-file' });
      }
    }
    const buffer = readFileSync(join(root, relativePath));
    if (isProbablyBinary(buffer)) continue;
    const text = buffer.toString('utf8');
    for (const { id, marker } of CONTENT_MARKERS) {
      if (text.includes(marker)) {
        findings.push({ path: relativePath, rule: id, kind: 'forbidden-content' });
      }
    }
  }
  return findings;
}

export function scanRepository(root = REPO_ROOT) {
  return scanFiles(root, listFiles(root));
}

function main() {
  const findings = scanRepository();
  if (findings.length > 0) {
    process.stderr.write('PUBLICATION SAFETY CHECK: FAIL\n');
    for (const finding of findings) {
      process.stderr.write(`  - ${finding.path}: ${finding.kind} (${finding.rule})\n`);
    }
    process.stderr.write('Stop. Do not publish. Revoke any affected credential first.\n');
    return 1;
  }
  process.stdout.write('PUBLICATION SAFETY CHECK: PASS\n');
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main());
}
