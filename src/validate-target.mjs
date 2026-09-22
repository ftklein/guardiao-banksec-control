#!/usr/bin/env node
// Deterministic, dependency-free validation of a BankSec control plane target
// manifest against schemas/target.schema.json.
//
// Hard constraints (by design, not by convenience):
//   - strict JSON only: no JSON5, no YAML, no eval, no Function(), no child
//     process is ever used to interpret a manifest;
//   - the manifest is never rewritten or repaired: this module only reports;
//   - unknown schema keywords are a hard error, so the validator can never
//     silently ignore a constraint it does not implement (fail closed).

import { readFileSync } from 'node:fs';
import { TARGET_OWNER, TARGET_REPOSITORY, STATUS_CONTEXT, TRUSTED_PATHS } from './executor/constants.mjs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
export const SCHEMA_PATH = join(HERE, '..', 'schemas', 'target.schema.json');

// The semantic invariants below are specific to this control plane, so they may
// only be applied to this control plane's own schema, identified explicitly.
export const CONTROL_PLANE_SCHEMA_ID =
  'https://github.com/ftklein/guardiao-banksec-control/schemas/target.schema.json';

const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description', 'definitions']);
const SUPPORTED = new Set([
  '$ref', 'type', 'const', 'enum', 'pattern', 'properties', 'required',
  'additionalProperties', 'items', 'minItems', 'maxItems', 'oneOf'
]);

export function readJsonFile(path) {
  const raw = readFileSync(path, 'utf8');
  if (raw.charCodeAt(0) === 0xfeff) {
    throw new SyntaxError(`${path}: byte order mark is not accepted`);
  }
  return JSON.parse(raw);
}

export function loadSchema(path = SCHEMA_PATH) {
  const schema = readJsonFile(path);
  if (!schema || schema.$id !== CONTROL_PLANE_SCHEMA_ID) {
    // Without its canonical identity the schema cannot carry the semantic
    // invariants, so loading it at all is refused rather than silently
    // validating less than it should.
    throw new Error(`${path}: schema is missing the control plane $id`);
  }
  return schema;
}

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (Number.isInteger(value)) return 'integer';
  return typeof value;
}

function deref(node, root, where, errors) {
  if (!Object.prototype.hasOwnProperty.call(node, '$ref')) return node;
  const ref = node.$ref;
  const prefix = '#/definitions/';
  if (typeof ref !== 'string' || !ref.startsWith(prefix)) {
    errors.push(`${where}: unsupported $ref "${String(ref)}"`);
    return null;
  }
  const name = ref.slice(prefix.length);
  const target = root.definitions && root.definitions[name];
  if (!target || typeof target !== 'object') {
    errors.push(`${where}: unresolvable $ref "${ref}"`);
    return null;
  }
  return target;
}

function check(schema, value, where, root, errors) {
  const node = deref(schema, root, where, errors);
  if (node === null) return;

  for (const keyword of Object.keys(node)) {
    if (!SUPPORTED.has(keyword) && !ANNOTATIONS.has(keyword)) {
      errors.push(`${where}: unsupported schema keyword "${keyword}" (validator fails closed)`);
      return;
    }
  }

  if (Object.prototype.hasOwnProperty.call(node, 'oneOf')) {
    const matches = [];
    const branchErrors = [];
    node.oneOf.forEach((branch, index) => {
      const local = [];
      check(branch, value, where, root, local);
      if (local.length === 0) matches.push(index);
      else branchErrors.push(`  [${branch.title || index}] ${local.join('; ')}`);
    });
    if (matches.length !== 1) {
      errors.push(
        `${where}: value matches ${matches.length} of ${node.oneOf.length} allowed states; exactly one is required\n${branchErrors.join('\n')}`
      );
    }
    return;
  }

  if (Object.prototype.hasOwnProperty.call(node, 'type')) {
    const actual = typeOf(value);
    const expected = node.type;
    const ok = expected === actual || (expected === 'number' && actual === 'integer');
    if (!ok) {
      errors.push(`${where}: expected type ${expected}, got ${actual}`);
      return;
    }
  }

  if (Object.prototype.hasOwnProperty.call(node, 'const') && value !== node.const) {
    errors.push(`${where}: expected constant ${JSON.stringify(node.const)}, got ${JSON.stringify(value)}`);
    return;
  }

  if (Object.prototype.hasOwnProperty.call(node, 'enum') && !node.enum.includes(value)) {
    errors.push(`${where}: ${JSON.stringify(value)} is not an allowed value`);
    return;
  }

  if (Object.prototype.hasOwnProperty.call(node, 'pattern')) {
    if (typeof value !== 'string' || !new RegExp(node.pattern).test(value)) {
      errors.push(`${where}: ${JSON.stringify(value)} does not match ${node.pattern}`);
      return;
    }
  }

  if (typeOf(value) === 'object') {
    const properties = node.properties || {};
    for (const name of node.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, name)) {
        errors.push(`${where}: missing required property "${name}"`);
      }
    }
    if (node.additionalProperties === false) {
      for (const name of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(properties, name)) {
          errors.push(`${where}: unknown property "${name}" is not allowed`);
        }
      }
    }
    for (const [name, sub] of Object.entries(properties)) {
      if (Object.prototype.hasOwnProperty.call(value, name)) {
        check(sub, value[name], `${where}/${name}`, root, errors);
      }
    }
  }

  if (typeOf(value) === 'array') {
    if (typeof node.minItems === 'number' && value.length < node.minItems) {
      errors.push(`${where}: expected at least ${node.minItems} item(s), got ${value.length}`);
    }
    if (typeof node.maxItems === 'number' && value.length > node.maxItems) {
      errors.push(`${where}: expected at most ${node.maxItems} item(s), got ${value.length}`);
    }
    if (node.items) {
      value.forEach((item, index) => check(node.items, item, `${where}[${index}]`, root, errors));
    }
  }
}

// Invariants the schema alone cannot express. JSON Schema can bound the number
// of entries, but it cannot say "these exact four paths, each exactly once", so
// an ACTIVE manifest is additionally checked semantically here. Two entries for
// the same path are rejected even when their digests differ.
export function checkTrustSurfaceInvariants(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object') return errors;

  if (manifest.target && typeof manifest.target === 'object') {
    if (manifest.target.owner !== TARGET_OWNER) {
      errors.push(`manifest/target/owner: this control plane governs only ${TARGET_OWNER}`);
    }
    if (manifest.target.repository !== TARGET_REPOSITORY) {
      errors.push(`manifest/target/repository: this control plane governs only ${TARGET_REPOSITORY}`);
    }
  }
  if ('statusContext' in manifest && manifest.statusContext !== STATUS_CONTEXT) {
    errors.push(`manifest/statusContext: only ${STATUS_CONTEXT} is allowed`);
  }

  const trust = manifest.trust;
  if (!trust || typeof trust !== 'object' || trust.state !== 'ACTIVE') return errors;

  const entries = trust.trustedFiles;
  if (!Array.isArray(entries)) return errors;

  const paths = entries.map((entry) => (entry && typeof entry === 'object' ? entry.path : undefined));
  const unique = new Set(paths);
  if (paths.length !== unique.size) {
    errors.push('manifest/trust/trustedFiles: duplicate path entries are not allowed');
  }
  for (const path of TRUSTED_PATHS) {
    if (!unique.has(path)) {
      errors.push(`manifest/trust/trustedFiles: the trust surface is incomplete, "${path}" is missing`);
    }
  }
  for (const path of unique) {
    if (!TRUSTED_PATHS.includes(path)) {
      errors.push(`manifest/trust/trustedFiles: "${String(path)}" is not part of the trust surface`);
    }
  }
  if (unique.size !== TRUSTED_PATHS.length || paths.length !== TRUSTED_PATHS.length) {
    errors.push(
      `manifest/trust/trustedFiles: an ACTIVE manifest must pin exactly ${TRUSTED_PATHS.length} files, got ${paths.length}`
    );
  }
  return errors;
}

export function validateTarget(manifest, schema = loadSchema()) {
  const errors = [];
  check(schema, manifest, 'manifest', schema, errors);
  // Semantic invariants are only meaningful for this control plane's own
  // schema, identified by its $id; a caller passing any other schema gets
  // structural validation alone and never BankSec-specific errors.
  if (schema && schema.$id === CONTROL_PLANE_SCHEMA_ID) {
    errors.push(...checkTrustSurfaceInvariants(manifest));
  }
  return { valid: errors.length === 0, errors };
}

export function validateTargetFile(path, schema = loadSchema()) {
  let manifest;
  try {
    manifest = readJsonFile(path);
  } catch (error) {
    return { valid: false, errors: [`${path}: ${error.message}`], manifest: null };
  }
  return { ...validateTarget(manifest, schema), manifest };
}

function main(argv) {
  const [, , target] = argv;
  if (!target) {
    process.stderr.write('usage: node src/validate-target.mjs <targets/*.json>\n');
    return 64;
  }
  const result = validateTargetFile(resolve(target));
  if (!result.valid) {
    process.stderr.write(`MANIFEST INVALID: ${target}\n`);
    for (const error of result.errors) process.stderr.write(`  - ${error}\n`);
    return 1;
  }
  process.stdout.write(`MANIFEST VALID: ${target} (trust state: ${result.manifest.trust.state})\n`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main(process.argv));
}
