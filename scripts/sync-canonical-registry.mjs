#!/usr/bin/env node
/**
 * Write src/canonical-registry.ts from the shared conformance suite
 * (tests/fixtures/conformance/field_registry.json, a copy of the core's
 * conformance/vectors/field_registry.json). Run after copying a new suite:
 *
 *   npm run sync:registry
 *
 * The conformance test fails while the embedded registry differs from the suite.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const suite = JSON.parse(readFileSync(fileURLToPath(new URL('../tests/fixtures/conformance/field_registry.json', import.meta.url)), 'utf-8'));
const body = `/**
 * The field registry of signed records (v1.2.0), generated from the Python
 * reference models. Do not edit: run \`npm run sync:registry\` after copying a
 * new conformance suite. See src/strict.ts.
 */
import type { CanonicalRegistry } from './strict.js';

/** Frozen at every level, so no code in the process can whitelist a field. */
function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const inner of Object.values(value)) freeze(inner);
    Object.freeze(value);
  }
  return value;
}

export const CANONICAL_REGISTRY: CanonicalRegistry = freeze(${JSON.stringify(suite.registry, null, 2)});
`;
writeFileSync(fileURLToPath(new URL('../src/canonical-registry.ts', import.meta.url)), body.replace(/\r\n/g, '\n'));
console.log(`src/canonical-registry.ts: ${Object.keys(suite.registry.models).length} models, version ${suite.registry.version}`);
