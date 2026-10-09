#!/usr/bin/env node
/**
 * Write src/canonical-registry.ts from the shared conformance suite
 * (tests/fixtures/conformance/canonical.json, a copy of the core's
 * conformance/vectors/canonical.json). Run after copying a new suite:
 *
 *   npm run sync:registry
 *
 * The conformance test fails while the embedded registry differs from the suite.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const suite = JSON.parse(readFileSync(fileURLToPath(new URL('../tests/fixtures/conformance/canonical.json', import.meta.url)), 'utf-8'));
const body = `/**
 * The field registry of signed records (v1.2.0), generated from the Python
 * reference models. Do not edit: run \`npm run sync:registry\` after copying a
 * new conformance suite. See src/strict.ts.
 */
import type { CanonicalRegistry } from './strict.js';

export const CANONICAL_REGISTRY: CanonicalRegistry = ${JSON.stringify(suite.registry, null, 2)};
`;
writeFileSync(fileURLToPath(new URL('../src/canonical-registry.ts', import.meta.url)), body.replace(/\r\n/g, '\n'));
console.log(`src/canonical-registry.ts: ${Object.keys(suite.registry.models).length} models, version ${suite.registry.version}`);
