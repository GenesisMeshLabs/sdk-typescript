import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import * as esm from 'genesis-mesh-sdk';
const cjs = createRequire(import.meta.url)('genesis-mesh-sdk');
for (const sdk of [esm, cjs]) {
  assert.equal(typeof sdk.GenesisMeshClient, 'function');
  assert.equal(typeof sdk.ExecutionRecorder, 'function');
  assert.equal(typeof sdk.governedAction, 'function');
  const fixture = sdk.parseJson(readFileSync(new URL('../tests/fixtures/python-vectors.json', import.meta.url), 'utf8'));
  assert.equal(sdk.verifyEvidenceEvents(sdk.parseExportLines(fixture.export), {
    naPublicKeys: [fixture.na_public_key], executorKeys: fixture.executor_keys,
  }).verified, true);
}
console.log('ESM and CommonJS package entry points verify the Python export.');
