import { describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Conformance receipts (tests/receipts.ts): runs the conformance runners with
 * GM_CONFORMANCE_RECEIPTS set and checks the receipts against the suite files: one receipt
 * per suite the bundle maps to this SDK, naming its suite file, and every kind of the file
 * accounted for (run + not_run equals the file's count). Only the kinds this SDK does not
 * run by design are not_run: the NA's own out_of_band rules, grants' na_only_kinds
 * (issuance), and consensus, which has no offline verifier here.
 */
const root = fileURLToPath(new URL('..', import.meta.url));

/** The runner of each mapped suite (test file), and the kinds it does not run by design. */
const RUNNERS: Record<string, { file: string; notRun: string[] }> = {
  admin_auth: { file: 'auth', notRun: [] },
  audit: { file: 'audit-conformance', notRun: [] },
  canonical: { file: 'canonical', notRun: [] },
  consensus: { file: 'consensus', notRun: ['*'] },
  field_registry: { file: 'field_registry', notRun: [] },
  grants: { file: 'grants-conformance', notRun: ['issuance'] },
  interop: { file: 'conformance', notRun: [] },
  out_of_band: { file: 'out-of-band', notRun: ['time_bounds', 'policy_history'] },
  remediation: { file: 'remediation-conformance', notRun: [] },
};

interface ReceiptFile {
  schema: string; suite: string; file: string; runner: string;
  run: Record<string, number>; not_run: Record<string, number>;
}

/** Vectors per kind in a suite file (no `kind` counts under "*"). */
function kindCounts(suite: string): Record<string, number> {
  const parsed = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'conformance', `${suite}.json`), 'utf8')) as
    { vectors: { kind?: string }[] };
  const counts: Record<string, number> = {};
  for (const vector of parsed.vectors) counts[vector.kind ?? '*'] = (counts[vector.kind ?? '*'] ?? 0) + 1;
  return counts;
}

describe('conformance receipts', () => {
  it('accounts for every kind of every mapped suite', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gm-receipts-'));
    try {
      const pattern = `tests/(${Object.values(RUNNERS).map(r => r.file.replace(/[-_]/g, '[-_]')).join('|')})\\.test\\.ts$`;
      const { GM_CONFORMANCE_RECEIPTS: _unset, ...env } = process.env;
      const result = spawnSync(process.execPath, ['--experimental-vm-modules', 'node_modules/jest/bin/jest.js',
        '--config', 'jest.config.cjs', '--ci', `--testPathPatterns=${pattern}`], {
        cwd: root, encoding: 'utf8', env: { ...env, GM_CONFORMANCE_RECEIPTS: dir },
      });
      expect(result.status).toBe(0);

      const files = readdirSync(dir).sort();
      expect(files).toEqual(Object.entries(RUNNERS).map(([suite, { file }]) => `${suite}.${file}.json`).sort());
      for (const [suite, { file, notRun }] of Object.entries(RUNNERS)) {
        const receipt = JSON.parse(readFileSync(join(dir, `${suite}.${file}.json`), 'utf8')) as ReceiptFile;
        expect(receipt).toMatchObject({ schema: 'gm.contract.receipt/1', suite, file: `tests/fixtures/conformance/${suite}.json` });
        expect(existsSync(join(root, receipt.file))).toBe(true);
        expect(receipt.runner.startsWith(`tests/${file}.test.ts:`)).toBe(true);

        const counts = kindCounts(suite);
        const named = [...new Set([...Object.keys(receipt.run), ...Object.keys(receipt.not_run)])].sort();
        expect({ suite, kinds: named }).toEqual({ suite, kinds: Object.keys(counts).sort() });
        for (const [kind, total] of Object.entries(counts)) {
          expect({ suite, kind, accounted: (receipt.run[kind] ?? 0) + (receipt.not_run[kind] ?? 0) })
            .toEqual({ suite, kind, accounted: total });
        }
        expect({ suite, notRun: Object.keys(receipt.not_run).sort() }).toEqual({ suite, notRun: [...notRun].sort() });
      }
      // grants.json declares its NA-only kinds itself.
      const grants = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'conformance', 'grants.json'), 'utf8')) as
        { na_only_kinds: string[] };
      expect(grants.na_only_kinds).toEqual(RUNNERS['grants']!.notRun);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);
});
