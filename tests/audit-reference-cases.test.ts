import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  canonicalJson, packReasons, parseChanges, parseExportLines, parseJson, renderReport, verifyAuditPack, verifyKeyHistory,
  verifyStoreAnchors,
} from '../src/index.js';
import type { ReportHeader, StoreAnchor } from '../src/index.js';

/**
 * Reports and changes files the Python reference rendered and read (1.9.0),
 * as sdk-dotnet's harnesses judged them: every report case, and every
 * changes file but the field size limit, which is tested apart. Read with
 * `parseJson`, so a float literal stays a float, as the reference reads it.
 */
interface Cases {
  render: Array<{
    id: string;
    input: {
      header: ReportHeader; lines: string; checks: Record<string, unknown>;
      states: Record<string, unknown> | null; notices: Record<string, unknown> | null;
    };
    expected: string;
  }>;
  changes_file: Array<{ id: string; text: string; csv: boolean; expected: { changes?: unknown[]; refused?: boolean } }>;
}

const fixture = (name: string) => readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf-8');
const cases = parseJson(fixture('audit-reference-cases.json')) as Cases;

describe('reports and changes files as the reference renders and reads them (1.9.0)', () => {
  it('holds the cases', () => {
    expect([cases.render.length, cases.changes_file.length]).toEqual([58, 99]);
  });

  it.each(cases.render.map(c => [c.id, c] as const))('renders %s', (_id, c) => {
    const i = c.input;
    expect(renderReport({
      manifest: i.header, entries: parseExportLines(i.lines), checks: i.checks, states: i.states ?? undefined,
      notices: i.notices ?? undefined,
    })).toBe(c.expected);
  });

  it.each(cases.changes_file.map(c => [c.id, c] as const))('reads %s', (_id, c) => {
    const read = () => parseChanges(c.text, { csv: c.csv });
    if (c.expected.refused) expect(read).toThrow();
    else expect(read()).toEqual(c.expected.changes);
  });

  it('writes a float of the checks as the reference does, in decimal below 2^53', () => {
    // The reference's rendering of these checks (render_report).
    const checks = parseJson('{"verified": true, "failures": [{"reason": 1e16, "file": 3.0, "store_sequence": 1e300, "detail": 2.5}], '
      + '"counts": {"big": 1e16, "one": 1.0, "zero": 0.0}}') as Record<string, unknown>;
    const report = renderReport({ manifest: cases.render[0]!.input.header, entries: [], checks });
    expect(report).toContain('| 1e+16 | 3 | 1e+300 | 2.5 |');
    expect(report).toContain('| big | 1e+16 |\n| one | 1 |\n\n');
  });

  it('refuses a CSV field longer than Python reads, counted in code points', () => {
    const file = (field: string) => `resource_id,action,changed_at\n${field},rotate,2026-03-01T12:00:00Z\n`;
    expect(parseChanges(file('r'.repeat(131072)), { csv: true })).toHaveLength(1);
    expect(() => parseChanges(file('r'.repeat(131073)), { csv: true })).toThrow('longer than 131072');
    expect(parseChanges(file('\u{1F600}'.repeat(131072)), { csv: true })).toHaveLength(1);
    expect(() => parseChanges(file('\u{1F600}'.repeat(131073)), { csv: true })).toThrow('longer than 131072');
    expect(() => parseChanges(file(`"${'r'.repeat(131073)}"`), { csv: true })).toThrow('longer than 131072');
  });
});

const audit = parseJson(fixture('conformance/audit.json')) as { vectors: Array<{ id: string; kind: string; input: Record<string, unknown> }> };
const vector = (id: string) => audit.vectors.find(v => v.id === id)!.input;

describe('audit packs and anchors as the reference reads them (1.9.0)', () => {
  it('refuses a manifest whose signature holds more than its key ID and signature: not the NA\'s form', () => {
    const input = vector('pack-frozen-1.5.0');
    const files = { ...(input['files'] as Record<string, string>) };
    const manifest = parseJson(files['manifest.json']!) as Record<string, unknown>;
    files['manifest.json'] = canonicalJson({ ...manifest, signature: { ...(manifest['signature'] as object), x: 1 } }) + '\n';
    const options = { rootPublicKey: input['root_public_key'] as string, heldAnchors: input['held_anchors'] as StoreAnchor[] };
    expect(packReasons(verifyAuditPack(files, options))).toEqual(['manifest_invalid']);
    expect(verifyAuditPack(input['files'] as Record<string, string>, options).verified).toBe(true);
  });

  it('verifies an anchor whose integers are written as floats, as the reference reads them (1 is 1.0)', () => {
    const input = vector('anchors-across-succession');
    const result = verifyKeyHistory(input['genesis'], input['successions'] as unknown[], input['root_public_key'] as string);
    const anchors = input['anchors'] as Array<Record<string, unknown>>;
    for (const field of ['anchor_sequence', 'store_sequence']) {
      const text = canonicalJson(anchors).replace(new RegExp(`"${field}":(\\d+)`, 'g'), `"${field}":$1.0`);
      expect(text).toMatch(new RegExp(`"${field}":\\d+\\.0`));
      const spelled = parseJson(text) as StoreAnchor[];
      expect(verifyStoreAnchors(spelled, { naPublicKeys: result.history! }).failures).toEqual([]);
    }
  });
});
