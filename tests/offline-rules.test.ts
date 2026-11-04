import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { checkEventsAgainstAnchors, keyPlacementProblem, parseJson, parseRfc3339 } from '../src/index.js';
import type { EvidenceStoreVerification, ExecutorKeyInfo, StoreAnchor } from '../src/index.js';

describe('offline rules as the references read them (1.9.0)', () => {
  it('refuses an RFC 3339 time outside the years 1 to 9999 once in UTC', () => {
    expect(parseRfc3339('0001-01-01T00:00:00Z')).toBe('0001-01-01T00:00:00Z');
    expect(parseRfc3339('9999-12-31T23:59:59Z')).toBe('9999-12-31T23:59:59Z');
    expect(parseRfc3339('0001-01-01T00:01:00+00:01')).toBe('0001-01-01T00:00:00Z');
    expect(() => parseRfc3339('0001-01-01T00:00:00+00:01')).toThrow('not an RFC 3339 date-time');
    expect(() => parseRfc3339('9999-12-31T23:59:59-00:01')).toThrow('not an RFC 3339 date-time');
  });

  it('reads a key placement time with more than six fraction digits to the microsecond', () => {
    const key = (registered: string, retired?: string): ExecutorKeyInfo => ({
      key_id: 'k', public_key: 'p', executor_sovereign_id: 's', role: 'executor', resource_prefix: null,
      registered_at: registered, retired_at: retired ?? null, registered_at_time: registered, retired_at_time: retired ?? null,
    } as ExecutorKeyInfo);
    // .NET's round-trip format writes seven digits; the references read six.
    expect(keyPlacementProblem(key('2026-01-01T00:00:00.0000009Z'), 5, '2026-01-01T00:00:00Z')).toBeNull();
    expect(keyPlacementProblem(key('2026-01-01T00:00:00.0000019Z'), 5, '2026-01-01T00:00:00Z')).toBe('evidence_unknown_executor');
    expect(keyPlacementProblem(key('2025-12-31T00:00:00Z', '2026-01-01T00:00:00.0000009Z'), 5, '2026-01-01T00:00:00Z'))
      .toBe('evidence_executor_key_retired');
  });

  it('refuses an anchor that is not well formed in the export check, so it never counts as matched', () => {
    const audit = parseJson(readFileSync(fileURLToPath(new URL('./fixtures/conformance/audit.json', import.meta.url)), 'utf-8')) as {
      vectors: Array<{ id: string; input: Record<string, unknown> }>;
    };
    const anchors = audit.vectors.find(v => v.id === 'anchors-across-succession')!.input['anchors'] as StoreAnchor[];
    const result = { verified: true, failures: [] } as unknown as EvidenceStoreVerification;
    expect(() => checkEventsAgainstAnchors([], [{ ...anchors[0]!, store_sequence: '5' as never }], result))
      .toThrow('invalid store anchor');
    expect(() => checkEventsAgainstAnchors([], [{ ...anchors[0]!, entry_digest: undefined as never }], result))
      .toThrow('invalid store anchor');
    expect(() => checkEventsAgainstAnchors([], anchors, result)).not.toThrow();
  });
});
