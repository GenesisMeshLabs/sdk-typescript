import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { packReasons, parseJson, verifyAuditPack } from '../src/index.js';
import type { StoreAnchor } from '../src/index.js';

/**
 * Audit packs holding grants (v1.6.0 review fixes), written by the core's NA
 * with its own test helpers (`tests/fixtures/grant-packs.json`, from
 * genesismesh feat/grants): a grant under an agreement, whose pack holds
 * `trust/agreements.jsonl` and checks it (and four refused variants, the last
 * without the responder's treaty, which an agreement the NA signed for both
 * parties needs (core 39b34d6); each
 * re-signed as an operator holding the NA key could), and a range after a
 * quarantined use, which cites the grant's whole chain. Each case carries the
 * Python reference's verdict.
 */
interface Case {
  id: string;
  root_public_key: string;
  held_anchors: StoreAnchor[];
  files: Record<string, string>;
  verified: boolean;
  reasons: string[];
}

const fixture = parseJson(readFileSync(fileURLToPath(new URL('./fixtures/grant-packs.json', import.meta.url)), 'utf-8')) as { cases: Case[] };

describe('audit packs holding grants (v1.6.0)', () => {
  it('holds the six cases', () => {
    expect(fixture.cases.map(c => c.id)).toEqual([
      'agreement-valid', 'agreement-missing', 'agreement-unsigned', 'agreement-changed', 'agreement-responder-treaty-stripped',
      'range-after-quarantined-use',
    ]);
  });

  it.each(fixture.cases.map(c => [c.id, c] as const))('%s', (_id, c) => {
    const result = verifyAuditPack(c.files, { rootPublicKey: c.root_public_key, heldAnchors: c.held_anchors });
    expect({ verified: result.verified, reasons: [...new Set(packReasons(result))].sort() })
      .toEqual({ verified: c.verified, reasons: c.reasons });
  });

  it('accepts the optional agreements file, and only a pack holding a grant under an agreement has it', () => {
    const [valid] = fixture.cases;
    expect(Object.keys(valid!.files)).toContain('trust/agreements.jsonl');
    expect(Object.keys(fixture.cases[5]!.files)).not.toContain('trust/agreements.jsonl');
    const cited = fixture.cases[5]!.files['cited.jsonl']!.split('\n').filter(Boolean)
      .map(line => (parseJson(line) as { entry: { entry_kind: string } }).entry.entry_kind);
    expect(cited).toEqual(expect.arrayContaining(['grant', 'grant_execution', 'quarantine']));
  });
});
