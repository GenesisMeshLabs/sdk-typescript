import { describe, expect, it } from '@jest/globals';
import { GenesisMeshClient } from '../src/index.js';
import { mockFetch, TEST_KEY } from './helpers.js';

function client(...responses: Array<{ status: number; body: unknown }>) {
  const fetch = mockFetch(...responses);
  const gm = new GenesisMeshClient({
    audience: 'TEST', baseUrl: 'http://na', signingKeyBase64: TEST_KEY.seedBase64, keyId: 'test',
    fetch: fetch as unknown as typeof globalThis.fetch,
  });
  return { gm, fetch, urls: () => fetch.mock.calls.map(c => String(c[0])) };
}

describe('arguments out of range are refused before anything is sent (1.9.0)', () => {
  it.each([
    ['an anchors limit of 0', (gm: GenesisMeshClient) => gm.evidenceStore.anchors({ limit: 0 })],
    ['an anchors limit over 1000', (gm: GenesisMeshClient) => gm.evidenceStore.anchors({ limit: 1001 })],
    ['a fractional anchors limit', (gm: GenesisMeshClient) => gm.evidenceStore.anchors({ limit: 1.5 })],
    ['a negative after_anchor', (gm: GenesisMeshClient) => gm.evidenceStore.anchors({ after_anchor: -1 })],
    ['allAnchors after a negative anchor', (gm: GenesisMeshClient) => gm.evidenceStore.allAnchors(-1)],
    ['an audit pack from position 0', (gm: GenesisMeshClient) => gm.evidenceStore.auditPack({ from_sequence: 0 })],
    ['an audit pack until position 0', (gm: GenesisMeshClient) => gm.evidenceStore.auditPack({ until_sequence: 0 })],
    ['a grants limit of 0', (gm: GenesisMeshClient) => gm.grants.listGrants({ limit: 0 })],
    ['a grants limit over 500', (gm: GenesisMeshClient) => gm.grants.listGrants({ limit: 501 })],
    ['a uses limit over 500', (gm: GenesisMeshClient) => gm.grants.listGrantUses('g-1', { limit: 501 })],
  ])('%s', async (_name, call) => {
    const x = client({ status: 200, body: {} });
    await expect(call(x.gm)).rejects.toBeInstanceOf(RangeError);
    expect(x.fetch).not.toHaveBeenCalled();
  });

  it('takes the bounds themselves', async () => {
    const x = client(
      { status: 200, body: { anchors: [], count: 0, next_after_anchor: null } },
      { status: 200, body: { anchors: [], count: 0, next_after_anchor: null } },
      { status: 200, body: { grants: [], next_before: null } },
      { status: 200, body: { grant_id: 'g-1', uses: [], next_before: null } },
      { status: 200, body: {} },
    );
    await x.gm.evidenceStore.anchors({ limit: 1, after_anchor: 0 });
    await x.gm.evidenceStore.anchors({ limit: 1000 });
    await x.gm.grants.listGrants({ limit: 500 });
    await x.gm.grants.listGrantUses('g-1', { limit: 1 });
    await x.gm.evidenceStore.auditPack({ from_sequence: 1, until_sequence: 1 });
    expect(x.urls()).toEqual([
      'http://na/admin/evidence/anchors?limit=1&after_anchor=0', 'http://na/admin/evidence/anchors?limit=1000',
      'http://na/admin/grants?limit=500', 'http://na/admin/grants/g-1/uses?limit=1', 'http://na/admin/evidence/audit-pack',
    ]);
  });

  it('refuses a waiver\'s end given for another verdict, or a waiver without one', async () => {
    const x = client({ status: 200, body: {} });
    await expect(x.gm.evidenceStore.decideReview('r1', { verdict: 'deny', waive_until: '2030-01-01T00:00:00Z' }))
      .rejects.toThrow('waive_until');
    await expect(x.gm.evidenceStore.decideReview('r1', { verdict: 'waive_until' })).rejects.toThrow('waive_until');
    expect(x.fetch).not.toHaveBeenCalled();
  });
});

describe('the grant lists, followed page by page (1.9.0)', () => {
  const grant = (id: string) => ({ grant_id: id });
  const use = (n: number) => ({ use_id: `u-${n}`, use_sequence: n });

  it('allGrants follows next_before with the filter and limit, and stops on an empty page', async () => {
    const x = client(
      { status: 200, body: { grants: [grant('g-3'), grant('g-2')], next_before: 'g-2' } },
      { status: 200, body: { grants: [grant('g-1')], next_before: 'g-1' } },
      { status: 200, body: { grants: [], next_before: 'g-0' } },
    );
    const ids: string[] = [];
    for await (const g of x.gm.grants.allGrants({ status: 'active', limit: 2 })) ids.push(g.grant_id);
    expect(ids).toEqual(['g-3', 'g-2', 'g-1']);
    expect(x.urls()).toEqual([
      'http://na/admin/grants?status=active&limit=2', 'http://na/admin/grants?status=active&limit=2&before=g-2',
      'http://na/admin/grants?status=active&limit=2&before=g-1',
    ]);
  });

  it('allGrantUses follows next_before, and refuses a cursor that does not advance', async () => {
    const x = client(
      { status: 200, body: { grant_id: 'g-1', uses: [use(3), use(2)], next_before: 2 } },
      { status: 200, body: { grant_id: 'g-1', uses: [use(1)], next_before: null } },
    );
    const seen: number[] = [];
    for await (const u of x.gm.grants.allGrantUses('g-1', 2)) seen.push(u.use_sequence);
    expect(seen).toEqual([3, 2, 1]);
    expect(x.urls()).toEqual(['http://na/admin/grants/g-1/uses?limit=2', 'http://na/admin/grants/g-1/uses?limit=2&before=2']);

    const stuck = client(
      { status: 200, body: { grant_id: 'g-1', uses: [use(3)], next_before: 3 } },
      { status: 200, body: { grant_id: 'g-1', uses: [use(3)], next_before: 3 } },
    );
    const read = async () => { for await (const _ of stuck.gm.grants.allGrantUses('g-1')) { /* reading */ } };
    await expect(read()).rejects.toThrow('cursor did not advance');
    const grants = client(
      { status: 200, body: { grants: [grant('g-2')], next_before: 'g-2' } },
      { status: 200, body: { grants: [grant('g-2')], next_before: 'g-2' } },
    );
    const all = async () => { for await (const _ of grants.gm.grants.allGrants()) { /* reading */ } };
    await expect(all()).rejects.toThrow('cursor did not advance');
  });
});
