import { describe, expect, it } from '@jest/globals';
import { GenesisMeshClient, GenesisMeshError } from '../src/index.js';
import { buildTransport, mockFetch, TEST_KEY } from './helpers.js';

/**
 * A caller-supplied ID travels as one encoded path segment and cannot address another route.
 * encodeURIComponent keeps `/`, `?`, `#` and `%` inside the segment, but leaves `.` and `..`
 * as they are, and URL parsing (fetch) resolves those: `attestation.get('..')` requested `/`,
 * and `grants.revokeGrant('..')` requested `/admin/revoke`. The transport now refuses a path
 * with a dot segment before it signs or sends anything.
 */
type Call = (gm: GenesisMeshClient, id: string) => Promise<unknown>;

const SINGLE: [string, Call][] = [
  ['attestation.get', (gm, id) => gm.attestation.get(id)],
  ['attestation.revoke', (gm, id) => gm.attestation.revoke(id)],
  ['policy.history', (gm, id) => gm.policy.history(id)],
  ['policy.activate', (gm, id) => gm.policy.activate(id, 1)],
  ['policy.deactivate', (gm, id) => gm.policy.deactivate(id, 1)],
  ['evidenceStore.remediation', (gm, id) => gm.evidenceStore.remediation(id)],
  ['evidenceStore.markNotified', (gm, id) => gm.evidenceStore.markNotified(id)],
  ['evidenceStore.review', (gm, id) => gm.evidenceStore.review(id)],
  ['evidenceStore.decideReview', (gm, id) => gm.evidenceStore.decideReview(id, { verdict: 'upheld' } as never)],
  ['evidenceStore.judgeObservation', (gm, id) => gm.evidenceStore.judgeObservation(id)],
  ['evidenceStore.judgeBreakGlass', (gm, id) => gm.evidenceStore.judgeBreakGlass(id)],
  ['evidenceStore.proposeHolder', (gm, id) => gm.evidenceStore.proposeHolder(id, 'team-b')],
  ['evidenceStore.approveHolder', (gm, id) => gm.evidenceStore.approveHolder(id)],
  ['evidenceStore.vendorHistory', (gm, id) => gm.evidenceStore.vendorHistory(id)],
  ['evidenceStore.retireExecutorKey', (gm, id) => gm.evidenceStore.retireExecutorKey(id)],
  ['grants.getGrant', (gm, id) => gm.grants.getGrant(id)],
  ['grants.listGrantUses', (gm, id) => gm.grants.listGrantUses(id)],
  ['grants.revokeGrant', (gm, id) => gm.grants.revokeGrant(id)],
];

/** Resource IDs are paths (`vaults/kv/secrets/name`): each segment is encoded, `/` is kept. */
const RESOURCE: [string, Call][] = [
  ['evidenceStore.resourceHistory', (gm, id) => gm.evidenceStore.resourceHistory(id)],
  ['evidenceStore.resourceChanges', (gm, id) => gm.evidenceStore.resourceChanges(id)],
  ['evidenceStore.storedResourceHead', (gm, id) => gm.evidenceStore.storedResourceHead(id)],
];

function client() {
  const fetch = mockFetch({ status: 200, body: {} });
  const gm = new GenesisMeshClient({
    audience: 'TEST', baseUrl: 'http://localhost', signingKeyBase64: TEST_KEY.seedBase64, keyId: 'test',
    fetch: fetch as unknown as typeof globalThis.fetch,
  });
  return { gm, fetch };
}

async function refused(call: Call, id: string) {
  const { gm, fetch } = client();
  const error = await call(gm, id).then(() => null, (err: unknown) => err);
  expect(error).toBeInstanceOf(GenesisMeshError);
  expect(error).toMatchObject({ code: 'invalid_path_segment' });
  expect(fetch).not.toHaveBeenCalled();
}

/** The path fetch requests, as URL parsing resolves it. */
async function requestedPath(call: Call, id: string): Promise<string> {
  const { gm, fetch } = client();
  await call(gm, id).catch(() => undefined);
  expect(fetch).toHaveBeenCalled();
  return new URL(fetch.mock.calls[0]![0] as string).pathname;
}

describe('caller-supplied IDs in request paths', () => {
  describe.each(SINGLE)('%s', (_name, call) => {
    it.each(['..', '.'])('refuses the dot segment %j before sending', id => refused(call, id));

    it('keeps /, ?, #, % and dots inside one segment', async () => {
      const id = 'a/../b?c=1#d%2e%2e';
      const path = await requestedPath(call, id);
      expect(path).toContain(`/${encodeURIComponent(id)}`);
      expect(path.split('/').map(decodeURIComponent)).toContain(id);
    });
  });

  describe.each(RESOURCE)('%s', (_name, call) => {
    it.each(['..', '.', 'vaults/../../grants/x', 'vaults/kv/.', '../admin/grants'])(
      'refuses a resource ID with a dot segment (%j) before sending', id => refused(call, id));

    it('sends each segment of a resource ID encoded', async () => {
      const path = await requestedPath(call, 'vaults/kv:1/secrets/a b?..');
      expect(path.endsWith('/vaults/kv%3A1/secrets/a%20b%3F..')).toBe(true);
    });
  });

  it('refuses a dot segment in a raw transport path, encoded or not', async () => {
    for (const path of ['/admin/grants/../revoke', '/admin/grants/%2E%2e/revoke', '/attestations/.']) {
      const fetch = mockFetch({ status: 200, body: {} });
      const http = buildTransport(fetch);
      await expect(http.adminGet(path)).rejects.toMatchObject({ code: 'invalid_path_segment' });
      await expect(http.publicGet(path)).rejects.toMatchObject({ code: 'invalid_path_segment' });
      await expect(http.adminPost(path, {})).rejects.toMatchObject({ code: 'invalid_path_segment' });
      expect(fetch).not.toHaveBeenCalled();
    }
  });
});
