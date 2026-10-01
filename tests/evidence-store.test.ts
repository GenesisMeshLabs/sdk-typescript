import { describe, expect, it } from '@jest/globals';
import { EvidenceStoreClient, executionDigest, parseExportLines } from '../src/index.js';
import { mockFetch, buildTransport } from './helpers.js';
import { vectors } from './vectors.js';

const v = vectors();
const events = parseExportLines(v.export);
async function collect<T>(items: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = []; for await (const item of items) result.push(item); return result;
}

describe('EvidenceStoreClient helpers', () => {
  it('follows search cursors and preserves filters', async () => {
    const fetch = mockFetch({ status: 200, body: { entries: events.slice(0, 2), next_after_sequence: 2 } }, { status: 200, body: { entries: events.slice(2), next_after_sequence: null } });
    const client = new EvidenceStoreClient(buildTransport(fetch));
    expect(await collect(client.iterate({ vendor_id: 'vendor' }))).toEqual(events);
    expect(fetch.mock.calls[1][0]).toContain('vendor_id=vendor&after_sequence=2');
  });
  it('rejects a non-advancing search cursor', async () => {
    const client = new EvidenceStoreClient(buildTransport(mockFetch({ status: 200, body: { entries: [], next_after_sequence: 0 } })));
    await expect(collect(client.iterate())).rejects.toThrow('cursor');
  });
  it('parses and pages NDJSON exports', async () => {
    const lines = v.export.trim().split('\n');
    const fetch = mockFetch({ status: 200, body: lines.slice(0, 5).join('\n') }, { status: 200, body: lines.slice(5).join('\n') });
    const client = new EvidenceStoreClient(buildTransport(fetch));
    expect(await collect(client.exportAll(0, 5))).toEqual(events);
    expect(fetch.mock.calls[1][0]).toContain('since_sequence=5&limit=5');
  });
  it.each([0, -1, 1001, 1.5])('rejects invalid export page size %s', async size => {
    const client = new EvidenceStoreClient(buildTransport(mockFetch({ status: 200, body: '' })));
    await expect(collect(client.exportAll(0, size))).rejects.toThrow('page size');
  });
  it('returns the newest resource head regardless of history order', async () => {
    const client = new EvidenceStoreClient(buildTransport(mockFetch({ status: 200, body: { entries: [...events].reverse(), verification: { verified: true } } })));
    expect(await client.resourceHead(v.resource_id)).toEqual({ resource_sequence: 2, record_digest: executionDigest(v.executions[1]) });
  });
  it('falls back to a retention checkpoint when history is absent', async () => {
    const client = new EvidenceStoreClient(buildTransport(mockFetch(
      { status: 404, body: { error: { code: 'resource_not_found', message: 'absent' } } },
      { status: 200, body: { entries: [{ payload: v.checkpoint }], next_after_sequence: null } },
    )));
    expect(await client.resourceHead(v.resource_id)).toEqual(v.checkpoint.resource_heads[v.resource_id]);
  });
  it('returns null when both history and checkpoint are absent', async () => {
    const client = new EvidenceStoreClient(buildTransport(mockFetch(
      { status: 404, body: { error: { code: 'resource_not_found', message: 'absent' } } },
      { status: 200, body: { entries: [], next_after_sequence: null } },
    )));
    expect(await client.resourceHead('new')).toBeNull();
  });
  it('propagates history errors other than an absent resource', async () => {
    const fetch = mockFetch({ status: 503, body: { error: { code: 'offline' } } });
    await expect(new EvidenceStoreClient(buildTransport(fetch)).resourceHead('x')).rejects.toMatchObject({ status: 503 });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('keeps the last successful state when a later action fails', async () => {
    const executionEvents = events.filter(e => e.entry.entry_kind === 'execution');
    const failed = { ...executionEvents[1], payload: { ...executionEvents[1].payload, resource_sequence: 3, outcome: 'failure', execution_parameters: { secret_version: 'bad' } } };
    const client = new EvidenceStoreClient(buildTransport(mockFetch({ status: 200, body: { entries: [...executionEvents, failed], next_after_sequence: null } })));
    const state = (await client.resourceStates()).get(v.resource_id);
    expect(state).toMatchObject({ resource_sequence: 3, last_outcome: 'failure', last_success_action: 'rotate', last_success_parameters: { secret_version: 'v2' } });
  });
});

it('refuses to continue a resource chain whose history failed verification', async () => {
  const client = new EvidenceStoreClient(buildTransport(mockFetch({ status: 200, body: { entries: events, verification: { verified: false } } })));
  await expect(client.resourceHead(v.resource_id)).rejects.toThrow('did not verify');
});
