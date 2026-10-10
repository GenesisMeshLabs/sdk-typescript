import { mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from '@jest/globals';
import {
  FileOutbox, MemoryOutbox, classifySubmissionError, retryDelayMs,
  BadRequestError, ConflictError, GenesisMeshError, NetworkError, NotFoundError, RateLimitError, SecretMaterialError,
  ValidationError,
} from '../src/index.js';
import type { EvidenceOutbox, ExecutionEvidence, OutboxEntry } from '../src/index.js';

function entry(id: string, extra: Partial<OutboxEntry> = {}): OutboxEntry {
  return {
    id,
    evidence: { evidence_id: id, outcome: 'success' } as unknown as ExecutionEvidence,
    state: 'pending', attempts: 0, queued_at: '2026-10-09T00:00:00.000Z', next_attempt_at: null, last_error: null,
    ...extra,
  };
}

const directories: string[] = [];
afterEach(async () => {
  for (const d of directories.splice(0)) await rm(d, { recursive: true, force: true });
});
async function directory(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), 'gm-outbox-'));
  directories.push(d);
  return join(d, 'outbox');
}

describe.each([
  ['FileOutbox', async (): Promise<EvidenceOutbox> => new FileOutbox(await directory())],
  ['MemoryOutbox', async (): Promise<EvidenceOutbox> => new MemoryOutbox()],
])('%s', (_, make) => {
  it('lists entries in the order added, and updates and removes them by id', async () => {
    const outbox = await make();
    for (const id of ['b', 'a', 'c']) await outbox.add(entry(id));
    await outbox.update(entry('a', { attempts: 2 }));
    await outbox.remove('b');
    await outbox.remove('missing');
    await outbox.update(entry('missing'));
    expect((await outbox.list()).map(e => [e.id, e.attempts])).toEqual([['a', 2], ['c', 0]]);
  });
  it('refuses a second entry with the same id', async () => {
    const outbox = await make();
    await outbox.add(entry('a'));
    await expect(outbox.add(entry('a'))).rejects.toThrow('exists');
  });
  it('returns copies', async () => {
    const outbox = await make();
    const added = entry('a');
    await outbox.add(added);
    added.attempts = 9;
    const [listed] = await outbox.list();
    listed!.attempts = 7;
    expect((await outbox.list())[0]!.attempts).toBe(0);
  });
});

describe('FileOutbox', () => {
  it('keeps entries across instances and processes', async () => {
    const dir = await directory();
    await new FileOutbox(dir).add(entry('a'));
    await new FileOutbox(dir).add(entry('b'));
    expect((await new FileOutbox(dir).list()).map(e => e.id)).toEqual(['a', 'b']);
  });
  it('keeps the order after earlier entries are removed', async () => {
    const outbox = new FileOutbox(await directory());
    await outbox.add(entry('a'));
    await outbox.add(entry('b'));
    await outbox.remove('a');
    await outbox.add(entry('a'));
    expect((await outbox.list()).map(e => e.id)).toEqual(['b', 'a']);
  });
  it('names files by sequence and id, hashing ids that are not plain identifiers', async () => {
    const dir = await directory();
    const outbox = new FileOutbox(dir);
    await outbox.add(entry('3f2a-uuid'));
    await outbox.add(entry('../escape'));
    const files = (await readdir(dir)).sort();
    expect(files[0]).toBe('000000000001-3f2a-uuid.json');
    expect(files[1]).toMatch(/^000000000002-[0-9a-f]{64}\.json$/);
    expect((await outbox.list()).map(e => e.id)).toEqual(['3f2a-uuid', '../escape']);
    await outbox.remove('../escape');
    expect(await readdir(dir)).toHaveLength(1);
  });
  it('writes a versioned format', async () => {
    const dir = await directory();
    await new FileOutbox(dir).add(entry('a'));
    const body = JSON.parse(await readFile(join(dir, '000000000001-a.json'), 'utf-8'));
    expect(body).toMatchObject({ format: 'gm.evidence.outbox.v1', entry: { id: 'a', state: 'pending' } });
  });
  it('recovers an add a crash interrupted and drops an unfinished update or partial write', async () => {
    const dir = await directory();
    await new FileOutbox(dir).add(entry('a'));
    const file = (e: OutboxEntry) => JSON.stringify({ format: 'gm.evidence.outbox.v1', entry: e });
    // An add synced but not renamed, an update not renamed, and a write cut short.
    await writeFile(join(dir, '.000000000002-b.json.0a1b2c.tmp'), file(entry('b')));
    await writeFile(join(dir, '.000000000001-a.json.3d4e5f.tmp'), file(entry('a', { attempts: 5 })));
    await writeFile(join(dir, '.000000000003-c.json.6a7b8c.tmp'), '{"form');
    const listed = await new FileOutbox(dir).list();
    expect(listed.map(e => [e.id, e.attempts])).toEqual([['a', 0], ['b', 0]]);
    expect((await readdir(dir)).sort()).toEqual(['000000000001-a.json', '000000000002-b.json']);
  });
  it('fails loudly on an unreadable entry', async () => {
    const dir = await directory();
    await new FileOutbox(dir).add(entry('a'));
    await writeFile(join(dir, '000000000002-b.json'), '{not json');
    await expect(new FileOutbox(dir).list()).rejects.toThrow('000000000002-b.json');
    await writeFile(join(dir, '000000000002-b.json'), '{"format":"other"}');
    await expect(new FileOutbox(dir).list()).rejects.toThrow('gm.evidence.outbox.v1');
  });
  it('reads entries the Rust SDK writes', async () => {
    const dir = await directory();
    await new FileOutbox(dir).list();
    // As `FileOutbox` in genesis-mesh-sdk (Rust) writes it: serde_json, two-space indent.
    const written = {
      format: 'gm.evidence.outbox.v1',
      entry: {
        id: 'e-1', evidence: { evidence_id: 'e-1' }, state: 'dead_letter', attempts: 3,
        queued_at: '2026-10-09T12:00:00.000Z', next_attempt_at: null,
        last_error: { status: 409, code: 'evidence_conflict', message: 'taken' },
      },
    };
    await writeFile(join(dir, '000000000001-e-1.json'), JSON.stringify(written, null, 2));
    expect(await new FileOutbox(dir).list()).toEqual([written.entry]);
  });
  (process.platform === 'win32' ? it.skip : it)('keeps the directory and entries private', async () => {
    const dir = await directory();
    await new FileOutbox(dir).add(entry('a'));
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
    expect((await stat(join(dir, '000000000001-a.json'))).mode & 0o777).toBe(0o600);
  });
});

describe('classifySubmissionError', () => {
  it.each([
    [new NetworkError('down'), true],
    [new RateLimitError(), true],
    [new GenesisMeshError('bad gateway', 'bad_gateway', 502), true],
    [new ConflictError('busy', 'retention_in_progress'), true],
    [new NotFoundError('disabled', 'evidence_store_disabled'), true],
    [new ValidationError('unknown key', 'evidence_unknown_executor'), true],
    [new ValidationError('gap', 'evidence_chain_gap'), true],
    [new GenesisMeshError('Request Timeout', 'unknown', 408), true],
    [new Error('socket hang up'), true],
    [new ConflictError('taken', 'evidence_conflict'), false],
    [new BadRequestError('malformed', 'evidence_malformed'), false],
    [new BadRequestError('not an object', 'invalid_evidence'), false],
    [new ValidationError('outside', 'evidence_outside_decision_window'), false],
    [new ValidationError('mismatch', 'resource_chain_mismatch'), false],
    [new SecretMaterialError('field'), false],
  ])('%s is transient: %s', (error, transient) => {
    expect(classifySubmissionError(error).transient).toBe(transient);
  });
  it('keeps the status, code and message', () => {
    expect(classifySubmissionError(new ConflictError('taken', 'evidence_conflict')).failure)
      .toEqual({ status: 409, code: 'evidence_conflict', message: 'taken' });
  });
});

describe('retryDelayMs', () => {
  it('doubles from 5 seconds up to 15 minutes', () => {
    expect([1, 2, 3, 8, 9, 50].map(retryDelayMs)).toEqual([5_000, 10_000, 20_000, 640_000, 900_000, 900_000]);
  });
});
