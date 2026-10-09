/**
 * The evidence outbox (v1.2.0): signed execution records the NA has not yet
 * admitted, kept in durable storage the caller supplies.
 *
 * `governedAction` writes its signed record here before submitting it, and
 * removes it once the NA admits it. A record whose submission failed stays
 * pending, and `EvidenceStoreClient.flushPending` submits it later, in order.
 * A record the NA refuses is kept as a dead letter with the refusal code; it
 * is never dropped. The outbox holds signed metadata only, never secret
 * values, but it must be durable and private.
 */

import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readdir, readFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { GenesisMeshError, isRetryableConflict } from './errors.js';
import type { ExecutionEvidence } from './types.js';

/** Why the NA, or the transport, refused a submission. */
export interface SubmissionFailure {
  /** HTTP status; 0 when no response arrived (network error, timeout). */
  status: number;
  code: string;
  message: string;
}

/** One signed record in the outbox. */
export interface OutboxEntry {
  /** The record's `evidence_id`. */
  id: string;
  /** The signed record, exactly as it will be submitted. */
  evidence: ExecutionEvidence;
  /** `pending`: to submit. `dead_letter`: refused by the NA; kept, never dropped. */
  state: 'pending' | 'dead_letter';
  /** Submissions attempted so far. */
  attempts: number;
  queued_at: string;
  /** Earliest time `flushPending` retries it; null when it has not failed. */
  next_attempt_at: string | null;
  last_error: SubmissionFailure | null;
}

/**
 * Durable storage for outbox entries. Implement it over a database or a
 * queue when the default file outbox does not fit. Every method must be
 * durable once its promise resolves, and `list` must return entries in the
 * order they were added.
 */
export interface EvidenceOutbox {
  /** Store a new entry. */
  add(entry: OutboxEntry): Promise<void>;
  /** Replace the stored entry with the same `id`; nothing when it is gone. */
  update(entry: OutboxEntry): Promise<void>;
  /** Remove an entry; nothing when it is gone. */
  remove(id: string): Promise<void>;
  /** Every entry, in the order added. */
  list(): Promise<OutboxEntry[]>;
}

/** A record still in the outbox after `governedAction` or `enqueue`. */
export interface QueuedSubmission {
  status: 'pending' | 'dead_letter';
  entry: OutboxEntry;
}

/** What one `flushPending` run did. */
export interface FlushResult {
  /** Entries the NA admitted (or already held), now removed from the outbox. */
  admitted: OutboxEntry[];
  /** Entries still pending, in order: not yet due, behind a pending record, or failed again. */
  pending: OutboxEntry[];
  /** Entries this run moved to the dead letters. */
  dead_lettered: OutboxEntry[];
}

export interface FlushOptions {
  /** Retry entries whose backoff has not expired (e.g. right after the NA is back). Default false. */
  ignoreBackoff?: boolean;
}

/** Local refusal code for a record whose predecessor in its chain is a dead letter. */
export const PREDECESSOR_DEAD_LETTERED = 'evidence_predecessor_dead_lettered';

const FIRST_RETRY_MS = 5_000;
const MAX_RETRY_MS = 15 * 60_000;

/** The submission error as stored, and whether a later retry may succeed. */
export function classifySubmissionError(err: unknown): { failure: SubmissionFailure; transient: boolean } {
  if (err instanceof GenesisMeshError) {
    const failure = { status: err.status, code: err.code, message: err.message };
    if (err.code === 'evidence_secret_material') return { failure, transient: false };
    // A 409 that only lost a race between NA instances changed nothing.
    const refused = err.status >= 400 && err.status < 500 && err.status !== 429 && !isRetryableConflict(err);
    return { failure, transient: !refused };
  }
  const message = err instanceof Error ? err.message : String(err);
  return { failure: { status: 0, code: 'network_error', message }, transient: true };
}

/** Delay before the next attempt after `attempts` failures: 5 s, doubling, at most 15 min. */
export function retryDelayMs(attempts: number): number {
  return Math.min(FIRST_RETRY_MS * 2 ** Math.max(0, attempts - 1), MAX_RETRY_MS);
}

/** A new pending entry for a signed record. */
export function outboxEntry(evidence: ExecutionEvidence, now = new Date()): OutboxEntry {
  return {
    id: evidence.evidence_id,
    evidence,
    state: 'pending',
    attempts: 0,
    queued_at: now.toISOString(),
    next_attempt_at: null,
    last_error: null,
  };
}

/** An outbox in memory. Not durable: for tests, or a process that keeps no evidence across restarts. */
export class MemoryOutbox implements EvidenceOutbox {
  private readonly entries = new Map<string, OutboxEntry>();

  async add(entry: OutboxEntry): Promise<void> {
    if (this.entries.has(entry.id)) throw new Error(`outbox entry ${entry.id} exists`);
    this.entries.set(entry.id, structuredClone(entry));
  }

  async update(entry: OutboxEntry): Promise<void> {
    if (this.entries.has(entry.id)) this.entries.set(entry.id, structuredClone(entry));
  }

  async remove(id: string): Promise<void> {
    this.entries.delete(id);
  }

  async list(): Promise<OutboxEntry[]> {
    return [...this.entries.values()].map(e => structuredClone(e));
  }
}

const ENTRY_FILE = /^(\d{12})-([A-Za-z0-9-]{1,64})\.json$/;
const FORMAT = 'gm.evidence.outbox.v1';

/**
 * The default outbox: one JSON file per entry in a private directory, written
 * to a temporary file, synced and renamed into place. File names keep the
 * order entries were added. The Rust SDK reads and writes the same format.
 */
export class FileOutbox implements EvidenceOutbox {
  constructor(readonly directory: string) {}

  async add(entry: OutboxEntry): Promise<void> {
    const files = await this.files();
    const name = fileStem(entry.id);
    if (files.some(f => f.name === name)) throw new Error(`outbox entry ${entry.id} exists`);
    const sequence = files.reduce((max, f) => Math.max(max, f.sequence), 0) + 1;
    await this.write(`${String(sequence).padStart(12, '0')}-${name}.json`, entry);
  }

  async update(entry: OutboxEntry): Promise<void> {
    const file = (await this.files()).find(f => f.name === fileStem(entry.id));
    if (file) await this.write(file.file, entry);
  }

  async remove(id: string): Promise<void> {
    const file = (await this.files()).find(f => f.name === fileStem(id));
    if (file) await rm(join(this.directory, file.file), { force: true });
  }

  async list(): Promise<OutboxEntry[]> {
    const entries: OutboxEntry[] = [];
    for (const { file } of await this.files()) {
      let body: { format?: string; entry?: OutboxEntry };
      try {
        body = JSON.parse(await readFile(join(this.directory, file), 'utf-8'));
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') continue; // removed meanwhile
        throw new Error(`outbox file ${file} is unreadable: ${(err as Error).message}`);
      }
      if (body.format !== FORMAT || !body.entry) throw new Error(`outbox file ${file} is not ${FORMAT}`);
      entries.push(body.entry);
    }
    return entries;
  }

  private async files(): Promise<{ file: string; sequence: number; name: string }[]> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const found = [];
    for (const file of await readdir(this.directory)) {
      const match = ENTRY_FILE.exec(file);
      if (match) found.push({ file, sequence: Number(match[1]), name: match[2]! });
    }
    return found.sort((a, b) => a.sequence - b.sequence || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  }

  private async write(file: string, entry: OutboxEntry): Promise<void> {
    const temporary = join(this.directory, `.${file}.${randomBytes(6).toString('hex')}.tmp`);
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(`${JSON.stringify({ format: FORMAT, entry }, null, 2)}\n`, 'utf-8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, join(this.directory, file));
    await syncDirectory(this.directory);
  }
}

/** A file-name-safe stem for an entry id: the id itself when it is a plain identifier. */
function fileStem(id: string): string {
  return /^[A-Za-z0-9-]{1,64}$/.test(id) ? id : createHash('sha256').update(id).digest('hex').slice(0, 64);
}

/** Make a rename durable on POSIX; Windows cannot open a directory and needs no sync. */
async function syncDirectory(directory: string): Promise<void> {
  let handle;
  try {
    handle = await open(directory, 'r');
    await handle.sync();
  } catch {
    // Not supported on this platform.
  } finally {
    await handle?.close();
  }
}
