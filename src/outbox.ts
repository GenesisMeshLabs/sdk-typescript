/**
 * The evidence outbox (v1.2.0): signed execution records the NA has not yet
 * admitted, kept in durable storage the caller supplies.
 *
 * With an outbox configured (`ClientOptions.outbox`), `governedAction`
 * writes its signed record here before submitting it, and removes it once
 * the NA admits it. A record whose submission failed stays pending, and
 * `EvidenceStoreClient.flushPending` submits it later, in order. A record the
 * NA refuses is kept as a dead letter with the refusal code; it is never
 * dropped. The outbox holds signed metadata only, never secret values, but it
 * must be durable and private.
 */

import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readdir, readFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { GenesisMeshError } from './errors.js';
import type { EvidenceSubmission, ExecutionEvidence } from './types.js';

/** Why the NA, or the transport, refused a submission. */
export interface SubmissionFailure {
  /** HTTP status; 0 when no response arrived (network error, timeout) or the SDK refused it. */
  status: number;
  code: string;
  message: string;
}

/** One signed record in the outbox. The Rust SDK reads and writes the same JSON. */
export interface OutboxEntry {
  /** The record's `evidence_id`. */
  id: string;
  /** The signed record, exactly as it will be submitted. */
  evidence: ExecutionEvidence;
  /** `pending`: to submit. `dead_letter`: refused; kept, never dropped. */
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
 * durable once its promise resolves, `list` must return entries in the order
 * they were added, and one store serves one process at a time.
 */
export interface EvidenceOutbox {
  /** Store a new entry; refuse an `id` already stored. */
  add(entry: OutboxEntry): Promise<void>;
  /** Replace the stored entry with the same `id`; nothing when it is gone. */
  update(entry: OutboxEntry): Promise<void>;
  /** Remove an entry; nothing when it is gone. */
  remove(id: string): Promise<void>;
  /** Every entry, in the order added. */
  list(): Promise<OutboxEntry[]>;
}

/**
 * What became of a record handed to the outbox: the NA's acknowledgement
 * when it was admitted, otherwise the outbox entry holding it (`pending` or
 * `dead_letter`).
 */
export interface Delivery {
  submission?: EvidenceSubmission;
  queued?: OutboxEntry;
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

/**
 * The NA's refusals that no retry of the same record can overcome. Every
 * other failure (network, timeout, `5xx`, `429`, an unknown or not yet
 * registered executor key, a chain gap behind a record not yet admitted, a
 * disabled store, a proxy's error page) is retried.
 */
export const PERMANENT_REFUSALS: ReadonlySet<string> = new Set([
  'invalid_evidence',
  'evidence_malformed',
  'evidence_invalid_signature',
  'evidence_decision_denied',
  'evidence_decision_mismatch',
  'evidence_outside_decision_window',
  'evidence_capability_mismatch',
  'evidence_chain_mismatch',
  'resource_chain_mismatch',
  'evidence_conflict',
  'evidence_secret_material',
]);

const FIRST_RETRY_MS = 5_000;
const MAX_RETRY_MS = 15 * 60_000;

/** The submission error as stored, and whether a later retry may succeed. */
export function classifySubmissionError(err: unknown): { failure: SubmissionFailure; transient: boolean } {
  if (err instanceof GenesisMeshError) {
    const failure = { status: err.status, code: err.code, message: err.message };
    const refused = PERMANENT_REFUSALS.has(err.code) && (err.status === 0 || (err.status >= 400 && err.status < 500));
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

/**
 * An outbox in memory. Not durable: everything in it is lost when the
 * process exits. For tests only.
 */
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
const TEMP_FILE = /^\.(\d{12}-[A-Za-z0-9-]{1,64}\.json)\.[0-9a-f]+\.tmp$/;
const FORMAT = 'gm.evidence.outbox.v1';

interface StoredEntry {
  file: string;
  sequence: number;
  entry: OutboxEntry;
}

/**
 * The default outbox: one JSON file per entry in a directory, written to a
 * temporary file, synced and renamed into place. File names keep the order
 * entries were added. The Rust SDK reads and writes the same format.
 *
 * One process uses a directory at a time: the directory is read once, then
 * kept in memory. A temporary file left by a crash is recovered (an entry
 * that was being added) or removed (an update that did not finish) on that
 * first read. A directory the outbox creates is `0700` and its files `0600`
 * on POSIX; on Windows, and for a directory that already exists, restrict
 * access to it yourself.
 */
export class FileOutbox implements EvidenceOutbox {
  private stored: Map<string, StoredEntry> | null = null;
  private loading: Promise<Map<string, StoredEntry>> | null = null;

  constructor(readonly directory: string) {}

  async add(entry: OutboxEntry): Promise<void> {
    const stored = await this.load();
    const stem = fileStem(entry.id);
    if (stored.has(stem)) throw new Error(`outbox entry ${entry.id} exists`);
    const sequence = Math.max(0, ...[...stored.values()].map(s => s.sequence)) + 1;
    const file = `${String(sequence).padStart(12, '0')}-${stem}.json`;
    // Reserve the position before the first await, so concurrent adds keep their order.
    const record = { file, sequence, entry: structuredClone(entry) };
    stored.set(stem, record);
    try {
      await this.write(file, entry);
    } catch (err) {
      stored.delete(stem);
      throw err;
    }
  }

  async update(entry: OutboxEntry): Promise<void> {
    const found = (await this.load()).get(fileStem(entry.id));
    if (!found) return;
    await this.write(found.file, entry);
    found.entry = structuredClone(entry);
  }

  async remove(id: string): Promise<void> {
    const stored = await this.load();
    const found = stored.get(fileStem(id));
    if (!found) return;
    await rm(join(this.directory, found.file), { force: true });
    await syncDirectory(this.directory);
    stored.delete(fileStem(id));
  }

  async list(): Promise<OutboxEntry[]> {
    return [...(await this.load()).values()]
      .sort((a, b) => a.sequence - b.sequence || (a.file < b.file ? -1 : 1))
      .map(s => structuredClone(s.entry));
  }

  private load(): Promise<Map<string, StoredEntry>> {
    if (this.stored) return Promise.resolve(this.stored);
    this.loading ??= this.read().then(
      stored => { this.stored = stored; return stored; },
      err => { this.loading = null; throw err; },
    );
    return this.loading;
  }

  private async read(): Promise<Map<string, StoredEntry>> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    let names = await readdir(this.directory);
    let recovered = false;
    for (const name of names) {
      const temp = TEMP_FILE.exec(name);
      if (!temp) continue;
      const path = join(this.directory, name);
      if (!names.includes(temp[1]!) && parseEntry(await readFile(path, 'utf-8').catch(() => '')) !== null) {
        await rename(path, join(this.directory, temp[1]!));
      } else {
        await rm(path, { force: true });
      }
      recovered = true;
    }
    if (recovered) {
      await syncDirectory(this.directory);
      names = await readdir(this.directory);
    }
    const stored = new Map<string, StoredEntry>();
    for (const file of names) {
      const match = ENTRY_FILE.exec(file);
      if (!match) continue;
      const entry = parseEntry(await readFile(join(this.directory, file), 'utf-8'));
      if (entry === null) throw new Error(`outbox file ${file} is unreadable or not ${FORMAT}`);
      stored.set(match[2]!, { file, sequence: Number(match[1]), entry });
    }
    return stored;
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

/** The entry in a file's text, or null when it is not a well-formed outbox file. */
function parseEntry(text: string): OutboxEntry | null {
  try {
    const body = JSON.parse(text) as { format?: unknown; entry?: OutboxEntry };
    const entry = body.entry;
    if (body.format !== FORMAT || !entry || typeof entry.id !== 'string' || typeof entry.evidence !== 'object') return null;
    return entry;
  } catch {
    return null;
  }
}

/** A file-name-safe stem for an entry id: the id itself when it is a plain identifier. */
function fileStem(id: string): string {
  return /^[A-Za-z0-9-]{1,64}$/.test(id) ? id : createHash('sha256').update(id).digest('hex').slice(0, 64);
}

/** Make a rename or removal durable on POSIX; Windows cannot open a directory to sync it. */
async function syncDirectory(directory: string): Promise<void> {
  if (process.platform === 'win32') return;
  const handle = await open(directory, 'r');
  try {
    await handle.sync();
  } catch (err) {
    // Some file systems cannot sync a directory.
    if (!['EINVAL', 'ENOTSUP'].includes((err as NodeJS.ErrnoException).code ?? '')) throw err;
  } finally {
    await handle.close();
  }
}
