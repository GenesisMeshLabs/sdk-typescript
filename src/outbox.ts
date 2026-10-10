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
 *
 * The record outbox (v1.3.0, `ClientOptions.recordOutbox`) keeps signed
 * observations and break-glass records the same way, in a directory of its
 * own; `EvidenceStoreClient.flushRecords` submits them.
 */

import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readdir, readFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { GenesisMeshError } from './errors.js';
import type { BreakGlassRecord, ObservationRecord } from './out-of-band.js';
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

/** One signed observation or break-glass record in the record outbox (v1.3.0). The Rust SDK reads and writes the same JSON. */
export interface RecordOutboxEntry {
  /** The record's `observation_id` or `break_glass_id`. */
  id: string;
  kind: 'observation' | 'break_glass';
  /** The signed record, exactly as it will be submitted. */
  record: ObservationRecord | BreakGlassRecord;
  /** `pending`: to submit. `dead_letter`: refused; kept, never dropped. */
  state: 'pending' | 'dead_letter';
  attempts: number;
  queued_at: string;
  next_attempt_at: string | null;
  last_error: SubmissionFailure | null;
}

/**
 * Durable storage for outbox entries. Implement it over a database or a
 * queue when the default file outbox does not fit. Every method must be
 * durable once its promise resolves, `list` must return entries in the order
 * they were added, and one store serves one process at a time.
 */
export interface Outbox<E extends { id: string }> {
  /** Store a new entry; refuse an `id` already stored. */
  add(entry: E): Promise<void>;
  /** Replace the stored entry with the same `id`; nothing when it is gone. */
  update(entry: E): Promise<void>;
  /** Remove an entry; nothing when it is gone. */
  remove(id: string): Promise<void>;
  /** Every entry, in the order added. */
  list(): Promise<E[]>;
}

/** Storage for signed execution records (v1.2.0). */
export type EvidenceOutbox = Outbox<OutboxEntry>;

/** Storage for signed observations and break-glass records (v1.3.0). */
export type RecordOutbox = Outbox<RecordOutboxEntry>;

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

/**
 * The NA's refusals of an observation or break-glass record that no retry
 * can overcome (v1.3.0). An unknown key is retried: it may not be registered
 * yet.
 */
export const RECORD_PERMANENT_REFUSALS: ReadonlySet<string> = new Set([
  'invalid_observation',
  'observation_malformed',
  'observation_invalid_signature',
  'observation_out_of_scope',
  'observation_secret_material',
  'observation_conflict',
  'invalid_break_glass',
  'break_glass_malformed',
  'break_glass_invalid_signature',
  'break_glass_out_of_scope',
  'break_glass_secret_material',
  'break_glass_conflict',
]);

const FIRST_RETRY_MS = 5_000;
const MAX_RETRY_MS = 15 * 60_000;

/** The submission error as stored, and whether a later retry may succeed. */
export function classifySubmissionError(
  err: unknown,
  refusals: ReadonlySet<string> = PERMANENT_REFUSALS,
): { failure: SubmissionFailure; transient: boolean } {
  if (err instanceof GenesisMeshError) {
    const failure = { status: err.status, code: err.code, message: err.message };
    const refused = refusals.has(err.code) && (err.status === 0 || (err.status >= 400 && err.status < 500));
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

/** A new pending record outbox entry for a signed observation or break-glass record (v1.3.0). */
export function recordOutboxEntry(record: ObservationRecord | BreakGlassRecord, now = new Date()): RecordOutboxEntry {
  const observation = 'observation_id' in record;
  return {
    id: observation ? (record as ObservationRecord).observation_id : (record as BreakGlassRecord).break_glass_id,
    kind: observation ? 'observation' : 'break_glass',
    record,
    state: 'pending',
    attempts: 0,
    queued_at: now.toISOString(),
    next_attempt_at: null,
    last_error: null,
  };
}

/**
 * An outbox in memory. Not durable: everything in it is lost when the
 * process exits. For tests only. `new MemoryOutbox<RecordOutboxEntry>()`
 * holds records (v1.3.0).
 */
export class MemoryOutbox<E extends { id: string } = OutboxEntry> implements Outbox<E> {
  private readonly entries = new Map<string, E>();

  async add(entry: E): Promise<void> {
    if (this.entries.has(entry.id)) throw new Error(`outbox entry ${entry.id} exists`);
    this.entries.set(entry.id, structuredClone(entry));
  }

  async update(entry: E): Promise<void> {
    if (this.entries.has(entry.id)) this.entries.set(entry.id, structuredClone(entry));
  }

  async remove(id: string): Promise<void> {
    this.entries.delete(id);
  }

  async list(): Promise<E[]> {
    return [...this.entries.values()].map(e => structuredClone(e));
  }
}

const ENTRY_FILE = /^(\d{12})-([A-Za-z0-9-]{1,64})\.json$/;
const TEMP_FILE = /^\.(\d{12}-[A-Za-z0-9-]{1,64}\.json)\.[0-9a-f]+\.tmp$/;
const FORMAT = 'gm.evidence.outbox.v1';
const RECORD_FORMAT = 'gm.evidence.record-outbox.v1';

interface StoredEntry<E> {
  file: string;
  sequence: number;
  entry: E;
}

/** One JSON file per entry in a directory; see `FileOutbox`. */
class JsonFileOutbox<E extends { id: string }> implements Outbox<E> {
  private stored: Map<string, StoredEntry<E>> | null = null;
  private loading: Promise<Map<string, StoredEntry<E>>> | null = null;

  protected constructor(
    readonly directory: string,
    private readonly format: string,
    private readonly isEntry: (entry: Record<string, unknown>) => boolean,
  ) {}

  async add(entry: E): Promise<void> {
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

  async update(entry: E): Promise<void> {
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

  async list(): Promise<E[]> {
    return [...(await this.load()).values()]
      .sort((a, b) => a.sequence - b.sequence || (a.file < b.file ? -1 : 1))
      .map(s => structuredClone(s.entry));
  }

  private load(): Promise<Map<string, StoredEntry<E>>> {
    if (this.stored) return Promise.resolve(this.stored);
    this.loading ??= this.read().then(
      stored => { this.stored = stored; return stored; },
      err => { this.loading = null; throw err; },
    );
    return this.loading;
  }

  private async read(): Promise<Map<string, StoredEntry<E>>> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    let names = await readdir(this.directory);
    let recovered = false;
    for (const name of names) {
      const temp = TEMP_FILE.exec(name);
      if (!temp) continue;
      const path = join(this.directory, name);
      if (!names.includes(temp[1]!) && this.parse(await readFile(path, 'utf-8').catch(() => '')) !== null) {
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
    const stored = new Map<string, StoredEntry<E>>();
    for (const file of names) {
      const match = ENTRY_FILE.exec(file);
      if (!match) continue;
      const entry = this.parse(await readFile(join(this.directory, file), 'utf-8'));
      if (entry === null) throw new Error(`outbox file ${file} is unreadable or not ${this.format}`);
      stored.set(match[2]!, { file, sequence: Number(match[1]), entry });
    }
    return stored;
  }

  private async write(file: string, entry: E): Promise<void> {
    const temporary = join(this.directory, `.${file}.${randomBytes(6).toString('hex')}.tmp`);
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(`${JSON.stringify({ format: this.format, entry }, null, 2)}\n`, 'utf-8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, join(this.directory, file));
    await syncDirectory(this.directory);
  }

  /** The entry in a file's text, or null when it is not a well-formed file of this outbox. */
  private parse(text: string): E | null {
    try {
      const body = JSON.parse(text) as { format?: unknown; entry?: Record<string, unknown> };
      const entry = body.entry;
      if (body.format !== this.format || !entry || typeof entry['id'] !== 'string' || !this.isEntry(entry)) return null;
      return entry as unknown as E;
    } catch {
      return null;
    }
  }
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
export class FileOutbox extends JsonFileOutbox<OutboxEntry> {
  constructor(directory: string) {
    super(directory, FORMAT, entry => typeof entry['evidence'] === 'object' && entry['evidence'] !== null);
  }
}

/**
 * The default record outbox (v1.3.0): signed observations and break-glass
 * records, stored as `FileOutbox` stores execution records, in a directory
 * of its own (`gm.evidence.record-outbox.v1`).
 */
export class FileRecordOutbox extends JsonFileOutbox<RecordOutboxEntry> {
  constructor(directory: string) {
    super(directory, RECORD_FORMAT, entry => (entry['kind'] === 'observation' || entry['kind'] === 'break_glass')
      && typeof entry['record'] === 'object' && entry['record'] !== null);
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
