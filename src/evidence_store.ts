import { checkMetadataOnly, SecretMaterialError } from './execution.js';
import type { HttpTransport } from './client.js';
import { executionDigest } from './canonical.js';
import { GenesisMeshError, NotFoundError } from './errors.js';
import {
  classifySubmissionError,
  outboxEntry,
  PREDECESSOR_DEAD_LETTERED,
  retryDelayMs,
  type Delivery,
  type EvidenceOutbox,
  type FlushOptions,
  type FlushResult,
  type OutboxEntry,
} from './outbox.js';
import { parseExportLines } from './verify.js';
import type {
  EntryKind,
  EvidenceEvent,
  EvidenceSearchResult,
  EvidenceStoreStatus,
  EvidenceStoreVerification,
  EvidenceSubmission,
  ExecutionEvidence,
  ExecutorKeyRecord,
  ExecutorKeyState,
  ResourceHead,
  ResourceHistory,
  RetentionCheckpoint,
  RetentionResult,
  VendorHistory,
} from './types.js';

export interface EvidenceSearchParams {
  vendor_id?: string;
  attestation_id?: string;
  capability?: string;
  resource_id?: string;
  /** "authorized" / "denied" for decisions; the executor's outcome for executions. */
  outcome?: string;
  entry_kind?: EntryKind;
  decision_id?: string;
  /** ISO timestamps bounding `recorded_at`. */
  since?: string;
  until?: string;
  /** Return entries with a store sequence greater than this (paging cursor). */
  after_sequence?: number;
  /** 1..1000, default 100. */
  limit?: number;
}

export interface EvidenceExportParams {
  /** Return entries with a store sequence greater than this. Default 0. */
  since_sequence?: number;
  /** 1..1000, default 1000. */
  limit?: number;
}

export interface RegisterExecutorKeyParams {
  key_id: string;
  /** Raw 32-byte Ed25519 public key, base64. */
  public_key: string;
  executor_sovereign_id: string;
}

/** Latest successful state of one resource, from its execution history. */
export interface ResourceState {
  resource_id: string;
  resource_sequence: number;
  record_digest: string;
  last_action: string | null;
  last_outcome: string;
  last_success_action: string | null;
  last_success_parameters: Record<string, unknown> | null;
  last_executed_at: string;
  last_decision_id: string;
}

const MAX_PAGE = 1000;

function resourcePath(resourceId: string): string {
  return resourceId.split('/').map(encodeURIComponent).join('/');
}

/** The records a signed record chains from: its predecessor under the decision and on the resource. */
function predecessors(evidence: ExecutionEvidence): string[] {
  return [evidence.prev_evidence_digest, evidence.prev_resource_digest].filter((d): d is string => !!d);
}

/** Most pending records an action submits before its own (older ones wait for `flushPending`). */
const MAX_INLINE_DRAIN = 100;

/** The NA evidence store (v0.59): controller submission, operator search, history, export. */
export class EvidenceStoreClient {
  private flushing: Promise<FlushResult> | null = null;
  /** Digests of outbox records by id: a record never changes once signed. */
  private readonly digests = new Map<string, string>();

  /**
   * @param outbox Durable storage for signed records not yet admitted
   *   (v1.2.0, `ClientOptions.outbox`). With one, `governedAction` keeps every
   *   record until the NA admits it.
   */
  constructor(private readonly http: HttpTransport, readonly outbox?: EvidenceOutbox) {}

  /**
   * Submit one signed ExecutionEvidence record. Authenticated by the executor
   * signature, not by operator headers. An identical resubmission returns
   * `status: "duplicate"`, so it is safe to retry.
   */
  async submit(evidence: ExecutionEvidence): Promise<EvidenceSubmission> {
    const reason = checkMetadataOnly(evidence.execution_parameters, evidence.outcome_detail);
    if (reason) throw new SecretMaterialError(reason);
    return this.http.publicPost<EvidenceSubmission>('/evidence/execution', { evidence }, true);
  }

  /**
   * Keep a signed record in the outbox and submit it (v1.2.0). Pending
   * records it chains from are submitted first, oldest first (up to 100;
   * older ones wait for `flushPending`). A failed submission does not throw:
   * a transient error leaves the record pending for `flushPending`, and a
   * refusal no retry can overcome keeps it as a dead letter with the NA's
   * code, as does a predecessor's refusal. Throws only when the outbox
   * cannot store the record. Passing a record already in the outbox submits
   * it again.
   */
  async enqueue(evidence: ExecutionEvidence): Promise<Delivery> {
    const outbox = this.requireOutbox();
    const entries = await outbox.list();
    let entry = entries.find(e => e.id === evidence.evidence_id);
    if (entry && this.digestOf(entry) !== executionDigest(evidence)) {
      throw new Error(`a different record with evidence_id ${evidence.evidence_id} is in the outbox`);
    }
    if (!entry) {
      entry = outboxEntry(evidence);
      await outbox.add(entry);
      entries.push(entry);
    }
    if (entry.state === 'dead_letter') return { queued: entry };
    const chain = this.chainOf(entries, entry);
    if (chain.dead) return { queued: await this.deadLetter(outbox, entries, entry, PREDECESSOR_DEAD_LETTERED) };
    if (!chain.pending.length) return this.attempt(outbox, entries, entry);
    if (this.flushing || chain.pending.length > MAX_INLINE_DRAIN) return { queued: entry };
    const only = new Set([...chain.pending.map(e => e.id), entry.id]);
    const run = this.flush(outbox, { ignoreBackoff: true }, only);
    this.flushing = run.then(r => r.result).finally(() => { this.flushing = null; });
    const { outcomes } = await run;
    return outcomes.get(entry.id) ?? { queued: entry };
  }

  /**
   * Submit the outbox's pending records in the order they were added
   * (v1.2.0). A record waits while one it chains from is pending, and is
   * dead-lettered (`evidence_predecessor_dead_lettered`) when that one was
   * refused. Records in backoff are skipped unless `ignoreBackoff`; a
   * transient error ends the run, leaving the rest for the next one. Run it
   * at startup and on a timer. Concurrent calls share one run.
   */
  async flushPending(options: FlushOptions = {}): Promise<FlushResult> {
    const outbox = this.requireOutbox();
    this.flushing ??= this.flush(outbox, options).then(r => r.result).finally(() => { this.flushing = null; });
    return this.flushing;
  }

  /**
   * The newest pending record in the outbox for a resource that can still be
   * admitted, or null (v1.2.0). `governedAction` chains from it, not from the
   * NA's head, while it waits.
   */
  async pendingHead(resourceId: string): Promise<ExecutionEvidence | null> {
    const entries = await this.requireOutbox().list();
    const dead = this.deadDigests(entries);
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = entries[i]!;
      if (e.state === 'pending' && e.evidence.resource_id === resourceId && !dead.has(this.digestOf(e))) return e.evidence;
    }
    return null;
  }

  private requireOutbox(): EvidenceOutbox {
    if (!this.outbox) throw new GenesisMeshError('no evidence outbox is configured (ClientOptions.outbox)', 'outbox_required', 0);
    return this.outbox;
  }

  private digestOf(entry: OutboxEntry): string {
    let digest = this.digests.get(entry.id);
    if (digest === undefined) {
      digest = executionDigest(entry.evidence);
      this.digests.set(entry.id, digest);
    }
    return digest;
  }

  /** Digests of dead letters and of every record that chains from one. */
  private deadDigests(entries: readonly OutboxEntry[]): Set<string> {
    const dead = new Set<string>();
    for (const e of entries) {
      if (e.state === 'dead_letter' || predecessors(e.evidence).some(d => dead.has(d))) dead.add(this.digestOf(e));
    }
    return dead;
  }

  /** Whether `entry` chains from a dead letter, and the pending records it chains from, oldest first. */
  private chainOf(entries: readonly OutboxEntry[], entry: OutboxEntry): { dead: boolean; pending: OutboxEntry[] } {
    const byDigest = new Map(entries.map(e => [this.digestOf(e), e]));
    const dead = this.deadDigests(entries);
    const pending: OutboxEntry[] = [];
    const seen = new Set<string>();
    const visit = (e: OutboxEntry) => {
      for (const d of predecessors(e.evidence)) {
        const before = byDigest.get(d);
        if (!before || seen.has(d)) continue;
        seen.add(d);
        visit(before);
        if (before.state === 'pending') pending.push(before);
      }
    };
    visit(entry);
    const order = new Map(entries.map((e, i) => [e.id, i]));
    pending.sort((a, b) => order.get(a.id)! - order.get(b.id)!);
    return { dead: predecessors(entry.evidence).some(d => dead.has(d)), pending };
  }

  /** Dead-letter `entry` and every pending record that chains from it. */
  private async deadLetter(
    outbox: EvidenceOutbox, entries: OutboxEntry[], entry: OutboxEntry, code: string, failure?: OutboxEntry['last_error'],
  ): Promise<OutboxEntry> {
    const refused: OutboxEntry = {
      ...entry, state: 'dead_letter', next_attempt_at: null,
      last_error: failure ?? { status: 0, code, message: 'a record this one chains from was refused' },
    };
    await this.keep(outbox, refused);
    const index = entries.findIndex(e => e.id === entry.id);
    entries[index] = refused;
    const dead = new Set([this.digestOf(entry)]);
    for (let i = index + 1; i < entries.length; i++) {
      const later = entries[i]!;
      if (later.state !== 'pending' || !predecessors(later.evidence).some(d => dead.has(d))) continue;
      dead.add(this.digestOf(later));
      entries[i] = {
        ...later, state: 'dead_letter', next_attempt_at: null,
        last_error: { status: 0, code: PREDECESSOR_DEAD_LETTERED, message: 'a record this one chains from was refused' },
      };
      await this.keep(outbox, entries[i]!);
    }
    return refused;
  }

  /** Store an entry's new state. Once the NA has answered, the answer stands even if this fails. */
  private async keep(outbox: EvidenceOutbox, entry: OutboxEntry): Promise<void> {
    try {
      await outbox.update(entry);
    } catch {
      // The entry keeps its previous state; the next flush settles it.
    }
  }

  private async attempt(outbox: EvidenceOutbox, entries: OutboxEntry[], entry: OutboxEntry): Promise<Delivery> {
    let submission: EvidenceSubmission;
    try {
      submission = await this.submit(entry.evidence);
    } catch (err) {
      const { failure, transient } = classifySubmissionError(err);
      const attempts = entry.attempts + 1;
      if (!transient) {
        return { queued: await this.deadLetter(outbox, entries, { ...entry, attempts }, failure.code, failure) };
      }
      const failed: OutboxEntry = {
        ...entry, attempts, last_error: failure, next_attempt_at: new Date(Date.now() + retryDelayMs(attempts)).toISOString(),
      };
      await this.keep(outbox, failed);
      entries[entries.findIndex(e => e.id === entry.id)] = failed;
      return { queued: failed };
    }
    try {
      await outbox.remove(entry.id);
    } catch {
      // The NA holds the record: the next flush resubmits it, gets a duplicate and removes it.
    }
    return { submission };
  }

  private async flush(
    outbox: EvidenceOutbox, options: FlushOptions, only?: ReadonlySet<string>,
  ): Promise<{ result: FlushResult; outcomes: Map<string, Delivery> }> {
    const result: FlushResult = { admitted: [], pending: [], dead_lettered: [] };
    const outcomes = new Map<string, Delivery>();
    const entries = await outbox.list();
    const waiting = new Set<string>();
    let stopped = false;
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]!;
      const digest = this.digestOf(entry);
      if (entry.state === 'dead_letter') continue;
      if (only && !only.has(entry.id)) {
        waiting.add(digest);
        continue;
      }
      const after = predecessors(entry.evidence);
      const next = entry.next_attempt_at ? Date.parse(entry.next_attempt_at) : NaN;
      const due = options.ignoreBackoff || !(next > Date.now());
      if (stopped || !due || after.some(d => waiting.has(d))) {
        waiting.add(digest);
        result.pending.push(entry);
        outcomes.set(entry.id, { queued: entry });
        continue;
      }
      const delivery = await this.attempt(outbox, entries, entry);
      outcomes.set(entry.id, delivery);
      if (delivery.submission) {
        result.admitted.push(entry);
      } else if (delivery.queued!.state === 'dead_letter') {
        // attempt() also dead-lettered the records chaining from it, later in `entries`.
        result.dead_lettered.push(delivery.queued!);
        for (let j = i + 1; j < entries.length; j++) {
          if (entries[j]!.state === 'dead_letter' && entries[j]!.last_error?.code === PREDECESSOR_DEAD_LETTERED
            && !result.dead_lettered.some(e => e.id === entries[j]!.id)) {
            result.dead_lettered.push(entries[j]!);
            outcomes.set(entries[j]!.id, { queued: entries[j]! });
          }
        }
      } else {
        waiting.add(digest);
        result.pending.push(delivery.queued!);
        stopped = true;
      }
    }
    return { result, outcomes };
  }

  /** Search stored entries (admin). Use `next_after_sequence` as the next `after_sequence`. */
  search(params: EvidenceSearchParams = {}): Promise<EvidenceSearchResult> {
    return this.http.adminGet<EvidenceSearchResult>('/admin/evidence', { ...params });
  }

  /** Every matching entry, following pages (admin). */
  async *iterate(params: Omit<EvidenceSearchParams, 'after_sequence'> = {}): AsyncGenerator<EvidenceEvent> {
    let after: number | null = 0;
    while (after !== null) {
      const page: EvidenceSearchResult = await this.search({ ...params, after_sequence: after });
      if (page.next_after_sequence !== null && (!Number.isSafeInteger(page.next_after_sequence) || page.next_after_sequence <= after)) {
        throw new Error('evidence search cursor did not advance');
      }
      yield* page.entries;
      after = page.next_after_sequence;
    }
  }

  /** Store mode, size, last sequence and retention checkpoint (admin). */
  status(): Promise<EvidenceStoreStatus> {
    return this.http.adminGet<EvidenceStoreStatus>('/admin/evidence/status');
  }

  /** Verify every stored entry, chain and signature on the NA (admin). */
  verify(): Promise<EvidenceStoreVerification> {
    return this.http.adminGet<EvidenceStoreVerification>('/admin/evidence/verify');
  }

  /** One resource's full history, decision to execution, verified by the NA (admin). */
  resourceHistory(resourceId: string): Promise<ResourceHistory> {
    return this.http.adminGet<ResourceHistory>(`/admin/evidence/resources/${resourcePath(resourceId)}`);
  }

  /** A vendor's decisions and the evidence under them, verified by the NA (admin). */
  vendorHistory(vendorId: string): Promise<VendorHistory> {
    return this.http.adminGet<VendorHistory>(`/admin/evidence/vendors/${encodeURIComponent(vendorId)}`);
  }

  /** One page of `gm.evidence.event` JSON Lines, unparsed (admin). */
  exportText(params: EvidenceExportParams = {}): Promise<string> {
    return this.http.adminGetText('/admin/evidence/export', { ...params });
  }

  /** One page of export events, parsed (admin). */
  async export(params: EvidenceExportParams = {}): Promise<EvidenceEvent[]> {
    return parseExportLines(await this.exportText(params));
  }

  /** Every event from `since_sequence` onward, following pages - an incremental SIEM pull (admin). */
  async *exportAll(sinceSequence = 0, pageSize = MAX_PAGE): AsyncGenerator<EvidenceEvent> {
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > MAX_PAGE
      || !Number.isSafeInteger(sinceSequence) || sinceSequence < 0) {
      throw new Error('export requires a nonnegative cursor and page size between 1 and 1000');
    }
    let since = sinceSequence;
    for (;;) {
      const events = await this.export({ since_sequence: since, limit: pageSize });
      if (events.length && events[events.length - 1].entry.store_sequence <= since) {
        throw new Error('evidence export cursor did not advance');
      }
      yield* events;
      if (events.length < pageSize) return;
      since = events[events.length - 1].entry.store_sequence;
    }
  }

  /** Registered executor keys, retired keys included (admin). */
  async listExecutorKeys(): Promise<ExecutorKeyRecord[]> {
    const body = await this.http.adminGet<{ executor_keys: ExecutorKeyRecord[] }>('/admin/evidence/executor-keys');
    return body.executor_keys;
  }

  /** Register a controller's executor signing key (admin, privileged). */
  registerExecutorKey(params: RegisterExecutorKeyParams): Promise<ExecutorKeyState> {
    return this.http.adminPost<ExecutorKeyState>('/admin/evidence/executor-keys', params);
  }

  /** Retire an executor key: it still verifies old records and can sign no new ones (admin, privileged). */
  retireExecutorKey(keyId: string): Promise<ExecutorKeyState> {
    return this.http.adminPost<ExecutorKeyState>(
      `/admin/evidence/executor-keys/${encodeURIComponent(keyId)}/retire`,
      {},
    );
  }

  /** Remove entries older than `olderThanDays` behind a signed checkpoint (admin, privileged). */
  applyRetention(olderThanDays: number): Promise<RetentionResult> {
    return this.http.adminPost<RetentionResult>('/admin/evidence/retention/apply', { older_than_days: olderThanDays });
  }

  /** The most recent retention checkpoint in the store, or null (admin). */
  async latestCheckpoint(): Promise<RetentionCheckpoint | null> {
    let latest: RetentionCheckpoint | null = null;
    for await (const event of this.iterate({ entry_kind: 'retention_checkpoint' })) {
      latest = event.payload as unknown as RetentionCheckpoint;
    }
    return latest;
  }

  /**
   * The head of a resource chain - what the next record must link to - or null
   * for a resource with no history (admin). One indexed lookup on the NA
   * (`/admin/evidence/resource-heads`, v0.63.1), which also covers chains whose
   * stored records retention removed. Against an older NA it falls back to
   * scanning the resource history.
   */
  async resourceHead(resourceId: string): Promise<ResourceHead | null> {
    try {
      const head = await this.http.adminGet<ResourceHead & { resource_id: string }>(
        `/admin/evidence/resource-heads/${resourcePath(resourceId)}`,
      );
      return { resource_sequence: head.resource_sequence, record_digest: head.record_digest };
    } catch (err) {
      if (!(err instanceof NotFoundError)) throw err;
      if (err.code === 'resource_not_found') return null;
      // Route missing: an NA older than v0.63.1.
    }
    return this.resourceHeadFromHistory(resourceId);
  }

  private async resourceHeadFromHistory(resourceId: string): Promise<ResourceHead | null> {
    let history: ResourceHistory;
    try {
      history = await this.resourceHistory(resourceId);
    } catch (err) {
      if (err instanceof NotFoundError && err.code === 'resource_not_found') {
        return (await this.latestCheckpoint())?.resource_heads[resourceId] ?? null;
      }
      throw err;
    }
    if (!history.verification?.verified) throw new Error('resource history did not verify');
    if (history.truncated) throw new Error('resource history is truncated; upgrade the NA to read the resource head');
    let head: ResourceHead | null = null;
    for (const event of history.entries) {
      if (event.entry.entry_kind !== 'execution') continue;
      const record = event.payload as unknown as ExecutionEvidence;
      if (record.resource_id !== resourceId || record.resource_sequence === undefined) continue;
      if (!head || record.resource_sequence > head.resource_sequence) {
        head = { resource_sequence: record.resource_sequence, record_digest: executionDigest(record) };
      }
    }
    return head;
  }

  /**
   * Latest state of every resource with stored execution evidence, for
   * reconciliation against a cloud inventory (admin).
   */
  async resourceStates(): Promise<Map<string, ResourceState>> {
    const states = new Map<string, ResourceState>();
    for await (const event of this.iterate({ entry_kind: 'execution' })) {
      const record = event.payload as unknown as ExecutionEvidence;
      if (record.resource_id === undefined || record.resource_sequence === undefined) continue;
      const previous = states.get(record.resource_id);
      if (previous && previous.resource_sequence >= record.resource_sequence) continue;
      const success = record.outcome === 'success';
      states.set(record.resource_id, {
        resource_id: record.resource_id,
        resource_sequence: record.resource_sequence,
        record_digest: executionDigest(record),
        last_action: record.resource_action ?? null,
        last_outcome: record.outcome,
        last_success_action: success ? record.resource_action ?? null : previous?.last_success_action ?? null,
        last_success_parameters: success ? record.execution_parameters : previous?.last_success_parameters ?? null,
        last_executed_at: record.executed_at,
        last_decision_id: record.decision_id,
      });
    }
    return states;
  }
}
