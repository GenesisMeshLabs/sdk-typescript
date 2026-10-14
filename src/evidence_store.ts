import type { StoreAnchor } from './anchors.js';
import type { ArchiveRecord, AuditPackManifest, AuditPackResponse } from './audit-pack.js';
import { checkMetadataOnly, SecretMaterialError } from './execution.js';
import type { HttpTransport } from './client.js';
import { executionDigest } from './canonical.js';
import { GenesisMeshError, NotFoundError } from './errors.js';
import type { GrantExecutionEvidence } from './grants.js';
import {
  outOfBandDigest,
  type BreakGlassRecord,
  type GovernedBy,
  type JudgementRecord,
  type ObservationRecord,
  type Verdict,
} from './out-of-band.js';
import {
  classifySubmissionError,
  nextAttemptAt,
  outboxEntry,
  PREDECESSOR_DEAD_LETTERED,
  RECORD_PERMANENT_REFUSALS,
  recordOutboxEntry,
  type Delivery,
  type EvidenceOutbox,
  type OutboxRecord,
  type FlushOptions,
  type FlushResult,
  type OutboxEntry,
  type RecordOutbox,
  type RecordOutboxEntry,
  type SubmissionFailure,
} from './outbox.js';
import type {
  RemediationQueueFilter, RemediationRecord, RemediationState, RemediationStatus, RemediationSubjectKind, ReviewRecord,
  ReviewSummary,
  ReviewVerdict, StoredRecord,
} from './remediation.js';
import { timestampOrder } from './validation.js';
import { parseExportLines } from './verify.js';
import type {
  EntryKind,
  EvidenceEvent,
  EvidenceSearchResult,
  EvidenceStoreStatus,
  EvidenceStoreVerification,
  EvidenceStoreEntry,
  EvidenceSubmission,
  ExecutionEvidence,
  ExecutorKeyRecord,
  ExecutorKeyState,
  ResourceAction,
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
  /** v1.3.0: `executor` (default) or `observer`, which signs observations only. */
  role?: 'executor' | 'observer';
  /** v1.3.0: the key signs only for resources whose ID starts with this; null or absent for any resource. */
  resource_prefix?: string | null;
}

// ── Changes outside the controlled path (v1.3.0) ─────────────────────────────

/** The NA's answer to an observation, break-glass record, (v1.4.0) remediation record or (v1.6.0) grant use. */
export interface RecordSubmission {
  /** `quarantined`: authentic but outside its time bounds; kept, not judged. */
  status: 'recorded' | 'duplicate' | 'quarantined';
  entry: EvidenceStoreEntry;
  entry_digest: string;
  payload: Record<string, unknown>;
  /** The judgement made at admission (`NA_JUDGE_ON_ADMISSION`); null when judging failed and waits for the judge route. */
  judgement?: JudgementSubmission | null;
  /** v1.4.0, for a remediation record just recorded: the subject's remediation state, now `remediated`. */
  remediation?: RemediationStatus;
  /**
   * v1.6.0, for a grant use just recorded: the position the NA assigned it in
   * its resource's chain (null for a use without a resource).
   */
  resource_sequence?: number | null;
}

/** One observation's result in a batch, at its index in the request. */
export interface ObservationBatchResult {
  index: number;
  status: 'recorded' | 'duplicate' | 'quarantined' | 'refused';
  entry?: EvidenceStoreEntry;
  entry_digest?: string;
  payload?: Record<string, unknown>;
  judgement?: JudgementSubmission | null;
  /** Present when refused. */
  error?: { code: string; message: string };
}

/** A judgement: made now (`judged`), or the one made before (`existing`). */
export interface JudgementSubmission {
  status: 'judged' | 'existing';
  entry: EvidenceStoreEntry;
  entry_digest: string;
  payload: JudgementRecord;
  /**
   * v1.4.0, with the NA's remediation records on: the remediation state the
   * judgement armed (`remediation_due`) or the review it opened
   * (`review_pending: true`); absent when it led to neither, or when the
   * change is already under review as a decision or a break-glass record.
   */
  remediation?: RemediationStatus;
}

/** How a change to a resource stands: see *Changes Outside the Controlled Path* in the NA runbooks. */
export type ChangeState =
  | 'recorded'
  | 'matched'
  | 'judged_allowed'
  | 'judged_denied'
  | 'indeterminate'
  | 'observed'
  | 'quarantined'
  // v1.4.0: the remediation state of a change a remediation or review concerns.
  | RemediationState;

/** One change to a resource, oldest first. */
export interface ResourceChange {
  store_sequence: number;
  /** v1.6.0: `grant_execution`, a change made under a grant (`governed_by: grant`). */
  kind: 'execution' | 'observation' | 'break_glass' | 'quarantine' | 'grant_execution';
  recorded_at: string;
  record_id: string | null;
  action: ResourceAction | null;
  /** When the change happened (for a window, its end); when it was quarantined, for a quarantine entry. */
  at: string | null;
  governed_by: GovernedBy | null;
  state: ChangeState;
  verdict?: Verdict;
  flagged_for_review?: boolean;
  decision_id?: string | null;
  /** The observation that matched this execution or break-glass record. */
  observed_by?: string | null;
  possible_match_evidence_id?: string;
  justification?: string;
  record_kind?: string;
  rejection_code?: string;
  /** v1.4.0: the remediation state, for a change a remediation or review concerns (its `state` too). */
  remediation?: RemediationStatus;
  /** v1.6.0, for a grant use: its grant and its place in the grant's use chain. */
  grant_id?: string;
  use_sequence?: number;
}

export interface ResourceChanges {
  resource_id: string;
  /** True when the resource has more changes than this page holds. */
  truncated: boolean;
  changes: ResourceChange[];
  /** v1.4.0: the next page's `after_sequence`; null on the last page (absent from an older NA). */
  next_after_sequence?: number | null;
}

/** v1.4.0: one page of a resource's changes. */
export interface ResourceChangesParams {
  /** 1..10000, default 1000. */
  limit?: number;
  /** The previous page's `next_after_sequence`. */
  after_sequence?: number;
}

/** An operator key's holder, as the store records it. */
export interface OperatorKeyHolder {
  key_id: string;
  holder: string;
  public_key: string | null;
  operator_tier: string | null;
  since: string;
  approved_by: string | null;
  registry_record_id: string;
}

export interface HolderChange {
  proposal_id: string;
  key_id: string;
  holder: string;
  proposed_by?: string;
  approved: boolean;
  approved_by?: string;
  registry_record_id?: string;
}

/** What became of a record handed to the record outbox. */
export interface RecordDelivery {
  submission?: RecordSubmission;
  queued?: RecordOutboxEntry;
}

/** What one `flushRecords` run did. */
export interface RecordFlushResult {
  /** Entries the NA admitted (or already held), now removed from the record outbox. */
  admitted: RecordOutboxEntry[];
  /** Of those, the ones the NA kept as quarantine entries (outside their time bounds). */
  quarantined: RecordOutboxEntry[];
  pending: RecordOutboxEntry[];
  dead_lettered: RecordOutboxEntry[];
}

// ── Remediation, reviews and notification (v1.4.0) ──────────────────────────

/** One page of the due queue. */
export interface RemediationQueue {
  /** The filter asked for; null for the default (due, overdue and waived changes, and those with a pending review). */
  state: RemediationQueueFilter | null;
  count: number;
  /** Oldest first. */
  remediations: RemediationStatus[];
  /** The next page's `after`; null on the last page. */
  next_after: string | null;
}

export interface RemediationQueueParams {
  /**
   * A stored state (`STORED_STATES`), or `review_pending` for every change
   * with a pending review whatever its state. Default: the due, overdue and
   * waived changes, and those with a pending review.
   */
  state?: RemediationQueueFilter;
  /** 1..500, default 100. */
  limit?: number;
  /** The previous page's `next_after`. */
  after?: string;
}

/** One subject's remediation state, with its newest 100 reviews and its newest 100 stored remediation and review entries. */
export interface RemediationDetail extends RemediationStatus {
  reviews: ReviewSummary[];
  /** True when the subject has more reviews than `reviews` holds. */
  reviews_truncated: boolean;
  records: StoredRecord[];
  /** True when the subject has more stored records than `records` holds. */
  records_truncated: boolean;
}

export interface ReviewRequest {
  subject_kind: RemediationSubjectKind;
  /** The judgement's (or decision's) ID. */
  subject_id: string;
  /** Why the change should be reviewed: 1 to 1024 characters, embedded in the review as signed. */
  justification: string;
}

/** A requested review: its ID and the subject's state (`review_pending: true`). */
export interface ReviewRequested extends RemediationStatus {
  review_id: string;
}

/** A review, pending or decided; `record` once decided (the stored `ReviewRecord` entry). */
export interface ReviewDetail extends ReviewSummary {
  record?: StoredRecord<ReviewRecord>;
}

export interface ReviewDecision {
  verdict: ReviewVerdict;
  /** For `waive_until` only: when the waiver ends (after now; within the NA's longest waiver). */
  waive_until?: Date | string;
  /** 1 to 1024 characters. */
  note?: string;
}

/** A decided review: the stored `ReviewRecord` entry (in place of a pending review) and the subject's state. */
export interface ReviewDecided extends Omit<RemediationStatus, 'review'> {
  review: StoredRecord<ReviewRecord>;
}

/** Most observations one batch request carries. */
const OBSERVATION_BATCH = 100;

/** Latest state of one resource, from its execution history and (1.3.1) its break-glass records. */
/** One page of `GET /admin/evidence/anchors` (v1.2.0). */
export interface AnchorPage {
  count: number;
  /** The next page's `after_anchor`; null on the last page. */
  next_after_anchor: number | null;
  anchors: StoreAnchor[];
}

/** `POST /admin/evidence/anchors`: the store's head signed now, or the latest anchor while it has not moved. */
export interface AnchorResult {
  anchor: StoreAnchor | null;
  status: 'anchored' | 'unchanged';
}

/**
 * The range of an audit pack (v1.5.0), every bound optional: the range widens
 * to the anchors around it, and ends at the last anchor that fits.
 */
export interface AuditPackParams {
  from_sequence?: number;
  /** ISO 8601 with an offset: the range starts at the first entry recorded at or after it. */
  since?: string;
  until_sequence?: number;
  /** ISO 8601 with an offset: the range ends at the last anchor signed at or before it. */
  until?: string;
}

/** `GET /admin/evidence/archives` (v1.5.0). */
export interface ArchiveList {
  archives: ArchiveRecord[];
  /** How far an unbroken run of archive records covers the store. */
  archived_through_sequence: number;
  /** Whether retention removes only what archives cover (`NA_RETENTION_REQUIRE_ARCHIVE`). */
  require_archive: boolean;
}

/** `POST /admin/evidence/archives` (v1.5.0): `recorded` (201), or `duplicate` (200) for the same manifest. */
export interface ArchiveResult {
  status: 'recorded' | 'duplicate';
  archive: ArchiveRecord;
  archived_through_sequence: number;
}

export interface ResourceState {
  resource_id: string;
  /** The newest execution record's position on the resource chain; 0 when it has only break-glass records. */
  resource_sequence: number;
  /** The newest execution record's digest; empty when it has only break-glass records. */
  record_digest: string;
  last_action: string | null;
  last_outcome: string;
  last_success_action: string | null;
  last_success_parameters: Record<string, unknown> | null;
  last_executed_at: string;
  /** The newest execution record's decision; empty when it has only break-glass records. */
  last_decision_id: string;
  /** The break-glass record of the latest change, when it was one (1.3.1). */
  last_break_glass_id?: string;
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

/** Refusals of a record whose predecessor is not stored: final once that predecessor is a dead letter (1.3.1). */
const CHAIN_GAPS: ReadonlySet<string> = new Set(['evidence_chain_gap', 'resource_chain_gap']);

/**
 * The flush in progress of one outbox, and what it tries: every due entry
 * (`full`, or only an action's own drain), and entries in backoff too.
 */
class FlushSlot<R> {
  private run: { result: Promise<R>; full: boolean; ignoreBackoff: boolean } | null = null;

  get busy(): boolean {
    return this.run !== null;
  }

  /** Make `result` the flush in progress until it settles. */
  track(result: Promise<R>, full: boolean, ignoreBackoff: boolean): Promise<R> {
    const run = { result, full, ignoreBackoff };
    this.run = run;
    const done = () => { if (this.run === run) this.run = null; };
    result.then(done, done);
    return result;
  }

  /**
   * Join the flush in progress when it tries everything `options` asks for;
   * otherwise let it finish and start one that does (1.3.1: a caller never
   * gets the result of an action's partial drain, nor of a run that kept the
   * backoff it asked to ignore).
   */
  async join(options: FlushOptions, start: () => Promise<R>): Promise<R> {
    for (let run = this.run; run; run = this.run) {
      if (run.full && (run.ignoreBackoff || !options.ignoreBackoff)) return run.result;
      await run.result.catch(() => undefined);
    }
    return this.track(start(), true, !!options.ignoreBackoff);
  }
}

/** The NA evidence store (v0.59): controller submission, operator search, history, export. */
export class EvidenceStoreClient {
  private readonly flushing = new FlushSlot<FlushResult>();
  private readonly flushingRecords = new FlushSlot<RecordFlushResult>();
  /** Most observations a batch carries: halved each time the NA throttles one (`429`, 1.3.1). */
  private observationBatch = OBSERVATION_BATCH;
  /** Until when the NA asked for no more records (`Retry-After`, 1.3.1): `flushRecords` waits unless `ignoreBackoff`. */
  private recordsPausedUntil = 0;
  /** Digests of outbox records by id: a record never changes once signed. */
  private readonly digests = new Map<string, string>();
  /** Records `enqueue` is submitting right now: a concurrent flush leaves them to it. */
  private readonly inFlight = new Set<string>();

  /**
   * @param outbox Durable storage for signed records not yet admitted
   *   (v1.2.0, `ClientOptions.outbox`). With one, `governedAction` keeps every
   *   record until the NA admits it.
   * @param recordOutbox Durable storage for signed observations and
   *   break-glass records not yet admitted (v1.3.0, `ClientOptions.recordOutbox`).
   */
  constructor(
    private readonly http: HttpTransport,
    readonly outbox?: EvidenceOutbox,
    readonly recordOutbox?: RecordOutbox,
  ) {}

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
   * code. A record whose predecessor was refused is still sent (1.3.1), so
   * the NA can quarantine it when it refuses it for good too; refused only
   * for the gap its predecessor left, it is a dead letter
   * (`evidence_predecessor_dead_lettered`). Throws only when the outbox
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
    const pending = this.pendingBefore(entries, entry);
    if (!pending.length) {
      this.inFlight.add(entry.id);
      try {
        return await this.attempt(outbox, entries, entry);
      } finally {
        this.inFlight.delete(entry.id);
      }
    }
    if (this.flushing.busy || pending.length > MAX_INLINE_DRAIN) return { queued: entry };
    const only = new Set([...pending.map(e => e.id), entry.id]);
    const run = this.flush(outbox, { ignoreBackoff: true }, only);
    this.flushing.track(run.then(r => r.result), false, true);
    const { outcomes } = await run;
    return outcomes.get(entry.id) ?? { queued: entry };
  }

  /**
   * Submit the outbox's pending records in the order they were added
   * (v1.2.0). A record waits while one it chains from is pending. A record
   * whose predecessor was refused is sent too (1.3.1), and is dead-lettered
   * (`evidence_predecessor_dead_lettered`) when the NA refuses it for that
   * gap. Records in backoff are skipped unless `ignoreBackoff`; a transient
   * error ends the run, leaving the rest for the next one. Run it at startup
   * and on a timer. A call joins the run in progress when that run tries
   * everything it asks for, and otherwise starts one once it ends.
   */
  async flushPending(options: FlushOptions = {}): Promise<FlushResult> {
    const outbox = this.requireOutbox();
    return this.flushing.join(options, () => this.flush(outbox, options).then(r => r.result));
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

  /** The pending records `entry` chains from, oldest first. */
  private pendingBefore(entries: readonly OutboxEntry[], entry: OutboxEntry): OutboxEntry[] {
    const byDigest = new Map(entries.map(e => [this.digestOf(e), e]));
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
    return pending;
  }

  /**
   * Dead-letter `entry`. Records that chain from it stay pending (1.3.1):
   * each is sent in turn, so the NA quarantines one it refuses for good, and
   * one it refuses only for the gap is dead-lettered then.
   */
  private async deadLetter(
    outbox: EvidenceOutbox, entries: OutboxEntry[], entry: OutboxEntry, failure: SubmissionFailure,
  ): Promise<OutboxEntry> {
    const refused: OutboxEntry = { ...entry, state: 'dead_letter', next_attempt_at: null, last_error: failure };
    await this.keep(outbox, refused);
    entries[entries.findIndex(e => e.id === entry.id)] = refused;
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
      // A gap behind a record not admitted yet is retried; behind a dead letter it never closes.
      if (CHAIN_GAPS.has(failure.code) && predecessors(entry.evidence).some(d => this.deadDigests(entries).has(d))) {
        return {
          queued: await this.deadLetter(outbox, entries, { ...entry, attempts }, {
            status: failure.status, code: PREDECESSOR_DEAD_LETTERED,
            message: `a record this one chains from was refused; the NA answered ${failure.code}: ${failure.message}`,
          }),
        };
      }
      if (!transient) return { queued: await this.deadLetter(outbox, entries, { ...entry, attempts }, failure) };
      const failed: OutboxEntry = { ...entry, attempts, last_error: failure, next_attempt_at: nextAttemptAt(attempts, err) };
      await this.keep(outbox, failed);
      entries[entries.findIndex(e => e.id === entry.id)] = failed;
      return { queued: failed };
    }
    try {
      await outbox.remove(entry.id);
      this.digests.delete(entry.id);
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
      if (this.inFlight.has(entry.id)) {
        // `enqueue` is submitting it: still pending as far as this run knows.
        waiting.add(digest);
        result.pending.push(entry);
        outcomes.set(entry.id, { queued: entry });
        continue;
      }
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
        result.dead_lettered.push(delivery.queued!);
      } else {
        waiting.add(digest);
        result.pending.push(delivery.queued!);
        stopped = true;
      }
    }
    return { result, outcomes };
  }

  // ── Changes outside the controlled path (v1.3.0) ───────────────────────────

  /**
   * Submit one signed observation. Authenticated by the observer key's
   * signature, not by operator headers. Idempotent per source event: a
   * resubmission returns `status: "duplicate"`.
   */
  submitObservation(observation: ObservationRecord): Promise<RecordSubmission> {
    return this.http.publicPost<RecordSubmission>('/evidence/observations', { observation }, true);
  }

  /** Submit up to 100 observations; the NA admits them in order of their change times. One result each, by index. */
  async submitObservations(observations: readonly ObservationRecord[]): Promise<ObservationBatchResult[]> {
    const body = await this.http.publicPost<{ results: ObservationBatchResult[] }>(
      '/evidence/observations/batch', { observations }, true,
    );
    return body.results;
  }

  /** Submit one signed break-glass record (authenticated by the executor key's signature). */
  submitBreakGlass(record: BreakGlassRecord): Promise<RecordSubmission> {
    return this.http.publicPost<RecordSubmission>('/evidence/break-glass', { record }, true);
  }

  /**
   * Submit one signed remediation record (v1.4.0). Authenticated by the
   * executor key's signature: `201` `recorded` with the subject's state, or
   * `200` `duplicate` for the same record again. A refusal no retry can
   * overcome is in `RECORD_PERMANENT_REFUSALS`; the NA keeps an authentic
   * record refused for good as a quarantine entry (`details.quarantine_id`).
   */
  submitRemediation(record: RemediationRecord): Promise<RecordSubmission> {
    return this.http.publicPost<RecordSubmission>('/evidence/remediations', { record }, true);
  }

  /**
   * One page of the due queue (admin, read tier; v1.4.0): the remediation
   * states in `state` (default: the open ones), oldest first. Follow
   * `next_after`, or use `allRemediations`.
   */
  listRemediations(params: RemediationQueueParams = {}): Promise<RemediationQueue> {
    return this.http.adminGet<RemediationQueue>('/admin/evidence/remediations', { ...params });
  }

  /** Every remediation state in `state` (default: the open ones), following pages (admin, read tier; v1.4.0). */
  async *allRemediations(params: Omit<RemediationQueueParams, 'after'> = {}): AsyncGenerator<RemediationStatus> {
    let after: string | undefined;
    for (;;) {
      const page: RemediationQueue = await this.listRemediations({ ...params, ...(after !== undefined ? { after } : {}) });
      yield* page.remediations;
      if (page.next_after === null || page.next_after === undefined) return;
      if (page.next_after === after) throw new Error('remediation queue cursor did not advance');
      after = page.next_after;
    }
  }

  /** One judgement's or decision's remediation state, its reviews and its stored records (admin, read tier; v1.4.0). */
  remediation(subjectId: string): Promise<RemediationDetail> {
    return this.http.adminGet<RemediationDetail>(`/admin/evidence/remediations/${encodeURIComponent(subjectId)}`);
  }

  /**
   * Record that the controller told the actor (admin; v1.4.0): an audit event
   * and, on the first notice, `notified_at`. Send the notice before
   * `remediation_due_at`. `channel`: 1 to 64 characters, such as `email`.
   */
  markNotified(subjectId: string, channel?: string): Promise<RemediationStatus> {
    return this.http.adminPost<RemediationStatus>(
      `/admin/evidence/remediations/${encodeURIComponent(subjectId)}/notified`,
      channel === undefined ? {} : { channel },
    );
  }

  /**
   * Ask a second holder to review a judged change or a decision (admin,
   * standard tier; v1.4.0). The NA keeps this signed request and embeds it in
   * the review, so the subject and justification verify offline. The
   * operator key needs a named holder in the store (`review_needs_named_holder`).
   */
  requestReview(request: ReviewRequest): Promise<ReviewRequested> {
    const body = { subject_kind: request.subject_kind, subject_id: request.subject_id, justification: request.justification };
    return this.http.adminPost<ReviewRequested>('/admin/evidence/reviews', body);
  }

  /** A review: pending, or decided with its stored record (admin, read tier; v1.4.0). */
  review(reviewId: string): Promise<ReviewDetail> {
    return this.http.adminGet<ReviewDetail>(`/admin/evidence/reviews/${encodeURIComponent(reviewId)}`);
  }

  /**
   * Decide a review (admin, privileged tier; v1.4.0): `uphold`, `deny` or
   * `waive_until` a time. Use a client whose operator key is privileged and
   * of another holder than the requester's and the observed actor's. The
   * request is signed as sent, without a query, and the NA embeds it in the
   * `ReviewRecord` it signs, so the approval verifies offline
   * (`reviewApprovalProblem`).
   */
  decideReview(reviewId: string, decision: ReviewDecision): Promise<ReviewDecided> {
    const body: Record<string, unknown> = { verdict: decision.verdict };
    if (decision.waive_until !== undefined) {
      body['waive_until'] = decision.waive_until instanceof Date ? decision.waive_until.toISOString() : decision.waive_until;
    }
    if (decision.note !== undefined) body['note'] = decision.note;
    return this.http.adminPost<ReviewDecided>(`/admin/evidence/reviews/${encodeURIComponent(reviewId)}/decide`, body);
  }

  /**
   * Keep a signed observation, break-glass record, (v1.4.0) remediation
   * record or (v1.6.0) grant use in the record outbox and submit it. A failed
   * submission does not throw: a transient error leaves it pending for
   * `flushRecords`, and a refusal no retry can overcome keeps it as a dead
   * letter. Throws only when the record outbox cannot store it.
   */
  async enqueueRecord(record: OutboxRecord): Promise<RecordDelivery> {
    const outbox = this.requireRecordOutbox();
    const fresh = recordOutboxEntry(record);
    let entry = (await outbox.list()).find(e => e.id === fresh.id);
    if (entry && outOfBandDigest(entry.record) !== outOfBandDigest(record)) {
      throw new Error(`a different record with id ${fresh.id} is in the record outbox`);
    }
    if (!entry) {
      entry = fresh;
      await outbox.add(entry);
    }
    if (entry.state === 'dead_letter') return { queued: entry };
    return this.attemptRecord(outbox, entry);
  }

  /**
   * Submit the record outbox's pending records: break-glass records first
   * (1.3.1), then (v1.6.0) grant uses, then observations up to 100 at a time,
   * then (v1.4.0) remediation records, each in the order they were added. A batch the NA refuses as a whole is split until the record
   * it refuses is found; a batch it throttles (`429`) halves the batches that
   * follow, and the records wait as long as its `Retry-After` asks. Records
   * in backoff are skipped unless `ignoreBackoff`; a transient error ends the
   * run. A call joins the run in progress when that run tries everything it
   * asks for, and otherwise starts one once it ends.
   */
  async flushRecords(options: FlushOptions = {}): Promise<RecordFlushResult> {
    const outbox = this.requireRecordOutbox();
    return this.flushingRecords.join(options, () => this.flushRecordRun(outbox, options));
  }

  /** Judge an observation once (admin); returns the existing judgement when it was judged before. */
  judgeObservation(observationId: string): Promise<JudgementSubmission> {
    return this.http.adminPost<JudgementSubmission>(
      `/admin/evidence/observations/${encodeURIComponent(observationId)}/judge`, {}, true,
    );
  }

  /** Judge a break-glass record once (admin); returns the existing judgement when it was judged before. */
  judgeBreakGlass(breakGlassId: string): Promise<JudgementSubmission> {
    return this.http.adminPost<JudgementSubmission>(
      `/admin/evidence/break-glass/${encodeURIComponent(breakGlassId)}/judge`, {}, true,
    );
  }

  /**
   * One page of a resource's changes, with how each was governed and its
   * state, oldest first (admin). Since 1.4.0 the NA pages them (`limit`
   * 1..10000, default 1000; `after_sequence` the previous page's
   * `next_after_sequence`); `allResourceChanges` follows the pages.
   */
  resourceChanges(resourceId: string, params: ResourceChangesParams = {}): Promise<ResourceChanges> {
    return this.http.adminGet<ResourceChanges>(`/admin/evidence/changes/${resourcePath(resourceId)}`, { ...params });
  }

  /**
   * Every change to a resource, oldest first, following pages (admin; v1.4.0).
   * Against an NA before 1.4.0, which does not page, it yields the one
   * response's changes, and throws when that response was truncated.
   */
  async *allResourceChanges(resourceId: string, limit?: number): AsyncGenerator<ResourceChange> {
    let after: number | undefined;
    for (;;) {
      const page: ResourceChanges = await this.resourceChanges(resourceId, {
        ...(limit !== undefined ? { limit } : {}), ...(after !== undefined ? { after_sequence: after } : {}),
      });
      yield* page.changes;
      const next = page.next_after_sequence;
      if (next === null || next === undefined) {
        if (page.truncated) throw new Error('the resource has more changes than the NA returns; upgrade the NA to page them');
        return;
      }
      if (!Number.isSafeInteger(next) || (after !== undefined && next <= after)) {
        throw new Error('resource changes cursor did not advance');
      }
      after = next;
    }
  }

  /** Operator key holders, as the store records them (admin). */
  async operatorHolders(): Promise<OperatorKeyHolder[]> {
    return (await this.http.adminGet<{ holders: OperatorKeyHolder[] }>('/admin/evidence/operator-holders')).holders;
  }

  /** Propose a new holder for an operator key (admin, privileged); a key of another holder approves it. */
  proposeHolder(keyId: string, holder: string): Promise<HolderChange> {
    return this.http.adminPost<HolderChange>(`/admin/operator-keys/${encodeURIComponent(keyId)}/holder`, { holder });
  }

  /** Approve a holder change with a privileged key of a different holder (admin, privileged). */
  approveHolder(proposalId: string): Promise<HolderChange> {
    return this.http.adminPost<HolderChange>(
      `/admin/operator-keys/holder-changes/${encodeURIComponent(proposalId)}/approve`, {},
    );
  }

  private requireRecordOutbox(): RecordOutbox {
    if (!this.recordOutbox) {
      throw new GenesisMeshError('no record outbox is configured (ClientOptions.recordOutbox)', 'record_outbox_required', 0);
    }
    return this.recordOutbox;
  }

  private async attemptRecord(outbox: RecordOutbox, entry: RecordOutboxEntry): Promise<RecordDelivery> {
    let submission: RecordSubmission;
    try {
      submission = entry.kind === 'observation'
        ? await this.submitObservation(entry.record as ObservationRecord)
        : entry.kind === 'remediation'
          ? await this.submitRemediation(entry.record as RemediationRecord)
          : entry.kind === 'grant_execution'
            ? await this.http.publicPost<RecordSubmission>('/evidence/grant-executions', { evidence: entry.record }, true)
            : await this.submitBreakGlass(entry.record as BreakGlassRecord);
    } catch (err) {
      // v1.6.0: a use the NA cannot place yet waits for the earlier uses; behind a dead letter it never will.
      if (entry.kind === 'grant_execution' && err instanceof GenesisMeshError && err.code === 'grant_use_chain_gap'
        && await this.grantPredecessorDead(outbox, entry)) {
        return {
          queued: await this.recordFailed(outbox, entry, err, {
            status: err.status, code: PREDECESSOR_DEAD_LETTERED,
            message: `an earlier use of this grant was refused; the NA answered ${err.code}: ${err.message}`,
          }),
        };
      }
      return { queued: await this.recordFailed(outbox, entry, err) };
    }
    await this.removeRecord(outbox, entry.id);
    return { submission };
  }

  /** Whether the record outbox holds an earlier use of the same grant as a dead letter (v1.6.0). */
  private async grantPredecessorDead(outbox: RecordOutbox, entry: RecordOutboxEntry): Promise<boolean> {
    const use = entry.record as GrantExecutionEvidence;
    return (await outbox.list()).some(e => e.kind === 'grant_execution' && e.state === 'dead_letter'
      && (e.record as GrantExecutionEvidence).grant_id === use.grant_id
      && (e.record as GrantExecutionEvidence).use_sequence < use.use_sequence);
  }

  /**
   * The entry after a failed submission: pending with a backoff, or a dead
   * letter (`refused`: a dead letter for that reason, whatever the error).
   */
  private async recordFailed(
    outbox: RecordOutbox, entry: RecordOutboxEntry, err: unknown, refused?: SubmissionFailure,
  ): Promise<RecordOutboxEntry> {
    const classified = classifySubmissionError(err, RECORD_PERMANENT_REFUSALS);
    const failure = refused ?? classified.failure;
    const transient = refused === undefined && classified.transient;
    const attempts = entry.attempts + 1;
    if (transient && err instanceof GenesisMeshError && err.retryAfterSeconds !== null) {
      this.recordsPausedUntil = Math.max(this.recordsPausedUntil, Date.parse(nextAttemptAt(0, err)));
    }
    const next: RecordOutboxEntry = transient
      ? { ...entry, attempts, last_error: failure, next_attempt_at: nextAttemptAt(attempts, err) }
      : { ...entry, attempts, state: 'dead_letter', next_attempt_at: null, last_error: failure };
    try {
      await outbox.update(next);
    } catch {
      // The entry keeps its previous state; the next flush settles it.
    }
    return next;
  }

  private async removeRecord(outbox: RecordOutbox, id: string): Promise<void> {
    try {
      await outbox.remove(id);
    } catch {
      // The NA holds the record: the next flush resubmits it, gets a duplicate and removes it.
    }
  }

  private async flushRecordRun(outbox: RecordOutbox, options: FlushOptions): Promise<RecordFlushResult> {
    const result: RecordFlushResult = { admitted: [], quarantined: [], pending: [], dead_lettered: [] };
    const pending = (await outbox.list()).filter(e => e.state === 'pending');
    // 1.3.1: break-glass records first. They share the NA's submission rate with observations, and
    // an observation of the same change then finds its break-glass record. v1.6.0: grant uses next,
    // in the order they were made, so an observation of the change finds its use. v1.4.0: remediation
    // records last, once the changes they remediate are recorded and judged.
    const first = ['break_glass', 'grant_execution', 'observation'];
    const entries = [
      ...first.flatMap(kind => pending.filter(e => e.kind === kind)), ...pending.filter(e => !first.includes(e.kind)),
    ];
    const due = (e: RecordOutboxEntry) => options.ignoreBackoff
      || (!(this.recordsPausedUntil > Date.now()) && !(Date.parse(e.next_attempt_at ?? '') > Date.now()));
    const settle = (entry: RecordOutboxEntry, delivery: RecordDelivery): boolean => {
      if (delivery.submission) {
        result.admitted.push(entry);
        if (delivery.submission.status === 'quarantined') result.quarantined.push(entry);
        return true;
      }
      const queued = delivery.queued!;
      (queued.state === 'dead_letter' ? result.dead_lettered : result.pending).push(queued);
      return queued.state === 'dead_letter';
    };
    let stopped = false;
    for (let i = 0; i < entries.length;) {
      const entry = entries[i]!;
      if (stopped || !due(entry)) {
        result.pending.push(entry);
        i += 1;
        continue;
      }
      if (entry.kind !== 'observation') {
        stopped = !settle(entry, await this.attemptRecord(outbox, entry));
        i += 1;
        continue;
      }
      const batch: RecordOutboxEntry[] = [];
      while (i < entries.length && batch.length < this.observationBatch && entries[i]!.kind === 'observation'
        && due(entries[i]!)) {
        batch.push(entries[i]!);
        i += 1;
      }
      stopped = await this.submitBatch(outbox, batch, settle, result);
    }
    return result;
  }

  /**
   * Submit a batch of observations and settle each; true when a transient
   * failure ends the run. A batch the NA refuses as a whole (one record it
   * cannot read, `invalid_json`), or larger than it takes (`413`), is split in
   * halves until the record it refuses is tried alone (1.3.1); a batch it
   * throttles (`429`) halves the batches that follow.
   */
  private async submitBatch(
    outbox: RecordOutbox,
    batch: RecordOutboxEntry[],
    settle: (entry: RecordOutboxEntry, delivery: RecordDelivery) => boolean,
    result: RecordFlushResult,
  ): Promise<boolean> {
    let results: ObservationBatchResult[];
    try {
      results = await this.submitObservations(batch.map(e => e.record as ObservationRecord));
    } catch (err) {
      const tooLarge = err instanceof GenesisMeshError && err.status === 413;
      if (!tooLarge && classifySubmissionError(err, RECORD_PERMANENT_REFUSALS).transient) {
        if (err instanceof GenesisMeshError && err.status === 429) {
          this.observationBatch = Math.min(this.observationBatch, Math.max(1, Math.floor(batch.length / 2)));
        }
        for (const e of batch) settle(e, { queued: await this.recordFailed(outbox, e, err) });
        return true;
      }
      // One observation alone goes by itself, so the NA's answer is about that record.
      const part = async (records: RecordOutboxEntry[]) => (records.length === 1
        ? !settle(records[0]!, await this.attemptRecord(outbox, records[0]!))
        : this.submitBatch(outbox, records, settle, result));
      if (batch.length === 1) return part(batch);
      const half = Math.ceil(batch.length / 2);
      if (await part(batch.slice(0, half))) {
        result.pending.push(...batch.slice(half));
        return true;
      }
      return part(batch.slice(half));
    }
    for (const [index, e] of batch.entries()) {
      const answer = results.find(r => r.index === index);
      if (!answer) {
        result.pending.push(e);
      } else if (answer.status === 'refused') {
        const code = answer.error?.code ?? 'unknown';
        const refusal = new GenesisMeshError(answer.error?.message ?? code, code, code.endsWith('_conflict') ? 409 : 422);
        settle(e, { queued: await this.recordFailed(outbox, e, refusal) });
      } else {
        await this.removeRecord(outbox, e.id);
        settle(e, { submission: answer as RecordSubmission });
      }
    }
    return false;
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

  /**
   * Remove entries older than `olderThanDays` behind a signed checkpoint (admin, privileged).
   * v1.5.0: `throughSequence` stops the prefix at a store position (`olderThanDays` may then be
   * null), and while the NA requires archives (the default) nothing past what archive records
   * cover is removed (`held_back.reason` `not_archived`).
   */
  applyRetention(olderThanDays: number | null, options: { throughSequence?: number } = {}): Promise<RetentionResult> {
    const body: Record<string, number> = {};
    if (olderThanDays !== null) body['older_than_days'] = olderThanDays;
    if (options.throughSequence !== undefined) body['through_sequence'] = options.throughSequence;
    return this.http.adminPost<RetentionResult>('/admin/evidence/retention/apply', body);
  }

  /** One page of the NA's signed store anchors, in order (admin, read tier; v1.2.0). */
  anchors(params: { after_anchor?: number; limit?: number } = {}): Promise<AnchorPage> {
    return this.http.adminGet<AnchorPage>('/admin/evidence/anchors', { ...params });
  }

  /**
   * Every store anchor after `afterAnchor`, following pages (admin, read tier): the copies an
   * auditor keeps outside the operator's reach and verifies exports and audit packs against.
   */
  async allAnchors(afterAnchor = 0): Promise<StoreAnchor[]> {
    const anchors: StoreAnchor[] = [];
    let after: number | null = afterAnchor;
    while (after !== null) {
      const page: AnchorPage = await this.anchors({ after_anchor: after, limit: MAX_PAGE });
      if (page.next_after_anchor !== null && (!Number.isSafeInteger(page.next_after_anchor) || page.next_after_anchor <= after)) {
        throw new Error('anchor page cursor did not advance');
      }
      anchors.push(...page.anchors);
      after = page.next_after_anchor;
    }
    return anchors;
  }

  /** Sign the store's current head now (admin, read tier; v1.2.0). */
  anchor(): Promise<AnchorResult> {
    return this.http.adminPost<AnchorResult>('/admin/evidence/anchors', {}, true);
  }

  /**
   * An audit pack (admin, read tier; v1.5.0): one range of the store between two anchors,
   * everything its records cite, the key history and the manifest the NA signs. The response
   * can be tens of megabytes (up to 50,000 entries). `auditPackFiles` turns it into the pack's
   * files; `verifyAuditPack` verifies them offline from the root key and the anchors you hold.
   * A pack is costly: the NA allows a few per hour (`RateLimitError`, `429`, beyond
   * `NA_RATE_LIMIT_AUDIT_PACKS_PER_HOUR`), so the request is never replayed; raise
   * `ClientOptions.timeout` for a large range.
   */
  auditPack(params: AuditPackParams = {}): Promise<AuditPackResponse> {
    return this.http.adminPost<AuditPackResponse>('/admin/evidence/audit-pack', { ...params });
  }

  /** Archive records and how far they cover the store (admin, read tier; v1.5.0). */
  archives(): Promise<ArchiveList> {
    return this.http.adminGet<ArchiveList>('/admin/evidence/archives');
  }

  /**
   * Record that a pack was written to immutable storage at `location` and read back intact
   * (admin, privileged; v1.5.0). The NA checks the manifest is its own, ends at its anchor of
   * the last entry and continues the archives without a gap, then appends a signed archive record.
   * The same manifest again answers `duplicate`.
   */
  recordArchive(manifest: AuditPackManifest, location: string): Promise<ArchiveResult> {
    return this.http.adminPost<ArchiveResult>('/admin/evidence/archives', { manifest, location }, true);
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
   * Latest state of every resource with stored execution evidence or (1.3.1)
   * break-glass records, for reconciliation against a cloud inventory
   * (admin). A break-glass change counts as the resource's change, in the
   * order the changes were made (`executed_at`), so reconciling after one
   * does not report it again as drift. The chain head (`resource_sequence`,
   * `record_digest`) and `last_decision_id` stay the newest execution
   * record's (0 and empty without one).
   */
  async resourceStates(): Promise<Map<string, ResourceState>> {
    const changes = new Map<string, { store: number; record: ExecutionEvidence | BreakGlassRecord }[]>();
    const add = (resourceId: string, store: number, record: ExecutionEvidence | BreakGlassRecord) => {
      const list = changes.get(resourceId) ?? [];
      list.push({ store, record });
      changes.set(resourceId, list);
    };
    for await (const event of this.iterate({ entry_kind: 'execution' })) {
      const record = event.payload as unknown as ExecutionEvidence;
      if (record.resource_id == null || record.resource_sequence == null) continue;
      add(record.resource_id, event.entry.store_sequence, record);
    }
    for await (const event of this.iterate({ entry_kind: 'break_glass' })) {
      const record = event.payload as unknown as BreakGlassRecord;
      add(record.resource_id, event.entry.store_sequence, record);
    }
    const states = new Map<string, ResourceState>();
    for (const [resourceId, list] of changes) {
      list.sort((a, b) => timestampOrder(a.record.executed_at, b.record.executed_at) || a.store - b.store);
      let state: ResourceState | undefined;
      for (const { record } of list) {
        const execution = 'evidence_id' in record ? record : null;
        if (execution && state && state.resource_sequence >= execution.resource_sequence!) continue;
        const action = execution ? execution.resource_action ?? null : (record as BreakGlassRecord).resource_action;
        const success = record.outcome === 'success';
        state = {
          resource_id: resourceId,
          resource_sequence: execution ? execution.resource_sequence! : state?.resource_sequence ?? 0,
          record_digest: execution ? executionDigest(execution) : state?.record_digest ?? '',
          last_action: action,
          last_outcome: record.outcome,
          last_success_action: success ? action : state?.last_success_action ?? null,
          last_success_parameters: success ? record.execution_parameters : state?.last_success_parameters ?? null,
          last_executed_at: record.executed_at,
          last_decision_id: execution ? execution.decision_id : state?.last_decision_id ?? '',
          ...(execution ? {} : { last_break_glass_id: (record as BreakGlassRecord).break_glass_id }),
        };
      }
      states.set(resourceId, state!);
    }
    return states;
  }
}
