/**
 * The holder of a pre-issued grant (v1.6.0): acts within it while the
 * Network Authority (NA) cannot be reached, keeps each use in the record
 * outbox, and uploads the uses when the NA is back.
 *
 * Before each change the holder checks the grant offline, in this order (the
 * NA's order where the two share a rule): secret material in the request
 * parameters (`grant_use_secret_material`), the bearer key's resource prefix
 * (`grant_use_out_of_scope`), the capability (`grant_capability_mismatch`),
 * the closed envelope (`grant_envelope_mismatch`), the budget counting its
 * own uses (`grant_budget_exhausted`), the validity (`grant_expired` past its
 * end, `grant_use_outside_validity` before its start), the revocation feed it
 * holds and what the NA last answered (`grant_revoked`, or the NA's code),
 * and the uses left on its time token, at most `max_uses_per_time_token`
 * after the use the token names (`grant_time_token_exhausted`, after asking
 * for a fresh token when the NA answers).
 *
 * Every use the holder signs takes the next place in its chain: one the NA
 * refuses for good is quarantined and stays in the chain, so the uses after
 * it are judged on their own. The holder never signs a use the NA would
 * refuse without storing it (secret material is checked first).
 *
 * The public contract's `grant_fallback` rule: when the grant has ended, its
 * budget or time token is spent, or it is revoked, the holder does not block
 * the change. It asks the NA through `governedAction` with break-glass,
 * naming the capability: an NA that answers decides (a DENY is never broken
 * through), and one that cannot be reached (network error, timeout, `5xx`,
 * `429`) leaves the change to run under break-glass, recorded and judged
 * after the fact. Any other refusal throws `GrantRefusedError` and runs
 * nothing.
 */

import { randomUUID } from 'node:crypto';
import { cloneJson, type Signer, verifyBytes } from './auth.js';
import type { AttestationClient } from './attestation.js';
import { GenesisMeshError } from './errors.js';
import { ExecutionRecorder } from './execution.js';
import {
  evaluationFailure, governedAction, GovernedActionError, EvidenceNotKeptError, withoutRefusedMetadata,
  type ActionReport, type BreakGlassResult, type GovernanceClients, type GovernedActionParams, type GovernedActionResult,
} from './governance.js';
import type { GrantsClient } from './grants-client.js';
import {
  envelopeProblem, GrantRecordError, grantUseDigest, signGrantUse, signTimeTokenRequest, verifyCapabilityGrant,
  verifyTimeToken, type CapabilityGrant, type GrantExecutionEvidence, type GrantUseOutcome, type TimeToken,
} from './grants.js';
import type { NAKeys } from './key-history.js';
import { metadataProblem, timeOf } from './out-of-band.js';
import type { RecordFlushResult, RecordSubmission } from './evidence_store.js';
import type { RecordOutboxEntry } from './outbox.js';
import { StrictJsonError } from './strict-json.js';
import { timestampMicros } from './validation.js';
import { verifyRevocationFeedSignature } from './verify.js';
import type { BoundaryDecision, ResourceAction, SovereignRevocationFeed } from './types.js';

/** Why a grant cannot be used, for which the holder falls back to break-glass when the NA cannot be reached. */
export type GrantUnusableCode =
  | 'grant_expired' | 'grant_budget_exhausted' | 'grant_revoked' | 'grant_time_token_exhausted';

/** The codes for which the holder falls back (the public contract's `grant_fallback` rule). */
export const GRANT_FALLBACK_CODES: ReadonlySet<string> = new Set<GrantUnusableCode>([
  'grant_expired', 'grant_budget_exhausted', 'grant_revoked', 'grant_time_token_exhausted',
]);

/** What a holder keeps between runs; persist it (`GrantHolderOptions.persist`) with the record outbox. */
export interface GrantHolderState {
  grant: CapabilityGrant;
  /** The latest time token, exactly as the NA signed it. */
  time_token: TimeToken;
  /** Uses made so far: the head of the grant's use chain. */
  uses: number;
  /** The digest of the last use; null before the first. */
  head_digest: string | null;
  /** When the last use was executed; null before the first. */
  head_executed_at: string | null;
  /** The latest revocation feed the holder verified. */
  revocation_feed: SovereignRevocationFeed | null;
  /** What the NA last answered for a time token when it refused one (`grant_expired`, `grant_revoked`, ...). */
  unusable: string | null;
}

/** The clients a holder uses: a record outbox on the evidence store is required. */
export interface GrantHolderClients extends GovernanceClients {
  grants: GrantsClient;
  attestation: AttestationClient;
}

export interface GrantHolderOptions {
  clients: GrantHolderClients;
  /** The bearer key: its key ID is the grant's `bearer_key_id`. */
  signer: Signer;
  /** The NA's keys (a list, or its key history): grants, time tokens and feeds must verify under them. */
  naPublicKeys: NAKeys;
  /**
   * The bearer key's resource prefix, as it is registered (`resource_prefix`):
   * a use outside it, or without a resource, is refused offline
   * (`grant_use_out_of_scope`), as the NA would quarantine it.
   */
  resourcePrefix?: string | null;
  /** A grant just issued and its first time token; or `state` to resume. */
  grant?: CapabilityGrant;
  timeToken?: TimeToken;
  state?: GrantHolderState;
  /** Called with the new state after every change, before the call that made it returns. */
  persist?: (state: GrantHolderState) => void | Promise<void>;
  /** The clock (default: the system clock). */
  now?: () => Date;
}

/** Break-glass through `governedAction` when the grant cannot be used. */
export interface GrantFallback {
  /** Why the change cannot wait (1 to 1024 characters; no secret values). */
  justification: string;
  /** The decision's offline verification, should the NA answer (as `governedAction` takes it). */
  verify: GovernedActionParams['verify'];
  /** Default: the grant's basis attestation. Break-glass needs an attestation-based evaluation. */
  attestation_id?: string;
  /** Attributes for the evaluation and the break-glass record. */
  attributes?: Record<string, unknown>;
}

export interface GrantActParams {
  capability: string;
  /** Inside the grant's envelope. */
  request_parameters?: Record<string, unknown>;
  resource_id?: string;
  resource_action?: ResourceAction;
  /** Without it, a grant that cannot be used throws `GrantUnusableError`. */
  fallback?: GrantFallback;
}

/** What the action runs under: the grant, a decision of the NA's, or break-glass. */
export type GrantAuthority =
  | { path: 'grant'; grant: CapabilityGrant; use_sequence: number }
  | { path: 'decision'; decision: BoundaryDecision }
  | { path: 'break_glass' };

export type GrantAction<T> = (authority: GrantAuthority) => Promise<ActionReport<T> | void>;

/** The action ran under the grant; `use` is its signed record, kept in the record outbox. */
export interface GrantUseResult<T> {
  path: 'grant';
  value?: T;
  use: GrantExecutionEvidence;
  /** The NA's acknowledgement, when it was reachable. */
  submission?: RecordSubmission;
  /** The record outbox entry holding the use otherwise. */
  queued?: RecordOutboxEntry;
  /** Reported metadata the secret guard refused, left out of the use. */
  dropped?: string[];
}

/** The grant could not be used (`unusable`): `governedAction` with break-glass decided what ran. */
export interface GrantFallbackResult<T> {
  path: 'decision' | 'break_glass';
  unusable: GrantUnusableCode;
  result: GovernedActionResult<T> | BreakGlassResult<T>;
}

export type GrantActResult<T> = GrantUseResult<T> | GrantFallbackResult<T>;

/** The request is outside the grant (or the grant cannot be held): nothing ran. `code` names why. */
export class GrantRefusedError extends GenesisMeshError {
  constructor(message: string, code: string) {
    super(message, code, 0);
    this.name = 'GrantRefusedError';
  }
}

/** The grant cannot be used (`code`, one of `GRANT_FALLBACK_CODES`) and no fallback was given: nothing ran. */
export class GrantUnusableError extends GenesisMeshError {
  constructor(message: string, code: GrantUnusableCode) {
    super(message, code, 0);
    this.name = 'GrantUnusableError';
  }
}

/** The action ran and its use is kept, but the holder's state could not be persisted. `result` is the outcome. */
export class GrantStateNotKeptError<T = unknown> extends GenesisMeshError {
  constructor(cause: unknown, readonly result: GrantUseResult<T>) {
    super(`the use is kept in the record outbox; the holder state was not persisted: ${String(cause)}`,
      'grant_state_not_kept', 0);
    this.name = 'GrantStateNotKeptError';
    this.cause = cause;
  }
}

/** What one `sync` did; a step the NA did not answer is left out of its result and named in `unreachable`. */
export interface GrantSyncResult {
  /** True when every step got an answer from the NA. */
  reachable: boolean;
  /** The time token the NA issued, when it issued one. */
  timeToken: TimeToken | null;
  /** The NA's refusal of a time token, when it refused (`grant_expired`, `grant_revoked`, ...). */
  unusable: string | null;
  /** The record outbox flush, when it ran. */
  flushed: RecordFlushResult | null;
}

/** The NA's answers to a time token request that end the grant for its holder. */
const ENDED = new Set(['grant_expired', 'grant_revoked', 'grant_budget_exhausted', 'grant_bearer_key_retired']);

const PROBE = 'genesis-mesh grant holder: bearer key check for grant ';

/**
 * The holder of one grant. One instance per grant and process; its calls run
 * one at a time. See the module comment for the checks and the fallback.
 */
export class GrantHolder {
  private current: GrantHolderState;
  private readonly clients: GrantHolderClients;
  private readonly signer: Signer;
  private readonly naKeys: NAKeys;
  private readonly resourcePrefix: string | null;
  private readonly persistState?: (state: GrantHolderState) => void | Promise<void>;
  private readonly now: () => Date;
  private readonly recorder: ExecutionRecorder;
  private queue: Promise<unknown> = Promise.resolve();
  private bearerChecked = false;

  constructor(options: GrantHolderOptions) {
    const state = options.state ? cloneJson(options.state) : options.grant && options.timeToken ? {
      grant: options.grant, time_token: options.timeToken, uses: 0, head_digest: null, head_executed_at: null,
      revocation_feed: null, unusable: null,
    } : null;
    if (state === null) throw new Error('GrantHolder needs grant and timeToken, or state');
    this.clients = options.clients;
    this.signer = options.signer;
    this.naKeys = options.naPublicKeys;
    this.resourcePrefix = options.resourcePrefix ?? null;
    this.persistState = options.persist;
    this.now = options.now ?? (() => new Date());
    const grant = state.grant;
    if (!verifyCapabilityGrant(grant, this.naKeys)) {
      throw new GrantRefusedError('the grant is not signed by the NA, or not in its form', 'grant_invalid');
    }
    if (this.signer.keyId !== grant.bearer_key_id) {
      throw new GrantRefusedError(`the signer ${this.signer.keyId} is not the grant's bearer key ${grant.bearer_key_id}`,
        'grant_bearer_mismatch');
    }
    this.checkToken(state.time_token, grant, state.uses);
    if (!this.clients.evidenceStore.recordOutbox) {
      throw new GenesisMeshError('a grant holder needs a record outbox (ClientOptions.recordOutbox)', 'record_outbox_required', 0);
    }
    this.current = state;
    this.recorder = new ExecutionRecorder({ executorSovereignId: grant.bearer_sovereign_id, signer: this.signer });
  }

  /** A copy of the holder's state, to persist and resume from. */
  get state(): GrantHolderState {
    return cloneJson(this.current);
  }

  get grant(): CapabilityGrant {
    return this.current.grant;
  }

  /** Run calls one at a time: two uses never take the same place in the chain. */
  private serial<R>(run: () => Promise<R>): Promise<R> {
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => undefined);
    return next;
  }

  private async persist(): Promise<void> {
    if (this.persistState) await this.persistState(this.state);
  }

  /** A time token is the NA's, for this grant, and no newer than the holder's chain. */
  private checkToken(token: TimeToken, grant: CapabilityGrant, uses: number): void {
    if (!verifyTimeToken(token, this.naKeys) || token.grant_id !== grant.grant_id || token.use_sequence > uses) {
      throw new GrantRefusedError("the time token is not the NA's for this grant and holder", 'grant_time_token_invalid');
    }
  }

  /** Once: the signer holds the grant's bearer key (it signs, and the grant's public key verifies it). */
  private async checkBearer(): Promise<void> {
    if (this.bearerChecked) return;
    const message = Buffer.from(PROBE + this.current.grant.grant_id, 'utf-8');
    const signature = Buffer.from(await this.signer.sign(message)).toString('base64');
    if (!verifyBytes(message, signature, this.current.grant.bearer_public_key)) {
      throw new GrantRefusedError("the signer does not hold the grant's bearer key", 'grant_bearer_mismatch');
    }
    this.bearerChecked = true;
  }

  /**
   * Verify a revocation feed (signed by the NA's key valid at its time, issued
   * by the grant's issuer) and keep it unless the one held is newer. A holder
   * refuses a grant the feed it holds lists as revoked.
   */
  updateRevocationFeed(feed: SovereignRevocationFeed): Promise<boolean> {
    return this.serial(async () => {
      if (!verifyRevocationFeedSignature(feed, this.naKeys) || feed.issuer_sovereign_id !== this.current.grant.issuer_sovereign_id) {
        throw new GrantRefusedError("the revocation feed is not the grant issuer's", 'feed_invalid_signature');
      }
      const held = this.current.revocation_feed;
      if (held !== null && held.sequence > feed.sequence) return false;
      this.current.revocation_feed = cloneJson(feed);
      await this.persist();
      return true;
    });
  }

  /** Read the NA's revocation feed and keep it (`updateRevocationFeed`). */
  async refreshRevocationFeed(): Promise<boolean> {
    const feed = await this.clients.attestation.revocationFeed(this.current.grant.issuer_sovereign_id);
    return this.updateRevocationFeed(feed);
  }

  /**
   * Ask the NA for a fresh time token naming the head of the holder's chain,
   * verify it and keep it. When the NA answers that the grant has ended
   * (`grant_expired`, `grant_revoked`, `grant_budget_exhausted`,
   * `grant_bearer_key_retired`), that answer is kept and the error thrown.
   */
  refreshTimeToken(): Promise<TimeToken> {
    return this.serial(() => this.refresh());
  }

  private async refresh(): Promise<TimeToken> {
    const { grant, uses, head_digest: head } = this.current;
    let token: TimeToken;
    try {
      const request = await signTimeTokenRequest({
        grant_id: grant.grant_id, use_sequence: uses, use_head_digest: head, requested_at: this.now(),
      }, this.signer);
      token = await this.clients.grants.requestTimeToken(request);
    } catch (err) {
      if (err instanceof GenesisMeshError && err.status === 409 && ENDED.has(err.code)) {
        this.current.unusable = err.code;
        await this.persist();
      }
      throw err;
    }
    this.checkToken(token, grant, uses);
    if (token.use_sequence !== uses || (token.use_head_digest ?? null) !== head) {
      throw new GrantRefusedError('the time token names another chain head than the holder asked for',
        'grant_time_token_mismatch');
    }
    this.current.time_token = token;
    await this.persist();
    return token;
  }

  /**
   * On reconnect: read the revocation feed, ask for a fresh time token, and
   * upload the record outbox (the grant's uses in order, with the other
   * records). Steps the NA does not answer are skipped, not thrown
   * (`reachable: false`); other errors are thrown.
   */
  async sync(options: { ignoreBackoff?: boolean } = {}): Promise<GrantSyncResult> {
    const result: GrantSyncResult = { reachable: true, timeToken: null, unusable: null, flushed: null };
    const unreachable = (err: unknown) => {
      if (evaluationFailure(err) === null) throw err;
      result.reachable = false;
    };
    try {
      await this.refreshRevocationFeed();
    } catch (err) {
      unreachable(err);
    }
    if (result.reachable) {
      try {
        result.timeToken = await this.refreshTimeToken();
      } catch (err) {
        if (err instanceof GenesisMeshError && err.status === 409 && ENDED.has(err.code)) result.unusable = err.code;
        else unreachable(err);
      }
    }
    if (result.reachable) {
      result.flushed = await this.clients.evidenceStore.flushRecords({ ignoreBackoff: options.ignoreBackoff ?? true });
    }
    return result;
  }

  /**
   * Act within the grant, offline: check it (the module comment lists the
   * checks), run `action`, sign the use with the bearer key and keep it in
   * the record outbox (submitted at once when the NA is reachable). An action
   * that throws is recorded as a `failure` use and the error rethrown. When
   * the grant cannot be used, `fallback` decides (see the module comment).
   */
  act<T>(params: GrantActParams, action: GrantAction<T>): Promise<GrantActResult<T>> {
    return this.serial(() => this.actNow(params, action));
  }

  private async actNow<T>(params: GrantActParams, action: GrantAction<T>): Promise<GrantActResult<T>> {
    const state = this.current;
    const grant = state.grant;
    if ((params.resource_id === undefined) !== (params.resource_action === undefined)) {
      throw new Error('resource_id and resource_action go together');
    }
    const parameters = params.request_parameters ?? {};
    // Refused before anything runs: the NA would refuse such a use and never store it.
    const secret = metadataProblem({ request_parameters: parameters });
    if (secret !== null) throw new GrantRefusedError(secret, 'grant_use_secret_material');
    if (this.resourcePrefix !== null && !(params.resource_id ?? '').startsWith(this.resourcePrefix)) {
      throw new GrantRefusedError(`the bearer key covers only resources starting with ${this.resourcePrefix}`,
        'grant_use_out_of_scope');
    }
    if (!grant.capabilities.includes(params.capability)) {
      throw new GrantRefusedError(`${params.capability} is not one of the grant's capabilities`, 'grant_capability_mismatch');
    }
    const outside = envelopeProblem(grant.parameter_envelope, parameters);
    if (outside !== null) throw new GrantRefusedError(outside, 'grant_envelope_mismatch');
    await this.checkBearer();

    const sequence = state.uses + 1;
    const now = this.now();
    // Never dated before the time token, nor before the previous use: the token proves the time is no earlier
    // (the NA allows 300 seconds before the token; the holder needs none of it).
    let executedAt = timeOf(now, 'executed_at', 'grant_use_malformed')!;
    for (const floor of [state.time_token.issued_at, state.head_executed_at]) {
      if (floor !== null && timestampMicros(floor) > timestampMicros(executedAt)) executedAt = floor;
    }
    const at = timestampMicros(executedAt);
    let unusable: GrantUnusableCode | null = null;
    if (sequence > grant.max_uses) unusable = 'grant_budget_exhausted';
    else if (at > timestampMicros(grant.valid_until)) unusable = 'grant_expired';
    else if (at < timestampMicros(grant.valid_from)) {
      throw new GrantRefusedError(`the grant is valid from ${grant.valid_from}`, 'grant_use_outside_validity');
    } else if (state.revocation_feed?.revoked_grant_ids?.includes(grant.grant_id)) unusable = 'grant_revoked';
    else if (state.unusable !== null) {
      if (!GRANT_FALLBACK_CODES.has(state.unusable)) {
        throw new GrantRefusedError(`the NA answered ${state.unusable} for this grant`, state.unusable);
      }
      unusable = state.unusable as GrantUnusableCode;
    } else if (sequence - state.time_token.use_sequence > grant.max_uses_per_time_token) {
      unusable = await this.freshToken();
    }
    if (unusable !== null) return this.fallBack(params, action, unusable);

    const token = this.current.time_token;
    const sign = (report: ActionReport<T>, outcome: GrantUseOutcome) => signGrantUse({
      grant, use_sequence: sequence, previous: state.head_digest, capability: params.capability,
      request_parameters: parameters, resource_id: params.resource_id, resource_action: params.resource_action,
      executed_at: timestampMicros(executedAt) >= timestampMicros(token.issued_at) ? executedAt : token.issued_at,
      time_token: token, outcome, outcome_detail: report.outcome_detail ?? undefined,
      execution_parameters: report.execution_parameters, use_id: randomUUID(),
    }, this.signer);

    let report: ActionReport<T>;
    try {
      report = (await action({ path: 'grant', grant, use_sequence: sequence })) ?? {};
    } catch (err) {
      try {
        await this.keep(await sign({ outcome_detail: 'action failed' }, 'failure'));
      } catch (recordError) {
        throw new GovernedActionError(err, recordError);
      }
      throw err;
    }

    // The action ran: from here on its outcome is always recorded.
    let use: GrantExecutionEvidence;
    let dropped: string[] | undefined;
    let delivery: { submission?: RecordSubmission; queued?: RecordOutboxEntry };
    const refusedReport = (err: unknown) => err instanceof StrictJsonError
      || (err instanceof GrantRecordError && err.code === 'grant_use_secret_material');
    try {
      try {
        use = await sign(report, report.outcome ?? 'success');
      } catch (err) {
        if (!refusedReport(err)) throw err;
        const cleaned = withoutRefusedMetadata(report.execution_parameters ?? {}, report.outcome_detail ?? null);
        use = await sign({ ...report, ...cleaned }, report.outcome ?? 'success');
        dropped = cleaned.dropped;
      }
      delivery = await this.keep(use);
    } catch (err) {
      throw new EvidenceNotKeptError(err, report.value);
    }
    const result: GrantUseResult<T> = { path: 'grant', value: report.value, use, ...delivery, ...(dropped ? { dropped } : {}) };
    try {
      await this.persist();
    } catch (err) {
      throw new GrantStateNotKeptError(err, result);
    }
    return result;
  }

  /** Advance the chain to a signed use and keep it in the record outbox; the chain stays put when it cannot be kept. */
  private async keep(use: GrantExecutionEvidence): Promise<{ submission?: RecordSubmission; queued?: RecordOutboxEntry }> {
    const before = { uses: this.current.uses, head_digest: this.current.head_digest, head_executed_at: this.current.head_executed_at };
    Object.assign(this.current, { uses: use.use_sequence, head_digest: grantUseDigest(use), head_executed_at: use.executed_at });
    try {
      return await this.clients.evidenceStore.enqueueRecord(use);
    } catch (err) {
      Object.assign(this.current, before);
      throw err;
    }
  }

  /** The token's uses are spent: a fresh one when the NA answers, else why the grant cannot be used. */
  private async freshToken(): Promise<GrantUnusableCode | null> {
    try {
      await this.refresh();
      return null;
    } catch (err) {
      if (evaluationFailure(err) !== null) return 'grant_time_token_exhausted';
      if (err instanceof GenesisMeshError && GRANT_FALLBACK_CODES.has(err.code)) return err.code as GrantUnusableCode;
      throw err;
    }
  }

  /** The grant cannot be used: `governedAction` with break-glass, naming the capability. */
  private async fallBack<T>(
    params: GrantActParams, action: GrantAction<T>, unusable: GrantUnusableCode,
  ): Promise<GrantFallbackResult<T>> {
    const fallback = params.fallback;
    if (!fallback) throw new GrantUnusableError(`the grant cannot be used (${unusable}) and no fallback was given`, unusable);
    const grant = this.current.grant;
    const attestationId = fallback.attestation_id ?? (grant.basis_kind === 'attestation' ? grant.basis_id : undefined);
    if (attestationId === undefined) {
      throw new GrantUnusableError(`the grant cannot be used (${unusable}); break-glass needs an attestation `
        + '(fallback.attestation_id)', unusable);
    }
    const result = await governedAction(this.clients, this.recorder, {
      attestation_id: attestationId, requested_capability: params.capability,
      context: {
        request_parameters: params.request_parameters ?? {},
        ...(fallback.attributes !== undefined ? { attributes: fallback.attributes } : {}),
      },
      resource_id: params.resource_id, resource_action: params.resource_action, verify: fallback.verify,
      breakGlass: { justification: fallback.justification },
    }, decision => action(decision ? { path: 'decision', decision } : { path: 'break_glass' }));
    return { path: 'brokeGlass' in result ? 'break_glass' : 'decision', unusable, result };
  }
}
