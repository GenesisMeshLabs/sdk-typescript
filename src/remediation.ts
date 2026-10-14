/**
 * Remediation, reviews and emergency changes (Genesis Mesh 1.4.0).
 *
 * Since 1.3.0 the Network Authority (NA) judges every change made outside the
 * controlled path. Since 1.4.0 a judged DENY leads somewhere: the NA states
 * what is to be done and by when (the remediation state, read from the due
 * queue), the controller does it and records it, and a second person can
 * review the change. Two records bring this into the evidence store:
 *
 * - `RemediationRecord` (entry kind `remediation`): what a controller did
 *   about a judged change, signed by its executor key (`signRemediation`,
 *   `ExecutionRecorder.signRemediation`, `cancelByRotatingForward`);
 * - `ReviewRecord` (entry kind `review`): a second holder's verdict, signed by
 *   the NA, with the operators' signed admin requests embedded
 *   (`AdminApproval`), so the approval verifies offline
 *   (`reviewApprovalProblem`).
 *
 * The rules the NA applies (`remediationPlan`, `nextState`, the due times,
 * `stepsProblem`, `checkRemediation`, `reviewHolderProblem`) are ported here
 * as pure functions, with the reference's codes (conformance suite
 * `remediation`). Both records sign every field but `signature`, absent
 * optional fields left out, as the 1.3.0 records do.
 */

import { randomUUID } from 'node:crypto';
import { adminSigningPayload, checkSignable, signCanonical, verifyBytes, type Signer } from './auth.js';
import { GenesisMeshError } from './errors.js';
import type { NAKeys } from './key-history.js';
import {
  metadataProblem, OutOfBandRecordError, outOfBandCanonical, timeOf, verifyOutOfBandRecord, wire,
} from './out-of-band.js';
import { nonCanonicalFields, unknownFields } from './strict.js';
import {
  remediationStepsProblem, reviewConsistencyProblem, timestampMicros, validRemediation,
} from './validation.js';
import type {
  BoundaryPolicy, BoundaryPolicyIntent, EvidenceStoreEntry, GateRemediation, PolicyGateEvaluation, PolicyIssue,
  ResourceAction, Signature,
} from './types.js';

// ── Records ─────────────────────────────────────────────────────────────────

/** What a remediation or review is about: a judgement of a change, or a decision under a policy that requires review. */
export type RemediationSubjectKind = 'judgement' | 'decision';
/** The record of the change a remediation acts on. */
export type ChangeKind = 'observation' | 'break_glass' | 'execution';
/**
 * What the controller did: `rotate_forward_then_disable` (a new version issued
 * under a governed decision, then the denied version disabled), `disable` or
 * `delete` (a resource nothing reads yet), or `none` (nothing changed).
 */
export type RemediationSteps = 'rotate_forward_then_disable' | 'disable' | 'delete' | 'none';
/** The steps the NA states for a remediation (a controller may carry out `disable` as `delete`). */
export type PlannedSteps = 'rotate_forward_then_disable' | 'disable' | 'none';
export type RemediationOutcome = 'cancelled' | 'alerted';
export type RemediationMode = 'cancel' | 'alert_only';
/** Why a `cancel` fell back to `alert_only`. */
export type RemediationFallback = 'not_versioned' | 'not_rotatable' | 'not_reversible' | 'indeterminate' | 'not_executed';
/** Where a plan's guidance came from: a failing gate, a policy's `"*"`, or the NA's defaults. */
export type GuidanceSource = 'gate' | 'policy' | 'default';
/** `uphold`: the change stands; `deny`: remediation becomes due; `waive_until`: it stands until a time. */
export type ReviewVerdict = 'uphold' | 'deny' | 'waive_until';
/** Why a review was opened: an operator asked, the judgement was flagged (1.3.0), or the policy requires it. */
export type ReviewOpenedFor = 'requested' | 'flagged_for_review' | 'review_required';

/**
 * An operator's signed admin request, kept whole in a review (signature
 * version 2): the fields of the payload the operator signed, the signature
 * from `X-Admin-Signature`, and the operator's public key as the NA held it.
 * `timestamp` is kept as sent: the signature covers its exact text.
 */
export interface AdminApproval {
  key_id: string;
  public_key: string;
  method: string;
  path: string;
  query: Record<string, string[]>;
  /** The NA's public key. */
  audience: string;
  body: Record<string, unknown>;
  timestamp: string;
  nonce: string;
  admin_signature: string;
}

/** What a controller did about a judged change, signed by the executor key that carried it out. */
export interface RemediationRecord {
  remediation_id: string;
  executor_sovereign_id: string;
  subject_kind: RemediationSubjectKind;
  /** The judgement (or decision) that made the remediation due. */
  subject_id: string;
  change_kind: ChangeKind;
  /** The record of the change: the observation, break-glass record or execution evidence. */
  change_id: string;
  resource_id: string;
  /** `alerted` exactly when `steps` is `none`. */
  outcome: RemediationOutcome;
  steps: RemediationSteps;
  /** For `rotate_forward_then_disable`: the forward rotation's execution evidence, stored first. */
  rotation_evidence_id?: string;
  /** For `rotate_forward_then_disable`: the version the forward rotation issued. */
  version_id?: string;
  /** The version disabled or deleted (never with `steps: none`). */
  disabled_version_id?: string;
  remediated_at: string;
  /** Up to 1024 characters; no secret material. */
  detail?: string;
  signature?: Signature;
}

/** A second holder's verdict on a judged change or a decision, signed by the NA. */
export interface ReviewRecord {
  review_id: string;
  subject_kind: RemediationSubjectKind;
  subject_id: string;
  /** SHA-256 of the subject entry's stored payload. */
  subject_digest: string;
  resource_id?: string;
  capability?: string;
  opened_for: ReviewOpenedFor;
  /** For a requested review: the requester's operator key, holder, justification and signed request. */
  requested_by?: string;
  requester_holder?: string;
  justification?: string;
  request_approval?: AdminApproval;
  requested_at: string;
  /** The actor as the source reported it (not authenticated), and the holder the NA mapped it to. */
  actor?: string;
  actor_holder?: string;
  verdict: ReviewVerdict;
  /** Present exactly for a waiver: after `decided_at`, at most 90 days later. */
  waive_until?: string;
  note?: string;
  decided_by: string;
  decider_holder: string;
  /** The decider's signed request. */
  approval: AdminApproval;
  decided_at: string;
  issuer_sovereign_id: string;
  issued_by: string;
  signature?: Signature;
}

/** The signed form of a remediation or review record: every field but `signature`, absent optional fields left out. */
export function remediationCanonical(record: RemediationRecord | ReviewRecord): string {
  return outOfBandCanonical(record);
}

/**
 * True when a remediation record is well formed, signed by one of the keys
 * (its executor key's) over the record as received, in the reference's form
 * and with no field this SDK does not know.
 */
export function verifyRemediationRecord(record: RemediationRecord, publicKeys: NAKeys): boolean {
  return 'remediation_id' in Object(record) && verifyOutOfBandRecord(record as never, publicKeys);
}

/**
 * True when a review record is well formed and signed by one of the NA keys,
 * as `verifyRemediationRecord` checks a remediation. Whether its embedded
 * approvals prove it is `reviewApprovalProblem`; whether a second holder
 * decided it is `reviewHolderProblem`.
 */
export function verifyReviewRecord(review: ReviewRecord, naPublicKeys: NAKeys): boolean {
  return 'review_id' in Object(review) && verifyOutOfBandRecord(review as never, naPublicKeys);
}

// ── The remediation state (the due queue) ───────────────────────────────────

/**
 * States of a change. A change enters Stage 3 from its Stage 2 state
 * (`judged_denied`, `judged_allowed`, `indeterminate`, `matched`, or
 * `recorded` for a governed change under a policy that requires review). A
 * denied or indeterminate change is armed at once (`remediation_due`); an
 * allowed one keeps its Stage 2 state while it is reviewed or its lifetime
 * runs. `review_denied` is passed through at once, on the way to
 * `remediation_due`. A pending review is not a state but a flag beside it
 * (`review_pending`): it stops no clock.
 */
export type RemediationState =
  | 'judged_denied' | 'judged_allowed' | 'indeterminate' | 'matched' | 'recorded'
  | 'remediation_due' | 'overdue' | 'remediated' | 'upheld' | 'waived' | 'review_denied';

/** What moves a change from one state to the next. */
export type TransitionEvent =
  | 'arm' | 'open_review' | 'due_passed' | 'record_remediation' | 'uphold' | 'deny' | 'waive' | 'waiver_expired'
  | 'lifetime_ended';

/** Codes a refused transition is answered with. */
export type TransitionRefusal =
  | 'review_waiver_after_remediation'
  | 'review_after_remediation'
  | 'remediation_already_recorded'
  | 'review_not_pending'
  | 'review_already_pending'
  | 'remediation_not_due'
  | 'illegal_transition';

/** An allowed change a remediation state concerns: under review, or with a lifetime running. */
export const STANDING_STATES: readonly RemediationState[] = ['judged_allowed', 'matched', 'recorded'];

/**
 * States in which something is still to happen. The due queue without
 * `state` lists these, and every change with a pending review but a
 * remediated one.
 */
export const OPEN_STATES: readonly RemediationState[] = ['remediation_due', 'overdue', 'waived'];

/** The states a remediation state holds. */
export const STORED_STATES: readonly RemediationState[] = [
  ...STANDING_STATES, 'remediation_due', 'overdue', 'remediated', 'upheld', 'waived',
];

/** The due queue's `state` filter: a stored state, or `review_pending` (the flag, whatever the state). */
export type RemediationQueueFilter = RemediationState | 'review_pending';
export const QUEUE_FILTERS: readonly RemediationQueueFilter[] = [...STORED_STATES, 'review_pending'];

/** A review as the NA summarises it (in the state while pending, and from `GET /admin/evidence/reviews/<id>`). */
export interface ReviewSummary {
  review_id: string;
  subject_id: string;
  opened_for: ReviewOpenedFor;
  requested_by: string | null;
  requester_holder: string | null;
  justification: string | null;
  requested_at: string;
  decided_at: string | null;
  verdict: ReviewVerdict | null;
}

/**
 * One change's remediation state, as the NA's routes return it: its identity,
 * the plan, the due times and the links. Times are UTC with six digits of
 * microseconds and `+00:00`.
 */
export interface RemediationStatus {
  subject_kind: RemediationSubjectKind;
  subject_id: string;
  change_kind: ChangeKind | null;
  /** Null for a decision before its execution evidence is known. */
  change_id: string | null;
  /** The version the change made, as recorded when the state was armed. */
  change_version_id: string | null;
  resource_id: string | null;
  capability: string | null;
  /**
   * The change's actor: the observed actor as the source reported it (not
   * proof of who acted), or, for a decision, the operator key that asked for it.
   */
  actor: string | null;
  /** The actor's holder: mapped when a review is decided, or the requesting key's holder for a decision. */
  actor_holder: string | null;
  verdict: string | null;
  state: RemediationState;
  /** True while a review is pending: a flag beside the state, which stops no clock. */
  review_pending: boolean;
  mode: RemediationMode;
  steps: PlannedSteps;
  fallback: RemediationFallback | null;
  grace_seconds: number;
  guidance_source: GuidanceSource;
  remediation_due_at: string | null;
  /** When an emergency change's lifetime ends. */
  lifetime_ends_at: string | null;
  waived_until: string | null;
  /** The latest review, and the remediation record. */
  review_id: string | null;
  remediation_id: string | null;
  /** The first notice recorded, and the operator key that recorded it. */
  notified_at: string | null;
  notified_by: string | null;
  overdue_since: string | null;
  created_at: string;
  updated_at: string;
  /** With `review_pending`: the pending review's summary. */
  review?: ReviewSummary;
}

/** A store entry as the NA returns it with its payload. */
export interface StoredRecord<P = Record<string, unknown>> {
  entry: EvidenceStoreEntry;
  entry_digest: string;
  payload: P;
}

// ── The state table ─────────────────────────────────────────────────────────

/** States a review may be opened, upheld or waived in. */
const REVIEWABLE: readonly RemediationState[] = [...STANDING_STATES, 'remediation_due', 'overdue', 'upheld', 'waived'];

const TRANSITIONS: ReadonlyMap<string, RemediationState> = new Map(([
  ['judged_denied', 'arm', 'remediation_due'],
  ['indeterminate', 'arm', 'remediation_due'],
  ['review_denied', 'arm', 'remediation_due'],
  ['remediation_due', 'due_passed', 'overdue'],
  ['remediation_due', 'record_remediation', 'remediated'],
  ['overdue', 'record_remediation', 'remediated'],
  ['waived', 'waiver_expired', 'remediation_due'],
  ...[...STANDING_STATES, 'upheld'].map(s => [s, 'lifetime_ended', 'remediation_due']),
  // Opening a review sets the flag; the state stays.
  ...REVIEWABLE.map(s => [s, 'open_review', s]),
  ...REVIEWABLE.map(s => [s, 'uphold', 'upheld']),
  ...REVIEWABLE.map(s => [s, 'waive', 'waived']),
  ...[...STANDING_STATES, 'upheld', 'waived'].map(s => [s, 'deny', 'review_denied']),
  // A denial of a change already due changes nothing but, perhaps, its due time.
  ['remediation_due', 'deny', 'remediation_due'],
  ['overdue', 'deny', 'overdue'],
  // A review pending when the remediation was recorded is still decided; it changes nothing.
  ['remediated', 'uphold', 'remediated'],
  ['remediated', 'deny', 'remediated'],
] as [string, string, RemediationState][]).map(([state, event, next]) => [`${state}\u0000${event}`, next]));

/** A transition the state table does not allow; `code` is a `TransitionRefusal`. */
export class TransitionRefusedError extends GenesisMeshError {
  constructor(code: TransitionRefusal, message: string) {
    super(message, code, 0);
    this.name = 'TransitionRefusedError';
  }
}

function refusal(state: string, event: string): TransitionRefusal {
  if (state === 'remediated') {
    if (event === 'waive') return 'review_waiver_after_remediation';
    if (event === 'open_review') return 'review_after_remediation';
    if (event === 'record_remediation') return 'remediation_already_recorded';
  }
  if (event === 'record_remediation') return 'remediation_not_due';
  return 'illegal_transition';
}

/**
 * The state after `event`, given whether a review is pending, as the NA's
 * state table has it; throws `TransitionRefusedError` (with the NA's code)
 * otherwise. A review is decided only while one is pending
 * (`review_not_pending`), and only one is pending at a time
 * (`review_already_pending`). Every other event applies whether a review is
 * pending or not: a pending review never stops a clock. A remediation is
 * recorded only from `remediation_due` or `overdue`.
 */
export function nextState(state: string, event: string, reviewPending = false): RemediationState {
  if ((event === 'uphold' || event === 'deny' || event === 'waive') && !reviewPending) {
    throw new TransitionRefusedError('review_not_pending', `${event}: no review of this change is pending`);
  }
  if (event === 'open_review' && reviewPending && state !== 'remediated') {
    throw new TransitionRefusedError('review_already_pending', 'a review of this change is already pending');
  }
  const next = TRANSITIONS.get(`${state}\u0000${event}`);
  if (next !== undefined) return next;
  throw new TransitionRefusedError(refusal(state, event), `${event} is not allowed in state ${state}`);
}

/**
 * A judged change's Stage 2 state: where it enters the state table. v1.6.0: a
 * change matched to a grant use is governed (`matched`), as one matched to
 * execution evidence is.
 */
export function judgementState(verdict: string, governedBy: string): RemediationState {
  if (governedBy === 'prior_decision' || governedBy === 'grant') return verdict === 'deny' ? 'judged_denied' : 'matched';
  return verdict === 'allow' ? 'judged_allowed' : verdict === 'deny' ? 'judged_denied' : 'indeterminate';
}

// ── Remediation plans ───────────────────────────────────────────────────────

/** What applies when no policy gives guidance (the NA's `NA_REMEDIATION_*` settings). */
export interface RemediationDefaults {
  /** Default 86400 (one day). */
  grace_seconds: number;
  /** Default `alert_only`. */
  mode: RemediationMode;
}

export const DEFAULT_REMEDIATION: Readonly<RemediationDefaults> = Object.freeze({ grace_seconds: 86400, mode: 'alert_only' });

/** What a judged change leads to, as the NA states it. */
export interface RemediationPlan {
  mode: RemediationMode;
  steps: PlannedSteps;
  fallback: RemediationFallback | null;
  grace_seconds: number;
  source: GuidanceSource;
}

type GuidedPolicy = Pick<BoundaryPolicy, 'policy_id' | 'version' | 'remediation'>;
type GateEvaluation = Pick<PolicyGateEvaluation, 'policy_id' | 'policy_version' | 'gate_id' | 'mode' | 'passed'>;

/** Code-point order, as the reference sorts strings. */
function codePointOrder(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

/**
 * The guidance for a judged change: that of each enforce-mode gate that failed
 * (its own entry, or its policy's `"*"`); without one, the `"*"` guidance of
 * the policies that applied; without that, the defaults. Among several,
 * `cancel` wins over `alert_only`, and the shortest grace of the winning mode
 * applies.
 */
export function remediationGuidance(
  policies: readonly GuidedPolicy[],
  evaluations: readonly GateEvaluation[],
  defaults: RemediationDefaults = DEFAULT_REMEDIATION,
): { mode: RemediationMode; grace_seconds: number; source: GuidanceSource } {
  const byKey = new Map<string, GuidedPolicy>();
  for (const p of policies) byKey.set(`${p.policy_id}\u0000${p.version}`, p);
  const guided = (p: GuidedPolicy | undefined) => (p?.remediation && Object.keys(p.remediation).length > 0
    ? p.remediation : null);
  let found: GateRemediation[] = [];
  for (const e of evaluations) {
    if (e.mode !== 'enforce' || e.passed) continue;
    const remediation = guided(byKey.get(`${e.policy_id}\u0000${e.policy_version}`));
    if (!remediation) continue;
    const entry = (Object.hasOwn(remediation, e.gate_id) ? remediation[e.gate_id] : undefined) ?? remediation['*'];
    if (entry) found.push(entry);
  }
  let source: GuidanceSource = 'gate';
  if (found.length === 0) {
    source = 'policy';
    found = [...byKey.values()]
      .sort((a, b) => codePointOrder(a.policy_id, b.policy_id) || a.version - b.version)
      .map(p => guided(p)?.['*'])
      .filter((g): g is GateRemediation => g !== undefined);
  }
  if (found.length === 0) return { mode: defaults.mode, grace_seconds: defaults.grace_seconds, source: 'default' };
  const mode: RemediationMode = found.some(g => g.mode === 'cancel') ? 'cancel' : 'alert_only';
  return { mode, grace_seconds: Math.min(...found.filter(g => g.mode === mode).map(g => g.grace_seconds)), source };
}

/**
 * How a change is cancelled, from what its record says: a created resource
 * nothing reads yet is disabled; a rotated or updated one with a version is
 * rotated forward, then the denied version disabled, unless the record says
 * it cannot be rotated. Without a version, or for a revocation or deletion
 * (cancelling it would restore something), the cancel falls back to
 * `alert_only`.
 */
export function cancelSteps(
  action: string, versionId: string | null | undefined, rotatable: boolean,
): { steps: PlannedSteps; fallback: RemediationFallback | null } {
  if (action === 'create') return { steps: 'disable', fallback: null };
  if (action === 'rotate' || action === 'update') {
    if (versionId === null || versionId === undefined) return { steps: 'none', fallback: 'not_versioned' };
    if (!rotatable) return { steps: 'none', fallback: 'not_rotatable' };
    return { steps: 'rotate_forward_then_disable', fallback: null };
  }
  return { steps: 'none', fallback: 'not_reversible' };
}

export interface RemediationPlanInput {
  /** The judgement's verdict (`deny`, or `indeterminate`, which always alerts). */
  verdict: string;
  /** The policies the judgement applied (with their `remediation` sections). */
  policies: readonly GuidedPolicy[];
  /** The judgement's gate evaluations. */
  evaluations: readonly GateEvaluation[];
  /** From the record of the change (`changeFacts`). */
  action: ResourceAction | string;
  version_id: string | null;
  rotatable: boolean;
  defaults?: RemediationDefaults;
}

/** What a change judged `verdict` leads to, as the NA states it (`mode`, `steps`, `fallback`, grace, source). */
export function remediationPlan(input: RemediationPlanInput): RemediationPlan {
  const { mode, grace_seconds, source } = remediationGuidance(input.policies, input.evaluations, input.defaults);
  if (input.verdict === 'indeterminate') {
    return { mode: 'alert_only', steps: 'none', fallback: mode === 'cancel' ? 'indeterminate' : null, grace_seconds, source };
  }
  if (mode !== 'cancel') return { mode: 'alert_only', steps: 'none', fallback: null, grace_seconds, source };
  const { steps, fallback } = cancelSteps(input.action, input.version_id, input.rotatable);
  return { mode: fallback ? 'alert_only' : 'cancel', steps, fallback, grace_seconds, source };
}

/**
 * A decision's plan, once a review denies it or its lifetime ends: from its
 * latest execution evidence (`changeFacts`), as for a denied change; for a
 * decision never executed (`executed` null), an alert (`fallback`
 * `not_executed`) with the guidance's grace. Its remediation record then
 * names the decision itself as its change (`remediationSubject`).
 */
export function decisionPlan(
  policies: readonly GuidedPolicy[],
  executed: { action: string; version_id: string | null; rotatable: boolean } | null,
  defaults: RemediationDefaults = DEFAULT_REMEDIATION,
): RemediationPlan {
  if (executed === null) {
    const { grace_seconds, source } = remediationGuidance(policies, [], defaults);
    return { mode: 'alert_only', steps: 'none', fallback: 'not_executed', grace_seconds, source };
  }
  return remediationPlan({
    verdict: 'deny', policies, evaluations: [], action: executed.action, version_id: executed.version_id,
    rotatable: executed.rotatable, defaults,
  });
}

/**
 * The action, version and rotatability of the record of a change: an
 * observation's `action`, `version_id` and `metadata.rotatable`; otherwise
 * (execution evidence, a break-glass record) `resource_action`,
 * `execution_parameters.version_id` and `execution_parameters.rotatable`.
 * Rotatable unless the record says `rotatable: false`.
 */
export function changeFacts(
  kind: ChangeKind | string, payload: Record<string, unknown>,
): { action: string; version_id: string | null; rotatable: boolean } {
  const object = (v: unknown) => (typeof v === 'object' && v !== null && !Array.isArray(v) ? v as Record<string, unknown> : {});
  const observation = kind === 'observation';
  const extra = object(observation ? payload['metadata'] : payload['execution_parameters']);
  const version = observation ? payload['version_id'] : extra['version_id'];
  const action = observation ? payload['action'] : payload['resource_action'];
  return {
    action: typeof action === 'string' ? action : action == null ? '' : String(action),
    version_id: typeof version === 'string' && version ? version : null,
    rotatable: extra['rotatable'] !== false,
  };
}

/** A time as the reference prints it: UTC, microseconds when not zero, `Z`. */
function isoMicros(micros: number): string {
  const ms = Math.floor(micros / 1000);
  const base = new Date(ms).toISOString().slice(0, 19);
  const fraction = micros - Math.floor(micros / 1_000_000) * 1_000_000;
  return fraction === 0 ? `${base}Z` : `${base}.${String(fraction).padStart(6, '0')}Z`;
}

function micros(value: string, field: string): number {
  const at = timestampMicros(value);
  if (Number.isNaN(at)) throw new Error(`${field} is not an ISO 8601 timestamp: ${value}`);
  return at;
}

/** `remediation_due_at`: a judgement's (or review's) time plus the grace. */
export function remediationDueAt(at: string, graceSeconds: number): string {
  return isoMicros(micros(at, 'at') + graceSeconds * 1_000_000);
}

/**
 * When a remediation a review denied is due: the grace from the decision,
 * never later than it was already due (a review holds a remediation, it does
 * not extend it).
 */
export function dueAfterDenial(currentDue: string | null, decidedAt: string, graceSeconds: number): string {
  const due = micros(decidedAt, 'decided_at') + graceSeconds * 1_000_000;
  return isoMicros(currentDue === null ? due : Math.min(micros(currentDue, 'current_due'), due));
}

/** When a remediation is due once a waiver ends: its grace again, from the waiver's end. */
export function dueAfterWaiver(waivedUntil: string, graceSeconds: number): string {
  return isoMicros(micros(waivedUntil, 'waived_until') + graceSeconds * 1_000_000);
}

/** Why a remediation record does not carry out the plan the NA stated, or null (`remediation_steps_mismatch`). */
export function stepsProblem(
  planMode: RemediationMode | string, planSteps: PlannedSteps | string, record: Pick<RemediationRecord, 'outcome' | 'steps'>,
): string | null {
  if (planMode === 'alert_only') {
    return record.outcome === 'alerted' ? null
      : `the remediation is alert_only; the record says ${record.outcome} (${record.steps})`;
  }
  if (record.outcome !== 'cancelled') return `the remediation is a cancel (${planSteps}); the record only alerted`;
  if (planSteps === 'disable' && (record.steps === 'disable' || record.steps === 'delete')) return null;
  if (record.steps === planSteps) return null;
  return `the remediation is ${planSteps}; the record says ${record.steps}`;
}

// ── Remediation records ─────────────────────────────────────────────────────

/** A registered key as the NA checks a record against it at admission. */
export interface RemediationKey {
  key_id: string;
  public_key: string;
  executor_sovereign_id: string;
  /** Default `executor`. */
  role?: 'executor' | 'observer';
  resource_prefix?: string | null;
  /** True for a retired key. */
  retired?: boolean;
}

/** Why a remediation record may carry secret material, or null: its versions and detail, under the NA's metadata guard. */
export function remediationSecretProblem(record: Pick<RemediationRecord, 'version_id' | 'disabled_version_id' | 'detail'>): string | null {
  const values: Record<string, unknown> = {};
  for (const name of ['version_id', 'disabled_version_id', 'detail'] as const) {
    if (record[name] !== undefined && record[name] !== null) values[name] = record[name];
  }
  return metadataProblem(values);
}

/**
 * Whether the NA would admit a signed remediation record from `key`, as its
 * `check_remediation` decides: `code` null when authentic, signed by an
 * active executor key of the record's sovereign covering its resource, and
 * free of secret material; otherwise the NA's code
 * (`remediation_invalid_signature`, `remediation_unknown_key`,
 * `remediation_key_retired`, `remediation_out_of_scope`,
 * `remediation_secret_material`).
 */
export function checkRemediation(
  record: RemediationRecord, key: RemediationKey | null | undefined,
): { code: string | null; detail: string } {
  if (!record.signature) return { code: 'remediation_invalid_signature', detail: 'record is not signed' };
  if (!key || key.executor_sovereign_id !== record.executor_sovereign_id) {
    return { code: 'remediation_unknown_key', detail: `signing key is not registered for ${record.executor_sovereign_id}` };
  }
  if (!verifyBytes(Buffer.from(remediationCanonical(record), 'utf-8'), record.signature.sig, key.public_key)) {
    return { code: 'remediation_invalid_signature', detail: 'signature does not verify' };
  }
  const role = key.role ?? 'executor';
  if (key.retired) return { code: 'remediation_key_retired', detail: 'signing key is retired' };
  if (role !== 'executor') return { code: 'remediation_out_of_scope', detail: `signing key is an ${role} key, not an executor key` };
  if (key.resource_prefix != null && !record.resource_id.startsWith(key.resource_prefix)) {
    return { code: 'remediation_out_of_scope', detail: `signing key covers only resources starting with ${key.resource_prefix}` };
  }
  const secret = remediationSecretProblem(record);
  if (secret) return { code: 'remediation_secret_material', detail: secret };
  return { code: null, detail: 'accepted' };
}

/**
 * Why a remediation record as received is not in its exact form, or null:
 * not an object, not a `RemediationRecord` (a field missing, of another type
 * or not its own, steps that do not fit), or not in the serialized form it is
 * signed in (an absent field sent as `null`, a time not in UTC `Z` form, a
 * signature with other fields).
 */
export function remediationFormProblem(raw: unknown): string | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return 'record is not an object';
  const record = raw as Record<string, unknown>;
  if (!validRemediation(record) || unknownFields('RemediationRecord', record).length > 0) {
    return remediationStepsProblem(record) ?? 'record does not match the RemediationRecord model';
  }
  const signature = record['signature'];
  if (Object.values(record).some(v => v === null) || nonCanonicalFields('RemediationRecord', record).length > 0
    || (signature !== undefined && Object.keys(signature as object).some(k => k !== 'key_id' && k !== 'sig'))) {
    return 'record is not in its exact serialized form';
  }
  return null;
}

/**
 * A remediation record as received, checked in the NA's order: first its
 * exact form (`remediation_malformed`), then `checkRemediation` (signature,
 * key, scope and secret material).
 */
export function remediationRecordProblem(
  raw: unknown, key: RemediationKey | null | undefined,
): { code: string | null; detail: string } {
  const form = remediationFormProblem(raw);
  if (form !== null) return { code: 'remediation_malformed', detail: form };
  return checkRemediation(raw as RemediationRecord, key);
}

/**
 * `(code, detail)` when a forward rotation cannot be the one that replaces a
 * change, or null: it is execution evidence of the remediation's own executor
 * sovereign (`remediation_rotation_other_executor`), stored after the record
 * of the change and executed no earlier than the change, when they are known
 * (`remediation_rotation_before_change`: an older version is a roll back),
 * and cited by no other remediation (`remediation_rotation_reused`). Times
 * are microseconds since the epoch.
 */
export function rotationProblem(rotation: {
  rotation_executor: string;
  rotation_sequence: number;
  rotation_executed_at: number;
  record_executor: string;
  change_sequence: number | null;
  changed_at: number | null;
  already_cited: boolean;
}): { code: string; detail: string } | null {
  if (rotation.rotation_executor !== rotation.record_executor) {
    return {
      code: 'remediation_rotation_other_executor',
      detail: `the rotation was executed by ${rotation.rotation_executor}, not by ${rotation.record_executor}`,
    };
  }
  if ((rotation.change_sequence !== null && rotation.rotation_sequence <= rotation.change_sequence)
    || (rotation.changed_at !== null && rotation.rotation_executed_at < rotation.changed_at)) {
    return { code: 'remediation_rotation_before_change', detail: 'the rotation was made before the change it replaces' };
  }
  if (rotation.already_cited) {
    return { code: 'remediation_rotation_reused', detail: 'another remediation already cites this rotation' };
  }
  return null;
}

/** The subject, change and resource a remediation names: from the remediation state in the due queue. */
export interface RemediationSubject {
  subject_kind: RemediationSubjectKind;
  subject_id: string;
  change_kind: ChangeKind;
  change_id: string;
  resource_id: string;
}

export interface RemediationInput extends RemediationSubject {
  steps: RemediationSteps;
  /** Default: `alerted` for steps `none`, `cancelled` otherwise. */
  outcome?: RemediationOutcome;
  rotation_evidence_id?: string;
  version_id?: string;
  disabled_version_id?: string;
  /** Default: now. Any ISO 8601 time with an offset; signed as UTC microseconds. */
  remediated_at?: Date | string;
  detail?: string;
  /** Default: a new UUID. */
  remediation_id?: string;
}

/** The unsigned remediation record for `input`, by the executor sovereign. */
export function remediationRecord(input: RemediationInput & { executor_sovereign_id: string }): RemediationRecord {
  return {
    remediation_id: input.remediation_id ?? randomUUID(),
    executor_sovereign_id: input.executor_sovereign_id,
    subject_kind: input.subject_kind,
    subject_id: input.subject_id,
    change_kind: input.change_kind,
    change_id: input.change_id,
    resource_id: input.resource_id,
    outcome: input.outcome ?? (input.steps === 'none' ? 'alerted' : 'cancelled'),
    steps: input.steps,
    rotation_evidence_id: input.rotation_evidence_id,
    version_id: input.version_id,
    disabled_version_id: input.disabled_version_id,
    remediated_at: timeOf(input.remediated_at ?? new Date(), 'remediated_at', 'remediation_malformed')!,
    detail: input.detail,
  };
}

/**
 * Throw what the NA would refuse an unsigned remediation record for, in its
 * order: JSON it cannot read (`StrictJsonError`), a record its model does not
 * take (`remediation_malformed`: a field missing, empty, too long or of
 * another type, or steps that do not fit the outcome and versions), then
 * secret material in its versions or detail (`remediation_secret_material`).
 */
export function checkRemediationRecord(record: RemediationRecord): void {
  checkSignable(record);
  if (!validRemediation(record)) {
    const steps = remediationStepsProblem(record as unknown as Record<string, unknown>);
    throw new OutOfBandRecordError(steps ?? 'the record does not match the RemediationRecord model '
      + '(a field missing, empty, too long or of another type)', 'remediation_malformed');
  }
  const secret = remediationSecretProblem(record);
  if (secret) throw new OutOfBandRecordError(secret, 'remediation_secret_material');
}

/**
 * Build and sign a remediation record with the executor's signer (its key
 * registered with `role: "executor"` for `executor_sovereign_id`), refused
 * first as the NA would refuse it. Submit it with
 * `evidenceStore.submitRemediation`, or keep it in the record outbox
 * (`evidenceStore.enqueueRecord`).
 */
export async function signRemediation(
  input: RemediationInput & { executor_sovereign_id: string }, signer: Signer,
): Promise<RemediationRecord> {
  const record = remediationRecord(input);
  checkRemediationRecord(record);
  return wire(record, await signCanonical(remediationCanonical(record), signer));
}

/**
 * The subject, change and resource of a remediation state, for a remediation
 * record. A decision never executed (`fallback` `not_executed`) names itself
 * as its change (`change_kind` `execution`, `change_id` its ID); give its
 * resource as `resourceId` when the state has none. Throws when the state
 * names no change yet.
 */
export function remediationSubject(
  state: Pick<RemediationStatus, 'subject_kind' | 'subject_id' | 'change_kind' | 'change_id' | 'resource_id'>
    & Partial<Pick<RemediationStatus, 'fallback'>>,
  resourceId?: string,
): RemediationSubject {
  const resource = state.resource_id ?? resourceId;
  if (state.subject_kind === 'decision' && state.fallback === 'not_executed' && resource) {
    return {
      subject_kind: 'decision', subject_id: state.subject_id, change_kind: 'execution', change_id: state.subject_id,
      resource_id: resource,
    };
  }
  if (!state.change_kind || !state.change_id || !state.resource_id) {
    throw new OutOfBandRecordError(`the remediation of ${state.subject_id} names no change yet (its execution `
      + 'evidence is not stored)', 'remediation_subject_not_found');
  }
  return {
    subject_kind: state.subject_kind, subject_id: state.subject_id, change_kind: state.change_kind,
    change_id: state.change_id, resource_id: state.resource_id,
  };
}

// ── Reviews ─────────────────────────────────────────────────────────────────

/** The route a review is requested on. */
export const REVIEW_REQUEST_PATH = '/admin/evidence/reviews';

/** The route a review is decided on. */
export function reviewDecisionPath(reviewId: string): string {
  return `${REVIEW_REQUEST_PATH}/${reviewId}/decide`;
}

/** How far an embedded approval's timestamp may be from the time the NA recorded (300 s, in microseconds). */
const APPROVAL_MAX_AGE = 300 * 1_000_000;

const DECISION_FIELDS: ReadonlySet<string> = new Set(['verdict', 'waive_until', 'note']);

/**
 * `(code, detail)` when the decider is not a second holder, or null: its key
 * and holder must differ from the requester's
 * (`review_same_holder_as_requester`), and its holder from the observed
 * actor's, where an actor named like the decider's key or holder counts as
 * the decider (`review_same_holder_as_actor`). The first that fails wins.
 */
export function reviewHolderProblem(review: {
  decided_by: string;
  decider_holder: string;
  requested_by?: string | null;
  requester_holder?: string | null;
  actor?: string | null;
  actor_holder?: string | null;
}): { code: 'review_same_holder_as_requester' | 'review_same_holder_as_actor'; detail: string } | null {
  const requestedBy = review.requested_by ?? null;
  const actor = review.actor ?? null;
  if (requestedBy !== null && (review.decided_by === requestedBy
    || review.decider_holder === (review.requester_holder ?? null))) {
    return {
      code: 'review_same_holder_as_requester',
      detail: `holder ${review.decider_holder} requested this review; another holder decides it`,
    };
  }
  if (actor !== null && (review.decider_holder === (review.actor_holder ?? null)
    || actor === review.decided_by || actor === review.decider_holder)) {
    return {
      code: 'review_same_holder_as_actor',
      detail: `holder ${review.decider_holder} is the observed actor (${actor}); another holder decides`,
    };
  }
  return null;
}

/** Whether the operator's signature verifies over the request it kept (signature version 2), with its public key. */
export function adminApprovalValid(approval: AdminApproval): boolean {
  try {
    const payload = adminSigningPayload({
      method: approval.method, path: approval.path, query: approval.query, audience: approval.audience, body: approval.body,
    }, approval.key_id, approval.timestamp, approval.nonce);
    return typeof approval.admin_signature === 'string' && typeof approval.public_key === 'string'
      && verifyBytes(Buffer.from(payload, 'utf-8'), approval.admin_signature, approval.public_key);
  } catch {
    return false;
  }
}

/**
 * The one timestamp grammar of `waive_until` and the admin timestamps a review
 * embeds: RFC 3339 with an upper-case `T`, seconds, an optional fraction of 1
 * to 6 digits and `Z` or `+HH:MM`/`-HH:MM`. Not ISO 8601's basic format, week
 * or ordinal dates, `24:00`, a leap second, an offset with seconds, or a time
 * without an offset.
 */
const RFC3339 = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))$/;

/** Microseconds since the epoch of an RFC 3339 timestamp in the grammar above; NaN for anything else. */
function instant(value: unknown): number {
  const m = typeof value === 'string' ? RFC3339.exec(value) : null;
  if (!m) return NaN;
  const [, y, mo, d, h, mi, s, fraction = '', sign, oh = '0', om = '0'] = m;
  const [year, month, date, hour, minute, second, offsetHour, offsetMinute] = [y, mo, d, h, mi, s, oh, om].map(Number);
  const day = new Date(0);
  day.setUTCFullYear(year!, month! - 1, date);
  if (day.getUTCFullYear() !== year || day.getUTCMonth() !== month! - 1 || day.getUTCDate() !== date || year! < 1
    || hour! > 23 || minute! > 59 || second! > 59 || offsetHour! > 23 || offsetMinute! > 59) {
    return NaN;
  }
  const offset = sign ? (sign === '-' ? -1 : 1) * (offsetHour! * 60 + offsetMinute!) : 0;
  const ms = day.getTime() + ((hour! * 60 + minute! - offset) * 60 + second!) * 1000;
  return ms * 1000 + Number(fraction.padEnd(6, '0'));
}

/**
 * `value` in UTC as the reference prints it (`2026-10-12T09:00:00.500000Z`)
 * when it is an RFC 3339 timestamp in the grammar `waive_until` and the
 * admin timestamps a review embeds must follow; null otherwise.
 */
export function rfc3339(value: unknown): string | null {
  const at = instant(value);
  return Number.isNaN(at) ? null : isoMicros(at);
}

function approvalProblem(
  approval: AdminApproval, who: string, keyId: string, path: string, audiences: readonly string[], at: string,
): string | null {
  if (!adminApprovalValid(approval)) return `the ${who}'s signature does not verify over its request`;
  if (approval.key_id !== keyId) return `the ${who}'s request is signed by ${approval.key_id}, not ${keyId}`;
  if (approval.method !== 'POST' || approval.path !== path || Object.keys(approval.query ?? {}).length > 0) {
    return `the ${who}'s request is ${approval.method} ${approval.path}, not POST ${path}`;
  }
  if (!audiences.includes(approval.audience)) return `the ${who}'s request is for another Network Authority`;
  const signedAt = instant(approval.timestamp);
  if (Number.isNaN(signedAt) || Math.abs(signedAt - timestampMicros(at)) > APPROVAL_MAX_AGE) {
    return `the ${who}'s request was signed more than 300s from when it was recorded`;
  }
  return null;
}

/**
 * Why the requests embedded in a review do not prove it, or null. Offline,
 * with the review alone and the NA's public keys (the audience): the decider
 * signed `POST /admin/evidence/reviews/<review_id>/decide`, without a query,
 * as `decided_by`, with exactly the verdict, waiver end and note the review
 * records, within 300 seconds of `decided_at`; a requester signed
 * `POST /admin/evidence/reviews` with exactly the subject and justification
 * it records, within 300 seconds of `requested_at`. Whether each public key
 * is the operator key's is checked against the holder registry
 * (`verifyEvidenceEvents`, `review_approval_key_mismatch`).
 */
export function reviewApprovalProblem(review: ReviewRecord, naPublicKeys: readonly string[]): string | null {
  const problem = approvalProblem(review.approval, 'decider', review.decided_by, reviewDecisionPath(review.review_id),
    naPublicKeys, review.decided_at);
  if (problem) return problem;
  const body = review.approval.body;
  if (Object.keys(body).some(k => !DECISION_FIELDS.has(k))) return "the decider's request carries fields the review does not record";
  const field = (k: string) => (Object.hasOwn(body, k) ? body[k] : undefined) ?? null;
  if (field('verdict') !== review.verdict || field('note') !== (review.note ?? null)) {
    return "the decider's request gives another verdict or note";
  }
  const waiver = field('waive_until');
  const recorded = review.waive_until ?? null;
  if ((waiver === null) !== (recorded === null)
    || (waiver !== null && recorded !== null && instant(waiver) !== timestampMicros(recorded))) {
    return "the decider's request gives another waiver time (an RFC 3339 timestamp)";
  }
  const request = review.request_approval;
  if (request !== undefined && request !== null) {
    return requestApprovalProblem(request, {
      requested_by: review.requested_by ?? '', subject_kind: review.subject_kind, subject_id: review.subject_id,
      justification: review.justification ?? '', requested_at: review.requested_at,
    }, naPublicKeys);
  }
  return null;
}

/**
 * Why a requester's embedded request does not prove a review request, or
 * null: signed by `requested_by` as `POST /admin/evidence/reviews` for this
 * NA, without a query, with exactly the subject and justification, within
 * 300 seconds of `requested_at`.
 */
export function requestApprovalProblem(
  approval: AdminApproval,
  request: {
    requested_by: string; subject_kind: string; subject_id: string; justification: string; requested_at: string;
  },
  naPublicKeys: readonly string[],
): string | null {
  const problem = approvalProblem(approval, 'requester', request.requested_by, REVIEW_REQUEST_PATH, naPublicKeys,
    request.requested_at);
  if (problem) return problem;
  const expected: Record<string, unknown> = {
    subject_kind: request.subject_kind, subject_id: request.subject_id, justification: request.justification,
  };
  const keys = Object.keys(approval.body);
  if (keys.length !== 3 || keys.some(k => !Object.hasOwn(expected, k) || approval.body[k] !== expected[k])) {
    return "the requester's request names another subject or justification";
  }
  return null;
}

/**
 * `(code, detail)` when the requester is the change's actor (its key, or its
 * holder), or null: the person who made a change does not ask for its review
 * (`review_requested_by_actor`). An actor that maps to no holder cannot be
 * excluded by holder.
 */
export function reviewRequestProblem(request: {
  requested_by: string;
  requester_holder: string;
  actor?: string | null;
  actor_holder?: string | null;
}): { code: 'review_requested_by_actor'; detail: string } | null {
  const actor = request.actor ?? null;
  if (actor !== null && (request.requester_holder === (request.actor_holder ?? null)
    || actor === request.requested_by || actor === request.requester_holder)) {
    return {
      code: 'review_requested_by_actor',
      detail: `holder ${request.requester_holder} is the change's actor (${actor}); another holder requests its review`,
    };
  }
  return null;
}

/** Why a review record's fields do not fit together (a waiver's bounds, a requested review's requester), or null. */
export function reviewRecordProblem(review: ReviewRecord): string | null {
  return reviewConsistencyProblem(review as unknown as Record<string, unknown>);
}

// ── Policies ────────────────────────────────────────────────────────────────

const PARAMETER = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * The issues the NA finds in a policy's 1.4.0 sections (the codes of
 * `validate_boundary_policy`): remediation guidance names a gate of the
 * policy or `"*"` (`invalid_remediation`); an emergency policy selects one
 * exact capability, other than the exact one it stands for, with a valid
 * justification parameter (`invalid_emergency`), required by an enforce-mode
 * `required_parameter.v1` gate (`emergency_justification_not_required`).
 * The rest of a policy is checked by `policy.validate` at the NA.
 */
export function policySectionIssues(policy: BoundaryPolicy | BoundaryPolicyIntent): PolicyIssue[] {
  const issues: PolicyIssue[] = [];
  const gates = policy.gates ?? [];
  const remediation = policy.remediation;
  if (remediation !== undefined && remediation !== null) {
    const keys = Object.keys(remediation);
    if (keys.length === 0) {
      issues.push({ code: 'invalid_remediation', message: 'remediation guidance names no gate' });
    }
    const gateIds = new Set(gates.map(g => g.gate_id));
    for (const key of keys.sort(codePointOrder)) {
      if (key !== '*' && !gateIds.has(key)) {
        issues.push({ code: 'invalid_remediation', message: `remediation names ${key}, which is not a gate of the policy`, gate_id: key });
      }
    }
  }
  const emergency = policy.emergency;
  if (emergency === undefined || emergency === null) return issues;
  const capabilities = policy.selector?.capabilities ?? [];
  if (capabilities.length !== 1 || capabilities[0]!.endsWith('.*')) {
    issues.push({ code: 'invalid_emergency', message: 'an emergency policy selects exactly one capability by its exact ID' });
  } else if (capabilities[0] === emergency.stands_for) {
    issues.push({ code: 'invalid_emergency', message: 'the emergency capability must differ from the capability it stands for' });
  }
  if (emergency.stands_for.endsWith('.*')) {
    issues.push({ code: 'invalid_emergency', message: 'stands_for is an exact capability ID' });
  }
  if (!PARAMETER.test(emergency.justification_parameter)) {
    issues.push({ code: 'invalid_emergency', message: 'justification_parameter must match [A-Za-z0-9_-]{1,64}' });
    return issues;
  }
  const path = `request_parameters.${emergency.justification_parameter}`;
  if (!gates.some(g => g.gate_type === 'required_parameter.v1' && (g.mode ?? 'enforce') === 'enforce'
    && (g.config ?? {})['path'] === path)) {
    issues.push({
      code: 'emergency_justification_not_required',
      message: `an emergency policy requires ${path} with an enforce-mode required_parameter.v1 gate`,
    });
  }
  return issues;
}

/** Whether a policy's selector names `capability`, exactly or by a `prefix.*` pattern. */
function selects(policy: Pick<BoundaryPolicy, 'selector'>, capability: string): boolean {
  return (policy.selector?.capabilities ?? []).some(pattern => pattern === capability
    || (pattern.endsWith('.*') && capability.startsWith(pattern.slice(0, -1))));
}

/**
 * Emergency capability to the ordinary capability it stands for, from the
 * policies given (those active at `at`) whose validity covers `at`. A
 * capability a policy without an emergency section also names is no
 * emergency capability. The NA matches an observer's report of the ordinary
 * capability to a change made under the emergency one with this map.
 */
export function emergencyMap(
  policies: readonly Pick<BoundaryPolicy, 'selector' | 'emergency' | 'valid_from' | 'valid_until'>[],
  at: string,
): Record<string, string> {
  const when = timestampMicros(at);
  const out: Record<string, string> = {};
  for (const policy of policies) {
    const emergency = policy.emergency;
    const capabilities = policy.selector?.capabilities ?? [];
    if (!emergency || capabilities.length !== 1
      || !(timestampMicros(policy.valid_from) <= when && when <= timestampMicros(policy.valid_until))) continue;
    const capability = capabilities[0]!;
    if (policies.some(other => !other.emergency && selects(other, capability))) continue;
    out[capability] = emergency.stands_for;
  }
  return out;
}
