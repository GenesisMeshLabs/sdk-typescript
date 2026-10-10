/**
 * Changes made outside the controlled path (Genesis Mesh 1.3.0).
 *
 * A governed change has a decision before it and execution evidence after it.
 * Other changes still happen: someone changes a secret in the cloud console,
 * or a controller acts while the Network Authority (NA) cannot be reached.
 * These records bring them into the evidence store:
 *
 * - `ObservationRecord`: a change an observer saw at its source, signed by an
 *   observer key (`ObservationRecorder`);
 * - `BreakGlassRecord`: a change a controller made while evaluation failed
 *   transiently, with its caller's justification (`governedAction` with
 *   `breakGlass`);
 * - `JudgementRecord`, `QuarantineRecord`, `RegistryRecord`: signed by the NA.
 *
 * Each record signs every field but `signature`; an absent optional field is
 * left out, never `null` (`outOfBandCanonical`). The forms are frozen from
 * 1.3.0 on and match the Python reference byte for byte (conformance suite
 * `out_of_band`).
 */

import { createHash, randomUUID } from 'node:crypto';
import {
  canonicalJson, checkSignable, copyPythonFloats, defineMember, pythonTimestamp, signCanonical, verifyCanonical,
  type Signer,
} from './auth.js';
import { GenesisMeshError } from './errors.js';
import { nonCanonicalFields, unknownFields } from './strict.js';
import {
  timestampOrder, validBreakGlass, validJudgement, validObservation, validQuarantine, validRegistry,
} from './validation.js';
import { MAX_METADATA_BYTES, secretMaterial } from './execution.js';
import type { ReconciliationFinding, ReconciliationStatus } from './governance.js';
import type { GateResult, PolicyBinding, ResourceAction, Signature } from './types.js';

/** How the NA came to know a change: before it, through a decision, or after it, by a judgement. */
export type GovernedBy = 'prior_decision' | 'after_the_fact';
/** A judgement's verdict; `indeterminate` when the NA cannot tell what applied then. */
export type Verdict = 'allow' | 'deny' | 'indeterminate';
/** Why a controller broke the glass: an evaluation failure a later attempt can overcome. */
export type EvaluationFailure = 'network_error' | 'timeout' | 'server_error' | 'rate_limited';

/** A change seen at its source, signed by an observer key. */
export interface ObservationRecord {
  observation_id: string;
  observer_sovereign_id: string;
  resource_id: string;
  action: ResourceAction;
  /** The capability the change exercises, as a governed action would request it. */
  capability: string;
  /** When the source says the change happened; or the window below for a reconciliation finding. */
  changed_at?: string;
  changed_not_before?: string;
  changed_not_after?: string;
  observed_at: string;
  /** As the source reported it; not authenticated. A pseudonymous identifier, never a credential. */
  actor?: string;
  source: string;
  source_event_id: string;
  /** The source's version after the change; matches execution evidence naming `execution_parameters.version_id`. */
  version_id?: string;
  metadata: Record<string, unknown>;
  signature?: Signature;
}

/** A change a controller made while it could not obtain a decision, signed by its executor key. */
export interface BreakGlassRecord {
  break_glass_id: string;
  executor_sovereign_id: string;
  resource_id: string;
  resource_action: ResourceAction;
  capability: string;
  attestation_id?: string;
  request_parameters: Record<string, unknown>;
  attributes: Record<string, unknown>;
  justification: string;
  /** SHA-256 of the evaluation request that failed (canonical JSON). */
  evaluation_request_digest: string;
  evaluation_failure: EvaluationFailure;
  executed_at: string;
  outcome: string;
  outcome_detail?: string;
  execution_parameters: Record<string, unknown>;
  signature?: Signature;
}

/** The NA's one verdict on an observation or break-glass record. Never an authorisation. */
export interface JudgementRecord {
  judgement_id: string;
  subject_kind: 'observation' | 'break_glass';
  subject_id: string;
  subject_digest: string;
  subject_store_sequence: number;
  resource_id: string;
  action: ResourceAction;
  capability: string;
  governed_by: GovernedBy;
  verdict: Verdict;
  reason?: string;
  evaluated_as_of: string;
  evaluated_from?: string;
  policy_binding?: PolicyBinding;
  gate_results: GateResult[];
  current_verdict?: Verdict;
  current_policy_set_digest?: string;
  flagged_for_review?: boolean;
  matched_evidence_id?: string;
  matched_decision_id?: string;
  possible_match_evidence_id?: string;
  judged_at: string;
  issuer_sovereign_id: string;
  issued_by: string;
  signature?: Signature;
}

/** An authentic record the NA refused after its action happened, kept with the refusal. */
export interface QuarantineRecord {
  quarantine_id: string;
  record_kind: 'execution' | 'observation' | 'break_glass';
  record: Record<string, unknown>;
  record_digest: string;
  rejection_code: string;
  detail: string;
  resource_id?: string;
  quarantined_at: string;
  issuer_sovereign_id: string;
  issued_by: string;
  signature?: Signature;
}

/** Signed history of the NA state judgements rest on. */
export interface RegistryRecord {
  registry_record_id: string;
  event: 'policy_history_started' | 'policy_activated' | 'policy_deactivated' | 'executor_key_registered'
    | 'executor_key_retired' | 'operator_key_holder';
  effective_at: string;
  reconstructed?: boolean;
  policy_id?: string;
  policy_version?: number;
  policy_digest?: string;
  key_id?: string;
  public_key?: string;
  executor_sovereign_id?: string;
  key_role?: 'executor' | 'observer';
  resource_prefix?: string;
  operator_tier?: string;
  holder?: string;
  approved_by?: string;
  recorded_by?: string;
  issuer_sovereign_id: string;
  issued_by: string;
  signature?: Signature;
}

export type OutOfBandRecord = ObservationRecord | BreakGlassRecord | JudgementRecord | QuarantineRecord | RegistryRecord;

/**
 * Thrown before signing when the NA would refuse the record: `*_malformed`
 * (a field it does not take, a timestamp it cannot read, an impossible change
 * time) or `*_secret_material`. JSON the NA would refuse to read throws
 * `StrictJsonError` instead (1.3.1).
 */
export class OutOfBandRecordError extends GenesisMeshError {
  constructor(message: string, code: string) {
    super(message, code, 0);
    this.name = 'OutOfBandRecordError';
  }
}

/** A copy without `signature` and without top-level fields that are absent (`undefined` or `null`). */
function signedFields(record: object): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (key !== 'signature' && value !== undefined && value !== null) defineMember(out, key, value);
  }
  copyPythonFloats(record, out);
  return out;
}

/** The signed form of a Stage 2 record (1.3.0): every field but `signature`, absent optional fields left out. */
export function outOfBandCanonical(record: object): string {
  return canonicalJson(signedFields(record));
}

/** SHA-256 of the signed form. */
export function outOfBandDigest(record: object): string {
  return createHash('sha256').update(outOfBandCanonical(record), 'utf-8').digest('hex');
}

const RECORD_KINDS: ReadonlyArray<[string, string, (v: unknown) => boolean]> = [
  ['observation_id', 'ObservationRecord', validObservation],
  ['break_glass_id', 'BreakGlassRecord', validBreakGlass],
  ['judgement_id', 'JudgementRecord', validJudgement],
  ['quarantine_id', 'QuarantineRecord', validQuarantine],
  ['registry_record_id', 'RegistryRecord', validRegistry],
];

/**
 * True when the record is well formed, its signature verifies under one of the
 * keys over the record as received, and it is in the reference's form with no
 * field this SDK does not know (as `verifyEvidenceEvents` checks it).
 */
export function verifyOutOfBandRecord(record: OutOfBandRecord, publicKeys: readonly string[]): boolean {
  const kind = RECORD_KINDS.find(([id]) => id in record);
  if (!kind || !kind[2](record)) return false;
  const sig = record.signature;
  return !!sig && verifyCanonical(outOfBandCanonical(record), sig.sig, publicKeys)
    && unknownFields(kind[1], record).length === 0 && nonCanonicalFields(kind[1], record).length === 0;
}

/** The wire form: the signed fields plus the signature. */
function wire<T extends object>(record: T, signature: Signature): T {
  return { ...signedFields(record), signature } as T;
}

const ISO_TIME = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?(?:([Zz])|([+-])(\d{2}):?(\d{2}))$/;

/**
 * A time as the reference writes it (1.3.1): UTC, microseconds (a finer
 * fraction is cut, as the reference reads it), `Z`. A string the reference
 * would read, with any UTC offset, is converted, so `toISOString()` output
 * (`.573Z`), `+00:00` and a seven-digit fraction are signed in the form the
 * NA re-serialises. A string without an offset or not a time is refused.
 */
function timeOf(value: Date | string | undefined, field: string, code: string): string | undefined {
  if (value === undefined) return undefined;
  const refuse = (): never => {
    throw new OutOfBandRecordError(`${field} is not an ISO 8601 time with a UTC offset: ${String(value)}`, code);
  };
  if (value instanceof Date) {
    const year = value.getUTCFullYear();
    return Number.isNaN(year) || year < 1 || year > 9999 ? refuse() : pythonTimestamp(value);
  }
  const m = typeof value === 'string' ? ISO_TIME.exec(value) : null;
  if (!m) return refuse();
  const [, y, mo, d, h, mi, s = '0', fraction = '', utc, sign, oh = '0', om = '0'] = m;
  const [year, month, date, hour, minute, second, offsetHour, offsetMinute] = [y, mo, d, h, mi, s, oh, om].map(Number);
  // The calendar date must exist (no 30 February); the time and the offset must be in range.
  const day = new Date(0);
  day.setUTCFullYear(year, month - 1, date);
  if (day.getUTCFullYear() !== year || day.getUTCMonth() !== month - 1 || day.getUTCDate() !== date || year < 1
    || hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59) {
    return refuse();
  }
  const offset = utc ? 0 : (sign === '-' ? -1 : 1) * (offsetHour * 60 + offsetMinute);
  const at = new Date(day.getTime() + ((hour * 60 + minute - offset) * 60 + second) * 1000);
  if (at.getUTCFullYear() < 1 || at.getUTCFullYear() > 9999) return refuse();
  const base = pythonTimestamp(at).slice(0, 19);
  const micros = fraction.slice(0, 6).padEnd(6, '0');
  return micros === '000000' ? `${base}Z` : `${base}.${micros}Z`;
}

// ── Observations ─────────────────────────────────────────────────────────────

export interface ObservationInput {
  resource_id: string;
  action: ResourceAction;
  capability: string;
  /** When the source says the change happened. Give this, or both bounds of the window. */
  changed_at?: Date | string;
  changed_not_before?: Date | string;
  changed_not_after?: Date | string;
  /** Default: now. */
  observed_at?: Date | string;
  actor?: string;
  source: string;
  source_event_id: string;
  version_id?: string;
  /** Identifiers, versions and times; never values. */
  metadata?: Record<string, unknown>;
  /**
   * Default (1.3.1): `observationId(observer, source, source_event_id)`, the
   * same for every record of one source event, so recording it again with
   * the same fields is a `duplicate` at the NA. Before 1.3.1, a new UUID.
   */
  observation_id?: string;
}

/**
 * The default `observation_id` (1.3.1): the SHA-256, in hex, of what makes an
 * observation one at the NA, its observer sovereign, source and source event
 * ID, joined by NUL characters. One source event gives one ID.
 */
export function observationId(observerSovereignId: string, source: string, sourceEventId: string): string {
  return createHash('sha256').update(`${observerSovereignId}\u0000${source}\u0000${sourceEventId}`, 'utf-8').digest('hex');
}

/**
 * Why a record's values would be refused as secret material, or null (1.3.1):
 * the reference's `metadata_problem`, which the NA applies to observations and
 * break-glass records. Their canonical JSON, non-ASCII escaped as the
 * reference counts it, is at most `MAX_METADATA_BYTES`; then, value by value
 * in the order given, no field named like a secret and no PEM block, key or
 * token.
 */
export function metadataProblem(values: Record<string, unknown>): string | null {
  const size = canonicalJson(values).length;
  if (size > MAX_METADATA_BYTES) return `metadata is ${size} bytes, over the ${MAX_METADATA_BYTES}-byte limit`;
  for (const [name, value] of Object.entries(values)) {
    const nested = typeof value === 'object' && value !== null;
    const found = secretMaterial(nested ? value : { [name]: value }, nested ? `${name}.` : '');
    if (found) return found;
  }
  return null;
}

/** The values of an observation the NA's guard checks: its metadata and the source's own strings. */
function observationValues(record: ObservationRecord): Record<string, unknown> {
  const values: Record<string, unknown> = {
    metadata: record.metadata, actor: record.actor, source_event_id: record.source_event_id, version_id: record.version_id,
  };
  return Object.fromEntries(Object.entries(values).filter(([, v]) => v !== undefined && v !== null));
}

export interface ObservationRecorderOptions {
  /** The sovereign the observer key is registered for. */
  observerSovereignId: string;
  /** The observer key; registered with the NA with `role: "observer"`. */
  signer: Signer;
}

/** Builds and signs observations for one observer. Submit them with `evidenceStore.submitObservation` or keep them in the record outbox. */
export class ObservationRecorder {
  private readonly observerSovereignId: string;
  private readonly signer: Signer;

  constructor(options: ObservationRecorderOptions) {
    this.observerSovereignId = options.observerSovereignId;
    this.signer = options.signer;
  }

  get keyId(): string {
    return this.signer.keyId;
  }

  async record(input: ObservationInput): Promise<ObservationRecord> {
    const window = input.changed_not_before !== undefined || input.changed_not_after !== undefined;
    if (input.changed_at !== undefined && window) {
      throw new OutOfBandRecordError('give changed_at, or the changed_not_before and changed_not_after window, not both',
        'observation_malformed');
    }
    if (input.changed_at === undefined && (input.changed_not_before === undefined || input.changed_not_after === undefined)) {
      throw new OutOfBandRecordError('changed_at, or both changed_not_before and changed_not_after, is required',
        'observation_malformed');
    }
    const time = (value: Date | string | undefined, field: string) => timeOf(value, field, 'observation_malformed');
    const record: ObservationRecord = {
      observation_id: input.observation_id ?? observationId(this.observerSovereignId, input.source, input.source_event_id),
      observer_sovereign_id: this.observerSovereignId,
      resource_id: input.resource_id,
      action: input.action,
      capability: input.capability,
      changed_at: time(input.changed_at, 'changed_at'),
      changed_not_before: time(input.changed_not_before, 'changed_not_before'),
      changed_not_after: time(input.changed_not_after, 'changed_not_after'),
      observed_at: time(input.observed_at ?? new Date(), 'observed_at')!,
      actor: input.actor,
      source: input.source,
      source_event_id: input.source_event_id,
      version_id: input.version_id,
      metadata: input.metadata ?? {},
    };
    // 1.3.1: refused before signing as the NA would refuse it, in its order: JSON it cannot read,
    // a record its model does not take, then secret material.
    checkSignable(record);
    if (!validObservation(record)) {
      const { changed_not_before: from, changed_not_after: to } = record;
      throw new OutOfBandRecordError(from && to && timestampOrder(from, to) > 0
        ? 'changed_not_before is after changed_not_after'
        : 'the observation does not match the ObservationRecord model (a field missing, empty, too long or of another type)',
      'observation_malformed');
    }
    const secret = metadataProblem(observationValues(record));
    if (secret) throw new OutOfBandRecordError(secret, 'observation_secret_material');
    return wire(record, await signCanonical(outOfBandCanonical(record), this.signer));
  }
}

const FINDING_ACTIONS: Partial<Record<ReconciliationStatus, ResourceAction>> = {
  unmanaged: 'create',
  drifted: 'update',
  present_after_revoke: 'update',
  missing: 'delete',
};

export interface FindingObservationOptions {
  capability: string;
  /** The scan before this one: the change happened after it. */
  previousScanAt: Date;
  /** This scan: the change happened before it. */
  scannedAt: Date;
  /** Default `reconciliation`. */
  source?: string;
  /** Override the action recorded for a status (`unmanaged` create, `drifted` update, ...). */
  actions?: Partial<Record<ReconciliationStatus, ResourceAction>>;
}

/**
 * A reconciliation finding as an observation input, or null for a resource in
 * sync. The change is known only within the window between the two scans, so
 * the NA judges it at both ends of the window. The source event is the scan
 * and the resource, so a repeated scan does not record the finding twice:
 * signed again, it is the same record (its `observation_id` is derived from
 * the source event, 1.3.1), and the NA answers `duplicate`.
 */
export function observationFromFinding(
  finding: ReconciliationFinding,
  options: FindingObservationOptions,
): ObservationInput | null {
  const action = (options.actions ?? {})[finding.status] ?? FINDING_ACTIONS[finding.status];
  if (action === undefined) return null;
  const scanned = pythonTimestamp(options.scannedAt);
  return {
    resource_id: finding.resource_id,
    action,
    capability: options.capability,
    changed_not_before: options.previousScanAt,
    changed_not_after: options.scannedAt,
    observed_at: options.scannedAt,
    source: options.source ?? 'reconciliation',
    source_event_id: createHash('sha256').update(`${scanned}\u0000${finding.resource_id}\u0000${finding.status}`).digest('hex'),
    version_id: finding.observed?.version,
    metadata: { status: finding.status, ...(finding.observed?.metadata ?? {}) },
  };
}

// ── Break-glass ──────────────────────────────────────────────────────────────

export interface BreakGlassInput {
  executor_sovereign_id: string;
  resource_id: string;
  resource_action: ResourceAction;
  capability: string;
  attestation_id?: string;
  request_parameters?: Record<string, unknown>;
  attributes?: Record<string, unknown>;
  justification: string;
  /** The evaluation request that failed; only its digest is recorded. */
  evaluation_request: unknown;
  evaluation_failure: EvaluationFailure;
  executed_at?: Date | string;
  outcome: string;
  outcome_detail?: string;
  execution_parameters?: Record<string, unknown>;
}

/** The reference's limits on a break-glass record's justification and outcome detail, in characters (code points). */
const MAX_JUSTIFICATION = 1024;
const MAX_OUTCOME_DETAIL = 1024;

/** The unsigned break-glass record for `input`. */
export function breakGlassRecord(input: BreakGlassInput): BreakGlassRecord {
  return {
    break_glass_id: randomUUID(),
    executor_sovereign_id: input.executor_sovereign_id,
    resource_id: input.resource_id,
    resource_action: input.resource_action,
    capability: input.capability,
    attestation_id: input.attestation_id,
    request_parameters: input.request_parameters ?? {},
    attributes: input.attributes ?? {},
    justification: input.justification,
    evaluation_request_digest: createHash('sha256').update(canonicalJson(input.evaluation_request), 'utf-8').digest('hex'),
    evaluation_failure: input.evaluation_failure,
    executed_at: timeOf(input.executed_at ?? new Date(), 'executed_at', 'break_glass_malformed')!,
    outcome: input.outcome,
    outcome_detail: input.outcome_detail,
    execution_parameters: input.execution_parameters ?? {},
  };
}

/**
 * Throw what the NA would refuse an unsigned break-glass record for, in its
 * order (1.3.1): JSON it cannot read (`StrictJsonError`), a record its model
 * does not take (`break_glass_malformed`; lengths counted in characters, as
 * the reference counts them), then secret material, sized and named as the
 * reference's `metadata_problem` does (`break_glass_secret_material`).
 */
export function checkBreakGlassRecord(record: BreakGlassRecord): void {
  checkSignable(record);
  const characters = (text: unknown) => (typeof text === 'string' ? Array.from(text).length : -1);
  const justification = characters(record.justification);
  if (justification < 1 || justification > MAX_JUSTIFICATION) {
    throw new OutOfBandRecordError(`a justification of 1 to ${MAX_JUSTIFICATION} characters is required`,
      'break_glass_malformed');
  }
  if (record.outcome_detail != null && characters(record.outcome_detail) > MAX_OUTCOME_DETAIL) {
    throw new OutOfBandRecordError(`outcome_detail is longer than ${MAX_OUTCOME_DETAIL} characters`, 'break_glass_malformed');
  }
  if (!validBreakGlass(record)) {
    throw new OutOfBandRecordError(
      'the record does not match the BreakGlassRecord model (a field missing, empty, too long or of another type)',
      'break_glass_malformed');
  }
  const secret = metadataProblem({
    execution_parameters: record.execution_parameters,
    request_parameters: record.request_parameters,
    attributes: record.attributes,
    outcome_detail: record.outcome_detail ?? '',
    justification: record.justification,
  });
  if (secret) throw new OutOfBandRecordError(secret, 'break_glass_secret_material');
}

/** Build and sign a break-glass record with the executor's signer; refused first as the NA would refuse it. */
export async function signBreakGlass(input: BreakGlassInput, signer: Signer): Promise<BreakGlassRecord> {
  const record = breakGlassRecord(input);
  checkBreakGlassRecord(record);
  return wire(record, await signCanonical(outOfBandCanonical(record), signer));
}
