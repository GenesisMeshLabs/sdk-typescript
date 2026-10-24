import {
  timestamp,
  validArchive,
  validBreakGlass,
  validCheckpoint,
  validContext,
  validDecision,
  validEvent,
  validExecution,
  validJudgement,
  validJustification,
  validKeySuccession,
  validObservation,
  validQuarantine,
  validRegistry,
  validRemediation,
  validReview,
} from './validation.js';
/**
 * Offline verification of NA-signed artifacts and evidence exports.
 * Direct ports of the Python reference with the same reason codes:
 *   verifyBoundaryDecision  - trust/context/decisions.py verify_boundary_decision
 *   verifyEvidenceEvents    - trust/evidence_store.py verify_evidence_events
 * No network access; every key is supplied by the caller.
 *
 * v1.5.0: wherever NA keys are taken (`NAKeys`), a list is valid at every time
 * (the behaviour before 1.5.0) and the NA's key history (`verifyKeyHistory`)
 * accepts a signature only by the key valid at the record's own time, with the
 * 300-second hand-over (src/key-history.ts).
 */

import { canonicalJson, compareCodePoints, copyPythonFloats, defineMember, parseJson, verifyCanonical } from './auth.js';
import {
  outOfBandCanonical,
  type BreakGlassRecord,
  type JudgementRecord,
  type ObservationRecord,
  type QuarantineRecord,
  type RegistryRecord,
} from './out-of-band.js';
import {
  reviewApprovalProblem, reviewHolderProblem, rotationProblem, type RemediationRecord, type ReviewRecord,
} from './remediation.js';
import {
  continuesChain, grantRecordDigest, nextPreviousUse, tokenSignatureValid, useProblem, validGrant, validGrantRevocation,
  validGrantUse, type CapabilityGrant, type GrantExecutionEvidence, type GrantRevocationRecord, type PreviousUse,
  type UseChainHead,
} from './grants.js';
import {
  NAKeyHistory, RECORD_TIME_TOLERANCE_SECONDS, SUCCESSION_MIN_LEAD_SECONDS, decisionOutlivesKey, naKeysAt,
  naKeysVouchingAt, naSignatureAt,
  successionDigest, successionSignedBy, type KeySuccessionRecord, type NAKeys,
} from './key-history.js';
import {
  isKnownEntryKind, nonCanonicalFields, signedAsReceived as signedAsReceivedBy, strictRefusal, unknownFields,
  withoutUnknownFields,
} from './strict.js';
import {
  agreementCanonical,
  attestationCanonical,
  attestationDigest,
  checkpointCanonical,
  dataAccessIntentCanonical,
  dataLicensePolicyCanonical,
  decisionCanonical,
  entryDigest,
  executionCanonical,
  executionDigest,
  freshnessProofCanonical,
  justificationCanonical,
  payloadDigest,
  policyCanonical,
  policyDigest,
  policySetDigest,
  revocationFeedCanonical,
} from './canonical.js';
import type {
  AgreementRecord,
  DataAccessIntent,
  DataLicensePolicy,
  BoundaryDecision,
  BoundaryPolicy,
  BoundaryVerification,
  BoundaryVerificationReason,
  ContextRecord,
  DecisionJustification,
  EntryKind,
  EvidenceEvent,
  EvidenceStoreVerification,
  ExecutionEvidence,
  MembershipAttestation,
  ResourceHead,
  RetentionCheckpoint,
  Signature,
  SovereignRevocationFeed,
} from './types.js';

// ── Time ──────────────────────────────────────────────────────────────────────

/** Microseconds since the epoch for an ISO 8601 timestamp, keeping Python's microsecond precision. */
export function parseTimestampMicros(value: string): number {
  if (!timestamp(value)) throw new Error(`not an ISO 8601 timestamp: ${value}`);
  const match = /^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})?$/.exec(value);
  if (!match) throw new Error(`not an ISO 8601 timestamp: ${value}`);
  const [, base, fraction = '', zone = 'Z'] = match;
  const ms = Date.parse(base + zone);
  if (Number.isNaN(ms)) throw new Error(`not an ISO 8601 timestamp: ${value}`);
  return ms * 1000 + Number(fraction.padEnd(6, '0').slice(0, 6));
}

function micros(value: Date | string): number {
  return typeof value === 'string' ? parseTimestampMicros(value) : value.getTime() * 1000;
}

// ── Signatures ────────────────────────────────────────────────────────────────

function signedBy(canonical: string, signature: Signature | null | undefined, keys: readonly string[]): boolean {
  return !!signature && typeof signature.sig === 'string' && verifyCanonical(canonical, signature.sig, keys);
}

/**
 * The registered key a signature names (1.3.1): own entries only, so a
 * `key_id` such as `constructor` names no key instead of a built-in.
 */
function keyNamed(keys: Record<string, ExecutorKeyInfo>, keyId: unknown): ExecutorKeyInfo | undefined {
  return typeof keyId === 'string' && Object.hasOwn(keys, keyId) ? keys[keyId] : undefined;
}

/** The signatures a `signatures` field holds: a list, as every implementation reads it (1.3.1); anything else holds none. */
function signatureList(signatures: unknown): Signature[] {
  return Array.isArray(signatures) ? signatures : [];
}

function anySigned(canonical: string, signatures: readonly Signature[] | undefined, keys: readonly string[]): boolean {
  return signatureList(signatures).some(sig => typeof sig?.sig === 'string' && verifyCanonical(canonical, sig.sig, keys));
}

// Since v1.2.0 a record with a signed field this SDK does not know never
// verifies (src/strict.ts): a field it cannot read could change the record's meaning.

function decisionSigned(decision: BoundaryDecision, publicKeys: readonly string[]): boolean {
  return signedBy(decisionCanonical(decision), decision.signature, publicKeys);
}

/**
 * True when the decision signature verifies under one of the operator (NA)
 * keys (v1.5.0: given the key history, the key valid at `decision_made_at`).
 */
export function verifyDecisionSignature(decision: BoundaryDecision, publicKeys: NAKeys): boolean {
  return decisionSigned(decision, naKeysAt(publicKeys, decision.decision_made_at))
    && unknownFields('BoundaryDecision', decision).length === 0;
}

/**
 * 1.8.0: judging a record for the present. With `now` and the NA's key
 * history, a key whose vouching horizon has passed by `now` no longer counts
 * (`naKeysVouchingAt`); without it the record is judged at its own time.
 */
export interface VouchingOptions {
  /** The time the record is judged at; absent, it is judged at its own time only. */
  now?: string | Date;
}

function keysFor(publicKeys: NAKeys, time: string, options: VouchingOptions): string[] {
  return options.now === undefined ? naKeysAt(publicKeys, time) : naKeysVouchingAt(publicKeys, time, options.now);
}

/**
 * True when any attestation signature verifies under the issuer keys (v1.5.0:
 * given the NA's key history, the key valid at `issued_at`; 1.8.0: with
 * `options.now`, a key still vouching then).
 */
export function verifyAttestationSignature(
  attestation: MembershipAttestation, publicKeys: NAKeys, options: VouchingOptions = {},
): boolean {
  return unknownFields('MembershipAttestation', attestation).length === 0
    && anySigned(attestationCanonical(attestation), attestation.signatures, keysFor(publicKeys, attestation.issued_at, options));
}

/** v1.5.0: given the NA's key history, signed by the key valid at the policy's `issued_at`. */
export function verifyPolicySignature(policy: BoundaryPolicy, publicKeys: NAKeys): boolean {
  return unknownFields('BoundaryPolicy', policy).length === 0
    && signedBy(policyCanonical(policy), policy.signature, naKeysAt(publicKeys, policy.issued_at));
}

/** v1.5.0: given the NA's key history, signed by the key valid at `proof_issued_at`. */
export function verifyJustificationSignature(proof: DecisionJustification, publicKeys: NAKeys): boolean {
  return unknownFields('JustificationProof', proof).length === 0
    && signedBy(justificationCanonical(proof), proof.signature, naKeysAt(publicKeys, proof.proof_issued_at));
}

/**
 * v1.5.0: given the NA's key history, signed by the key valid at the feed's
 * `issued_at`; 1.8.0: with `options.now`, by a key still vouching then.
 */
export function verifyRevocationFeedSignature(
  feed: SovereignRevocationFeed, publicKeys: NAKeys, options: VouchingOptions = {},
): boolean {
  return unknownFields('SovereignRevocationFeed', feed).length === 0
    && anySigned(revocationFeedCanonical(feed), feed.signatures, keysFor(publicKeys, feed.issued_at, options));
}

/** The NA key that signed a revocation feed at its `issued_at` (1.8.0), or `undefined`. */
export function revocationFeedSigner(feed: SovereignRevocationFeed, publicKeys: NAKeys): string | undefined {
  return naKeysAt(publicKeys, feed.issued_at).find(k => anySigned(revocationFeedCanonical(feed), feed.signatures, [k]));
}

function checkpointSigned(checkpoint: RetentionCheckpoint, publicKeys: readonly string[]): boolean {
  return signedBy(checkpointCanonical(checkpoint), checkpoint.signature, publicKeys);
}

/** v1.5.0: given the NA's key history, signed by the key valid at the checkpoint's `created_at`. */
export function verifyRetentionCheckpoint(checkpoint: RetentionCheckpoint, publicKeys: NAKeys): boolean {
  return checkpointSigned(checkpoint, naKeysAt(publicKeys, checkpoint.created_at))
    && unknownFields('RetentionCheckpoint', checkpoint).length === 0;
}

/** A recognition treaty (v1.5.0): the NA's trust in another sovereign's keys. */
export interface RecognitionTreaty {
  treaty_id: string;
  issuer_sovereign_id: string;
  subject_sovereign_id: string;
  subject_public_keys: string[];
  scope: Record<string, unknown>;
  status: string;
  issued_at: string;
  valid_from: string;
  expires_at: string;
  issued_by: string;
  metadata: Record<string, unknown>;
  signatures: Signature[];
}

/** The signed form of a recognition treaty: every field but `signatures`, as received. */
export function treatyCanonical(treaty: RecognitionTreaty): string {
  const body: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(treaty)) {
    if (key !== 'signatures' && value !== undefined) defineMember(body, key, value);
  }
  copyPythonFloats(treaty, body);
  return canonicalJson(body);
}

/**
 * True when a treaty signature verifies under the issuer keys (v1.5.0): given
 * the NA's key history, the key valid at the treaty's `issued_at`, so a key
 * succession leaves every treaty signed before it vouching at its own time.
 * 1.8.0: with `options.now`, only while that key still vouches.
 */
export function verifyTreatySignature(
  treaty: RecognitionTreaty, publicKeys: NAKeys, options: VouchingOptions = {},
): boolean {
  return anySigned(treatyCanonical(treaty), treaty.signatures, keysFor(publicKeys, treaty.issued_at, options));
}

/** True when the record's signature verifies under the executor's public key. */
export function verifyExecutionSignature(evidence: ExecutionEvidence, executorPublicKey: string): boolean {
  return unknownFields('ExecutionEvidence', evidence).length === 0
    && signedBy(executionCanonical(evidence), evidence.signature, [executorPublicKey]);
}

// ── Boundary decisions ────────────────────────────────────────────────────────

const ATTESTATION_GATE_NAMES = new Set(['attestation_status', 'attestation_validity']);
const BUILTIN_GATE_NAMES = new Set([
  'capability_check', 'validity_window', 'freshness_check', 'freshness_proof', ...ATTESTATION_GATE_NAMES,
]);

export interface VerifyDecisionOptions {
  /**
   * NA keys that may sign decisions. v1.5.0: given the NA's key history, the
   * decision must be signed by the key valid at its `decision_made_at`
   * (`na_key_not_valid_at_time` for another key of the history).
   */
  operatorPublicKeys: NAKeys;
  /** When set and the decision embeds a FreshnessProof, the proof must verify under these keys. */
  freshnessProofIssuerKeys?: readonly string[];
  now?: Date;
  /** The decision must bind exactly these policy versions, in resolution order. */
  expectedPolicies?: readonly BoundaryPolicy[];
  /** The decision must bind this attestation: id, subject, issuer and digest. */
  expectedAttestation?: MembershipAttestation;
  /**
   * v1.5.0: judge the decision as of its own time (`decision_made_at`), not
   * `now`: an archived decision, verified in an audit years later, was valid
   * when it was made and used, and its expiry since says nothing against it.
   */
  atRecordTime?: boolean;
}

/** Verify a decision's signature, expiry and bindings offline. */
export function verifyBoundaryDecision(
  decision: BoundaryDecision,
  options: VerifyDecisionOptions,
): BoundaryVerification {
  const result = (accepted: boolean, reason: BoundaryVerificationReason, authorized = decision?.authorized === true) =>
    ({ accepted, reason, decision_id: decision?.decision_id ?? null, authorized });
  const reject = (reason: BoundaryVerificationReason) => result(false, reason);

  if (!validDecision(decision)) return reject('payload_invalid');
  if (!Number.isFinite((options.now ?? new Date()).getTime())) return reject('payload_invalid');
  if (!decision.signature) return reject('missing_signature');
  const now = options.atRecordTime ? micros(decision.decision_made_at) : micros(options.now ?? new Date());
  if (now > micros(decision.decision_valid_until)) return reject('decision_expired');
  const signed = naSignatureAt(keys => decisionSigned(decision, keys), options.operatorPublicKeys, decision.decision_made_at);
  if (signed !== 'ok') return reject(signed);
  // v1.5.0: a key with an end vouches for a decision only as long as the longest lifetime the NA
  // issues past that end (and the hand-over).
  const signer = naKeysAt(options.operatorPublicKeys, decision.decision_made_at).find(k => decisionSigned(decision, [k]));
  if (signer !== undefined && decisionOutlivesKey(options.operatorPublicKeys, signer, decision.decision_valid_until)) {
    return reject('decision_outlives_key');
  }
  // v1.2.0: an authentic decision with a signed field this SDK does not know, or
  // expected inputs it cannot read, is refused by name: upgrade this SDK.
  if (
    unknownFields('BoundaryDecision', decision).length > 0
    || (options.expectedPolicies ?? []).some(p => unknownFields('BoundaryPolicy', p).length > 0)
    || (options.expectedAttestation !== undefined
      && unknownFields('MembershipAttestation', options.expectedAttestation).length > 0)
  ) {
    return reject('unknown_field');
  }
  // v1.2.0: a decision signed over a form the reference does not write.
  if (nonCanonicalFields('BoundaryDecision', decision).length > 0) return reject('non_canonical_form');

  const proof = decision.freshness_proof;
  if (proof && options.freshnessProofIssuerKeys && options.freshnessProofIssuerKeys.length > 0) {
    if (!signedBy(freshnessProofCanonical(proof), proof.signature, options.freshnessProofIssuerKeys)) {
      return reject('freshness_proof_invalid_signature');
    }
    if (micros(proof.proof_valid_until) < micros(decision.decision_made_at)) return reject('freshness_proof_expired');
  }

  const binding = decision.policy_binding ?? null;
  if (options.expectedPolicies) {
    if (!binding) return reject('policy_binding_missing');
    const expected = [...options.expectedPolicies]
      .sort((a, b) => (compareCodePoints(a.policy_id, b.policy_id) || a.version - b.version))
      .map(p => `${p.policy_id}\u0000${p.version}\u0000${policyDigest(p)}`);
    const bound = binding.policies.map(a => `${a.policy_id}\u0000${a.version}\u0000${a.policy_digest}`);
    if (expected.join('\n') !== bound.join('\n') || policySetDigest(binding.policies) !== binding.policy_set_digest) {
      return reject('policy_binding_mismatch');
    }
  }

  const attestationBinding = decision.attestation_binding ?? null;
  const expectedAttestation = options.expectedAttestation;
  if (expectedAttestation) {
    if (!attestationBinding) return reject('attestation_binding_missing');
    if (
      attestationBinding.attestation_id !== expectedAttestation.attestation_id
      || attestationBinding.subject_id !== expectedAttestation.subject_id
      || attestationBinding.issuer_sovereign_id !== expectedAttestation.issuer_sovereign_id
      || attestationBinding.attestation_digest !== attestationDigest(expectedAttestation)
    ) {
      return reject('attestation_binding_mismatch');
    }
  }

  if (!decision.authorized) {
    const failed = decision.gate_results.filter(g => !g.passed);
    if (failed.some(g => ATTESTATION_GATE_NAMES.has(g.gate_name))) {
      return result(true, 'unauthorized_attestation_basis', false);
    }
    const builtinFailed = failed.some(g => BUILTIN_GATE_NAMES.has(g.gate_name));
    if (binding && !builtinFailed && (
      binding.resolution_status === 'failed'
      || binding.gate_evaluations.some(e => e.mode === 'enforce' && !e.passed)
    )) {
      return result(true, binding.resolution_status === 'failed'
        ? 'unauthorized_policy_resolution_failed'
        : 'unauthorized_policy_gate_failure', false);
    }
    const denial = decision.denial_reason ?? '';
    if (denial.includes('capability')) return result(true, 'unauthorized_capability_out_of_scope', false);
    if (denial.includes('validity') || denial.includes('window')) {
      return result(true, 'unauthorized_outside_validity_window', false);
    }
    if (denial.includes('freshness')) return result(true, 'unauthorized_insufficient_freshness', false);
    return result(true, 'unauthorized_gate_failure', false);
  }
  return result(true, 'authorized', true);
}

// ── Evidence store export ─────────────────────────────────────────────────────

/** A registered executor key, as listed by `GET /admin/evidence/executor-keys`. */
export interface ExecutorKeyInfo {
  key_id: string;
  public_key: string;
  executor_sovereign_id: string;
  /**
   * v1.3.0: `executor` (the default) signs execution evidence and break-glass
   * records; `observer` signs observations only.
   */
  role?: 'executor' | 'observer';
  /** v1.3.0: the key signs only for resources under this prefix (checked by the NA at admission). */
  resource_prefix?: string | null;
  /**
   * v1.5.0: where the store registered and retired the key, for a key read
   * from its registry records (as an audit pack places it): by store position,
   * or by time for a record backfilled at an upgrade or carried past
   * retention. A record verifies only with a key registered before it and not
   * retired before it (`evidence_unknown_executor`,
   * `evidence_executor_key_retired`). A key supplied without them is not placed.
   */
  registered_sequence?: number | null;
  registered_at_time?: string | null;
  retired_sequence?: number | null;
  retired_at_time?: string | null;
}

/** Why a record at this store position and time may not carry this key's signature, or null (v1.5.0). */
export function keyPlacementProblem(key: ExecutorKeyInfo, storeSequence: number, recordedAt: string): string | null {
  const registeredSequence = key.registered_sequence ?? null;
  const registeredAt = key.registered_at_time ?? null;
  if (registeredSequence === null && registeredAt === null) return null;
  const at = micros(recordedAt);
  const registered = (registeredSequence !== null && registeredSequence < storeSequence)
    || (registeredAt !== null && micros(registeredAt) <= at);
  if (!registered) return 'evidence_unknown_executor';
  const retiredSequence = key.retired_sequence ?? null;
  const retiredAt = key.retired_at_time ?? null;
  const retired = (retiredSequence !== null && retiredSequence < storeSequence)
    || (retiredAt !== null && micros(retiredAt) <= at);
  return retired ? 'evidence_executor_key_retired' : null;
}

/** v1.5.0: the kinds retention appends again after its checkpoint, each with the time it was first recorded. */
export const CARRIED_KINDS: ReadonlySet<string> = new Set(['registry', 'key_succession', 'archive']);

/**
 * Store positions of the entries retention carried forward (v1.5.0): entries
 * of `CARRIED_KINDS` in an unbroken run of positions right after a retention
 * checkpoint entry.
 */
export function carriedSequences(events: Iterable<EvidenceEvent>): Set<number> {
  const out = new Set<number>();
  let previous: EvidenceEvent['entry'] | null = null;
  let carrying = false;
  for (const event of [...events].sort((a, b) => a.entry.store_sequence - b.entry.store_sequence)) {
    const entry = event.entry;
    const adjacent = previous !== null && entry.store_sequence === previous.store_sequence + 1;
    carrying = CARRIED_KINDS.has(entry.entry_kind) && adjacent && previous !== null
      && (previous.entry_kind === 'retention_checkpoint' || carrying);
    if (carrying) out.add(entry.store_sequence);
    previous = entry;
  }
  return out;
}

/** An instant as the reference writes it in reports: UTC, six fraction digits when not zero, `Z`. */
export function isoMicros(value: number): string {
  const ms = Math.floor(value / 1000);
  const fraction = value - ms * 1000;
  const base = new Date(ms).toISOString().slice(0, 19);
  const micro = (ms % 1000 + 1000) % 1000 * 1000 + fraction;
  return `${base}${micro === 0 ? '' : `.${String(micro).padStart(6, '0')}`}Z`;
}

function keysAtMicros(keys: NAKeys, when: number): string[] {
  return keys instanceof NAKeyHistory ? keys.keysAtMicros(when) : [...keys];
}

export interface VerifyEvidenceOptions {
  /**
   * NA keys that sign decisions, justification proofs, retention checkpoints
   * and the NA's other records. v1.5.0: given the NA's key history
   * (`verifyKeyHistory`), each record must be signed by the key valid at its
   * entry's `recorded_at` (`na_key_not_valid_at_time` for another key of the
   * history), and a `key_succession` entry must be one of the history's
   * successions (`succession_not_in_history`). A list of keys is valid at
   * every time.
   */
  naPublicKeys: NAKeys;
  /** Executor keys by key_id, or the list returned by the NA (retired keys still verify old records). */
  executorKeys: Record<string, ExecutorKeyInfo> | readonly ExecutorKeyInfo[];
  /**
   * True for an unbroken run of the store (an export or the whole store); false
   * for a filtered history, where store links are checked only between adjacent
   * positions. Default true.
   */
  contiguous?: boolean;
  /** Resource heads for chains whose early records were removed by retention. */
  checkpoint?: RetentionCheckpoint | null;
  /**
   * v1.5.0: an audit pack's cited records, outside the run. They seed what the
   * run's records rest on (their decisions, subjects and matched records, and
   * the heads of the chains the run continues) and are verified for
   * authenticity but not as a run; the run then holds every chain from its
   * start, and a record it cites that neither holds is `cited_record_missing`.
   */
  prior?: Iterable<EvidenceEvent> | null;
}

const JSON_SPACE = ' \t\r\n';

/** `s` without JSON whitespace at either end, as every implementation trims a line (`trim()` also removes other spaces). */
function trimJsonSpace(s: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && JSON_SPACE.includes(s[start]!)) start++;
  while (end > start && JSON_SPACE.includes(s[end - 1]!)) end--;
  return s.slice(start, end);
}

/** Parse `gm.evidence.event` JSON Lines (blank lines ignored). */
export function parseExportLines(text: string | Iterable<string>): EvidenceEvent[] {
  const lines = typeof text === 'string' ? text.split('\n') : text;
  const events: EvidenceEvent[] = [];
  for (const raw of lines) {
    const line = trimJsonSpace(raw);
    if (!line) continue;
    const event = parseJson(line) as EvidenceEvent;
    if (!validEvent(event)) throw new Error('invalid evidence event envelope or unsupported schema');
    events.push(event);
  }
  return events;
}

/** Entry kinds counted only when a run holds them (v1.3.0, v1.4.0, v1.5.0, v1.6.0). */
const COUNTED = ['observations', 'break_glass', 'judgements', 'quarantined', 'remediations', 'reviews',
  'key_successions', 'archives', 'grants', 'grant_executions', 'grant_revocations'] as const;
type Counts = Record<(typeof COUNTED)[number], number>;

/** Verify stored entries: envelopes, the store chain, every signature, and the decision and resource chains. */
export function verifyEvidenceEvents(
  events: Iterable<EvidenceEvent>,
  options: VerifyEvidenceOptions,
): EvidenceStoreVerification {
  const result: EvidenceStoreVerification = { verified: true, checked_entries: 0, decisions: 0, executions: 0, failures: [] };
  const failOn = (target: EvidenceStoreVerification): Fail => (storeSequence, reason, detail = '') => {
    target.verified = false;
    target.failures.push({ store_sequence: storeSequence, reason, detail });
  };
  const warnOn = (target: EvidenceStoreVerification): Fail => (storeSequence, reason, detail = '') => {
    (target.warnings ??= []).push({ store_sequence: storeSequence, reason, detail });
  };
  const executorKeys: Record<string, ExecutorKeyInfo> = Array.isArray(options.executorKeys)
    ? Object.fromEntries((options.executorKeys as readonly ExecutorKeyInfo[]).map(k => [k.key_id, k]))
    : options.executorKeys as Record<string, ExecutorKeyInfo>;
  const contiguous = options.contiguous ?? true;
  const checkpoint = options.checkpoint ?? null;
  const naKeys = options.naPublicKeys;
  const allNaKeys = naKeysAt(naKeys, null);
  const history = naKeys instanceof NAKeyHistory ? naKeys : null;
  // v1.5.0: the successions a key history with its root key holds, by digest.
  const successions = history?.root_public_key ? new Set(history.successions.map(successionDigest)) : null;

  const decisions = new Map<string, BoundaryDecision>();
  const contexts = new Map<string, ContextRecord>();
  const lastExec = new Map<string, ExecutionEvidence>();
  const resourceHeads = new Map<string, ResourceHead>(Object.entries(checkpoint?.resource_heads ?? {}));
  // v1.3.0: observation positions per resource, judged records, matched evidence.
  const observationHeads = new Map<string, number>(Object.entries(checkpoint?.observation_heads ?? {}));
  // v1.3.1: judgement subjects and judged records by kind and ID.
  const subjects = new Map<string, { digest: string; sequence: number }>();
  const judged = new Set<string>();
  const matched = new Set<string>();
  const notDecisions = new Set<string>();
  // v1.3.1: the record IDs seen per kind, the records a judgement can match, and the checkpoints seen.
  const recordIds = new Map<string, Set<string>>();
  const matchable = new Set<string>();
  const checkpoints = new Map<string, RetentionCheckpoint>();
  // v1.4.0: judgements and decisions by ID (payload digest, resource), execution evidence's resources,
  // remediated subjects, and operator keys as the holder registry records them.
  const judgedRecords = new Map<string, JudgedSubject>();
  const executed = new Map<string, HeldExecution>();
  const remediated = new Set<string>();
  const operatorKeys = new Map<string, OperatorKeyRecord[]>();
  // v1.4.0 (review fixes): the version each observation or break-glass record names, and the forward
  // rotations remediations already cite.
  const versions = new Map<string, string | null>();
  const cited = new Set<string>();
  // v1.6.0: grants by ID (the record and its digest as received; an authentic grant only), when each
  // was revoked (the first authentic revocation), the head of each grant's use chain (an admitted use,
  // or a quarantined one that continued it), its last admitted use, how many uses were admitted (when
  // the chain is held from its first use), each chain use's digest and time by grant and position, and
  // the IDs of uses and of the other records observations match by ID.
  const grantsHeld = new Map<string, { grant: CapabilityGrant; digest: string }>();
  const revoked = new Map<string, string>();
  const chainHeads = new Map<string, UseChainHead>();
  const lastAdmitted = new Map<string, PreviousUse>();
  const admittedUses = new Map<string, number>();
  const useHeads = new Map<string, { digest: string; executed_at: string }>();
  const useIds = new Set<string>();
  const otherMatchable = new Set<string>();
  let firstSequence: number | null = null;
  let fromStart = false;
  let prev: EvidenceEvent['entry'] | null = null;
  // v1.5.0: with `prior` (an audit pack's cited records) every record the run cites is supplied,
  // and the chains continue from the records it holds.
  const pack = options.prior !== undefined && options.prior !== null;
  // v1.5.0: the latest recorded_at so far in the run (microseconds), and whether the entries just
  // visited are a block retention carried forward.
  let clock: number | null = null;
  let carrying = false;
  // v1.5.0: the chains a checkpoint removed continue from its heads.
  const seedHeads = (cp: RetentionCheckpoint) => {
    for (const [rid, head] of Object.entries(cp.resource_heads ?? {})) {
      const held = resourceHeads.get(rid);
      if (held === undefined || held.resource_sequence < head.resource_sequence) resourceHeads.set(rid, head);
    }
    for (const [rid, position] of Object.entries(cp.observation_heads ?? {})) {
      if ((observationHeads.get(rid) ?? 0) < position) observationHeads.set(rid, position);
    }
  };

  if (checkpoint && (!validCheckpoint(checkpoint) || !checkpointSigned(checkpoint, naKeysAt(naKeys, checkpoint.created_at)))) {
    failOn(result)(null, 'invalid_signature', 'retention_checkpoint');
    return result;
  }
  if (checkpoint && unknownFields('RetentionCheckpoint', checkpoint).length > 0) {
    failOn(result)(null, 'unknown_field', unknownFields('RetentionCheckpoint', checkpoint).map(f => `checkpoint.${f}`).join(', '));
    return result;
  }

  /** Verify one event into `target`; `citedRun` for a pack's cited records, which are not a run. */
  const visit = (event: EvidenceEvent, target: EvidenceStoreVerification, counts: Counts, citedRun: boolean) => {
    const fail = failOn(target);
    const warn = warnOn(target);
    if (!validEvent(event)) {
      target.checked_entries += 1;
      fail(null, 'payload_invalid', 'event envelope');
      return;
    }
    const entry = event.entry;
    const seq = entry.store_sequence;
    target.checked_entries += 1;
    // v1.5.0: in a contiguous run an entry is not recorded more than the tolerance before an earlier one
    // (carried entries keep their first time), and an NA key must also be valid at the latest earlier time.
    let notBefore: number | null = null;
    if (contiguous && !citedRun) {
      const adjacent = prev !== null && seq === prev.store_sequence + 1;
      carrying = CARRIED_KINDS.has(entry.entry_kind) && adjacent && prev !== null
        && (prev.entry_kind === 'retention_checkpoint' || carrying);
      if (!carrying) {
        const at = micros(entry.recorded_at);
        if (clock !== null && at < clock - RECORD_TIME_TOLERANCE_SECONDS * 1_000_000) {
          fail(seq, 'recorded_at_out_of_order', `recorded at ${isoMicros(at)}, after an entry recorded at ${isoMicros(clock)}`);
        }
        notBefore = clock;
        clock = clock === null || at > clock ? at : clock;
      }
    }
    if (entryDigest(entry) !== event.entry_digest) fail(seq, 'entry_digest_mismatch');
    if (payloadDigest(event.payload) !== entry.payload_digest) fail(seq, 'payload_digest_mismatch');
    const linked = contiguous && !citedRun;
    if (prev && (linked || seq === prev.store_sequence + 1)) {
      if (seq !== prev.store_sequence + 1) fail(seq, 'store_sequence_gap');
      else if (entry.prev_entry_digest !== entryDigest(prev)) fail(seq, 'store_chain_break');
    } else if (!prev && checkpoint && seq === checkpoint.removed_through_sequence + 1) {
      if (entry.prev_entry_digest !== checkpoint.last_removed_entry_digest) {
        fail(seq, 'store_chain_break', 'does not continue from the checkpoint');
      }
    }
    if (firstSequence === null && !citedRun) {
      firstSequence = seq;
      fromStart = pack || seq === 1 || (checkpoint !== null && seq === checkpoint.removed_through_sequence + 1);
    }
    prev = entry;
    const kind = entry.entry_kind;
    const validPayload = isKnownEntryKind(kind) && Object.hasOwn(PAYLOAD_CHECKS, kind) ? PAYLOAD_CHECKS[kind] : undefined;
    if (!validPayload) {
      // v1.2.0: a kind from a later release; its envelope still chains.
      fail(seq, 'unknown_entry_kind', String(kind));
      return;
    }

    const checked = checkPayloadFields(kind, event.payload, allNaKeys, history?.root_public_key ?? null, executorKeys);
    if (checked.signed.length > 0) {
      fail(seq, 'unknown_field', checked.signed.join(', '));
      return;
    }
    if (checked.unsigned.length > 0) warn(seq, 'unsigned_field', checked.unsigned.join(', '));
    if (checked.unsigned.length > 0
      && (isOutOfBand(kind) || kind === 'key_succession' || kind === 'retention_checkpoint')) {
      // v1.3.0: the reference stores these records exactly as signed; a field outside the
      // signature is no part of one (the reference refuses it as it reads the record).
      // v1.5.0: a retention checkpoint too.
      fail(seq, 'payload_invalid', checked.unsigned.join(', '));
      return;
    }
    const payload = checked.payload;
    if (!validPayload(payload)) {
      fail(seq, 'payload_invalid');
      return;
    }
    const record = (kind === 'decision' ? payload['decision'] : payload) as Record<string, unknown>;
    // v1.3.0: a record whose signature covers it as received, in a form the reference
    // does not write, is refused by name, as the reference refuses it. v1.3.1: also when
    // fields outside the signature were set aside: what the signer signed is checked.
    const signature = (signed: boolean, model: string) => {
      if (!signed) fail(seq, 'invalid_signature', kind);
      else if (nonCanonicalFields(model, record).length > 0) fail(seq, 'non_canonical_form', kind);
    };
    // v1.5.0: an NA signature by the key valid at the entry's `recorded_at` (and at the latest earlier
    // time in the run); by another key of the history, `na_key_not_valid_at_time` (a form the reference
    // does not write is named first). Returns the keys valid then when the signature is accepted.
    const naSignature = (signedBy: (keys: readonly string[]) => boolean, model: string): readonly string[] | null => {
      const recordedAt = micros(entry.recorded_at);
      let valid = keysAtMicros(naKeys, recordedAt);
      if (notBefore !== null && notBefore > recordedAt) {
        const later = new Set(keysAtMicros(naKeys, notBefore));
        valid = valid.filter(k => later.has(k));
      }
      const loose = nonCanonicalFields(model, record).length > 0;
      if (signedBy(valid)) {
        signature(true, model);
        return loose ? null : valid;
      }
      const others = allNaKeys.filter(k => !valid.includes(k));
      if (others.length > 0 && signedBy(others)) fail(seq, loose ? 'non_canonical_form' : 'na_key_not_valid_at_time', kind);
      else fail(seq, 'invalid_signature', kind);
      return null;
    };
    // v1.5.0: a key-signed record verifies only with a key registered before it and not retired before it.
    const misplaced = (key: ExecutorKeyInfo | undefined): boolean => {
      const problem = key ? keyPlacementProblem(key, seq, entry.recorded_at) : null;
      if (problem !== null) fail(seq, problem, `${kind} signed by ${key!.key_id}`);
      return problem !== null;
    };
    // v1.3.1: a record's ID appears once per kind: a copy is a replay, still checked like any record.
    const recordId = String(record[RECORD_ID[kind]]);
    const seen = recordIds.get(kind) ?? new Set<string>();
    if (seen.has(recordId)) fail(seq, 'duplicate_record', `${kind} ${recordId}`);
    recordIds.set(kind, seen.add(recordId));
    // v1.3.1: a Stage 2 entry's envelope names what its record says (an absent field is null).
    const envelopeFields = entry as unknown as Record<string, unknown>;
    const wrong = Object.entries(ENVELOPE_FIELDS[kind])
      .filter(([field, recordField]) => (envelopeFields[field] ?? null) !== (payload[recordField] ?? null))
      .map(([field]) => field);
    if (wrong.length > 0) fail(seq, 'envelope_mismatch', `${kind}: ${wrong.join(', ')}`);
    // Checks that need a record's predecessors in the run; a pack's cited records are not a run.
    const chained = !citedRun;
    switch (kind) {
      case 'decision': {
        const model = record as unknown as BoundaryDecision;
        const valid = naSignature(keys => decisionSigned(model, keys), 'BoundaryDecision');
        // v1.5.0: valid longer than the key that signed it may vouch for.
        const signer = valid?.find(k => decisionSigned(model, [k]));
        if (signer !== undefined && decisionOutlivesKey(naKeys, signer, model.decision_valid_until)) {
          fail(seq, 'decision_outlives_key', model.decision_id);
        }
        target.decisions += 1;
        decisions.set(model.decision_id, model);
        judgedRecords.set(model.decision_id, { digest: entry.payload_digest, resource: null });
        const context = payload['context'];
        if (validContext(context)) {
          contexts.set(model.decision_id, context as unknown as ContextRecord);
        } else {
          fail(seq, 'payload_invalid', 'context');
        }
        break;
      }
      case 'justification':
        naSignature(keys => verifyJustificationSignature(payload as unknown as DecisionJustification, keys),
          'JustificationProof');
        break;
      case 'execution': {
        const ev = payload as unknown as ExecutionEvidence;
        const key = keyNamed(executorKeys, ev.signature?.key_id);
        // v1.3.0: only an executor key signs execution evidence.
        const fits = !!key && key.executor_sovereign_id === ev.executor_sovereign_id && (key.role ?? 'executor') === 'executor';
        if (!fits || !misplaced(key)) {
          signature(fits && verifyExecutionSignature(ev, key!.public_key), 'ExecutionEvidence');
        }
        target.executions += 1;
        const decision = decisions.get(ev.decision_id);
        if (decision) {
          const context = contexts.get(ev.decision_id);
          const at = micros(ev.executed_at);
          if (!decision.authorized) fail(seq, 'evidence_decision_denied');
          else if (at < micros(decision.decision_made_at) || at > micros(decision.decision_valid_until)) {
            fail(seq, 'evidence_outside_decision_window');
          } else if (context && ev.executed_capability !== context.requested_capability) {
            fail(seq, 'evidence_capability_mismatch');
          }
        } else if (pack && chained) {
          // v1.5.0: a pack holds the decision every execution in its range rests on.
          fail(seq, 'cited_record_missing', `decision ${ev.decision_id}`);
        }
        // v1.3.0: execution evidence never rests on a judgement or a record of one.
        if (notDecisions.has(ev.decision_id)) fail(seq, 'evidence_cites_judgement', ev.decision_id);
        const prior = lastExec.get(ev.decision_id);
        if (chained && prior) {
          if (ev.sequence_no !== prior.sequence_no + 1 || (ev.prev_evidence_digest ?? null) !== executionDigest(prior)) {
            fail(seq, 'evidence_chain_break');
          }
        } else if (chained && !prior && decision && (ev.sequence_no !== 1 || (ev.prev_evidence_digest ?? null) !== null)) {
          fail(seq, 'evidence_chain_break');
        }
        lastExec.set(ev.decision_id, ev);
        matchable.add(ev.evidence_id);
        // v1.6.0: observations match a grant use, execution evidence and a break-glass record by ID.
        if (useIds.has(ev.evidence_id)) fail(seq, 'duplicate_record', `execution ${ev.evidence_id} is a grant use's ID`);
        otherMatchable.add(ev.evidence_id);
        executed.set(ev.evidence_id, {
          resource: ev.resource_id ?? null, sequence: seq, executed_at: micros(ev.executed_at),
          executor: ev.executor_sovereign_id, decision_id: ev.decision_id,
        });
        if (ev.resource_id !== undefined && ev.resource_id !== null) {
          const head = resourceHeads.get(ev.resource_id);
          // v1.3.1: a run that starts neither at entry 1 nor right after the checkpoint takes
          // the first record it holds of a resource as that chain's start.
          if (chained && (head || fromStart)) {
            const expected = head ? head.resource_sequence + 1 : 1;
            if (ev.resource_sequence !== expected
              || (ev.prev_resource_digest ?? null) !== (head ? head.record_digest : null)) {
              fail(seq, 'resource_chain_break', ev.resource_id);
            }
          }
          resourceHeads.set(ev.resource_id, { resource_sequence: ev.resource_sequence ?? 0, record_digest: executionDigest(ev) });
        }
        break;
      }
      case 'retention_checkpoint': {
        const cp = payload as unknown as RetentionCheckpoint;
        const failures = target.failures.length;
        naSignature(keys => verifyRetentionCheckpoint(cp, keys), 'RetentionCheckpoint');
        const authentic = target.failures.length === failures;
        // v1.3.1: a checkpoint removed as many entries as positions, counted from the checkpoint
        // before it when the run holds that one, or from entry 1 when there is none.
        const previous = cp.previous_checkpoint_id;
        const before = previous ? checkpoints.get(previous) : undefined;
        if (previous === null || previous === undefined || before) {
          const start = before ? before.removed_through_sequence : 0;
          if (cp.removed_count !== cp.removed_through_sequence - start) {
            fail(seq, 'retention_count_mismatch', `removed ${cp.removed_count} of ${cp.removed_through_sequence - start} `
              + `entries after #${start} through #${cp.removed_through_sequence}`);
          }
        }
        checkpoints.set(cp.checkpoint_id, cp);
        if (authentic) seedHeads(cp);
        break;
      }
      case 'observation':
      case 'break_glass': {
        if (!misplaced(fittingKey(kind, payload, executorKeys))) {
          signature(outOfBandSigned(kind, payload, allNaKeys, executorKeys), OUT_OF_BAND_MODELS[kind]);
        }
        subjects.set(subjectKey(kind, recordId), { digest: entry.payload_digest, sequence: seq });
        const version = kind === 'observation' ? payload['version_id']
          : (payload['execution_parameters'] as Record<string, unknown> | undefined)?.['version_id'];
        versions.set(subjectKey(kind, recordId), typeof version === 'string' && version ? version : null);
        notDecisions.add(recordId);
        if (kind === 'observation') {
          counts.observations += 1;
          const resource = (payload as unknown as ObservationRecord).resource_id;
          const position = entry.observation_sequence ?? null;
          if (chained && (observationHeads.has(resource) || fromStart)) {
            if (position !== (observationHeads.get(resource) ?? 0) + 1) fail(seq, 'observation_chain_break', resource);
          }
          observationHeads.set(resource, position || (observationHeads.get(resource) ?? 0));
        } else {
          counts.break_glass += 1;
          matchable.add(recordId);
          if (useIds.has(recordId)) fail(seq, 'duplicate_record', `break_glass ${recordId} is a grant use's ID`);
          otherMatchable.add(recordId);
        }
        break;
      }
      case 'judgement': {
        naSignature(keys => outOfBandSigned('judgement', payload, keys, executorKeys), 'JudgementRecord');
        const judgement = payload as unknown as JudgementRecord;
        counts.judgements += 1;
        notDecisions.add(judgement.judgement_id);
        judgedRecords.set(judgement.judgement_id, {
          digest: entry.payload_digest, resource: judgement.resource_id, change_kind: judgement.subject_kind,
          change_id: judgement.subject_id, change_sequence: judgement.subject_store_sequence,
          changed_at: micros(judgement.evaluated_as_of),
        });
        const key = subjectKey(judgement.subject_kind, judgement.subject_id);
        if (judged.has(key)) fail(seq, 'duplicate_judgement', judgement.subject_id);
        judged.add(key);
        const subject = subjects.get(key);
        if (subject) {
          if (subject.digest !== judgement.subject_digest || subject.sequence !== judgement.subject_store_sequence) {
            fail(seq, 'judgement_subject_mismatch', judgement.subject_id);
          }
        } else if (chained && contiguous && firstSequence !== null && judgement.subject_store_sequence >= firstSequence) {
          fail(seq, 'judgement_subject_missing', judgement.subject_id);
        } else if (pack && chained) {
          fail(seq, 'cited_record_missing', `${judgement.subject_kind} ${judgement.subject_id}`);
        }
        const match = judgement.matched_evidence_id;
        if (match !== undefined && match !== null) {
          if (matched.has(match)) fail(seq, 'match_reused', match);
          matched.add(match);
          // v1.3.1: the NA matches a record it already holds, so a run from entry 1 holds it.
          if (chained && contiguous && firstSequence === 1 && !matchable.has(match)) {
            fail(seq, 'judgement_match_missing', match);
          } else if (pack && chained && !matchable.has(match)) {
            fail(seq, 'cited_record_missing', `matched record ${match}`);
          }
        }
        break;
      }
      case 'quarantine': {
        const failures = target.failures.length;
        naSignature(keys => outOfBandSigned('quarantine', payload, keys, executorKeys), 'QuarantineRecord');
        const authentic = target.failures.length === failures;
        counts.quarantined += 1;
        const quarantine = payload as unknown as QuarantineRecord;
        if (payloadDigest(quarantine.record) !== quarantine.record_digest) fail(seq, 'quarantine_digest_mismatch');
        else if (authentic && quarantine.record_kind === 'grant_execution') quarantinedUse(quarantine.record);
        break;
      }
      case 'registry': {
        const failures = target.failures.length;
        naSignature(keys => outOfBandSigned('registry', payload, keys, executorKeys), 'RegistryRecord');
        const registry = payload as unknown as RegistryRecord;
        // v1.4.0 (review fixes): only a registry record the NA signed binds an operator key.
        const authentic = target.failures.length === failures;
        if (authentic && registry.event === 'operator_key_holder' && registry.key_id != null) {
          const list = operatorKeys.get(registry.key_id) ?? [];
          list.push({ at: micros(registry.effective_at), public_key: registry.public_key ?? null, holder: registry.holder ?? null });
          operatorKeys.set(registry.key_id, list);
        }
        break;
      }
      case 'remediation': {
        // v1.4.0: signed by an executor key of the record's sovereign, as execution evidence is.
        if (!misplaced(fittingKey('remediation', payload, executorKeys))) {
          signature(outOfBandSigned('remediation', payload, allNaKeys, executorKeys), 'RemediationRecord');
        }
        counts.remediations += 1;
        const remediation = payload as unknown as RemediationRecord;
        notDecisions.add(remediation.remediation_id);
        checkRemediationEntry(seq, remediation, fail, judgedRecords, executed, remediated, versions, cited,
          chained && contiguous && fromStart);
        break;
      }
      case 'review': {
        naSignature(keys => outOfBandSigned('review', payload, keys, executorKeys), 'ReviewRecord');
        counts.reviews += 1;
        const review = payload as unknown as ReviewRecord;
        notDecisions.add(review.review_id);
        checkReviewEntry(seq, review, fail, judgedRecords, remediated, operatorKeys, allNaKeys,
          chained && contiguous && fromStart);
        break;
      }
      case 'key_succession':
        checkSuccessionEntry(seq, payload as unknown as KeySuccessionRecord, fail, allNaKeys,
          history?.root_public_key ?? null, successions, micros(entry.recorded_at));
        counts.key_successions += 1;
        break;
      case 'archive':
        // v1.5.0: an archive record is signed by the NA, as its other records are.
        naSignature(keys => outOfBandSigned('archive', payload, keys, executorKeys), 'ArchiveRecord');
        counts.archives += 1;
        break;
      // v1.6.0: pre-issued grants (src/grants.ts).
      case 'grant': {
        const failures = target.failures.length;
        naSignature(keys => outOfBandSigned('grant', payload, keys, executorKeys), 'CapabilityGrant');
        counts.grants += 1;
        // A grant whose signature fails is not held: its uses and revocation are checked as for a grant
        // the run does not hold.
        if (target.failures.length === failures) {
          const grant = payload as unknown as CapabilityGrant;
          grantsHeld.set(grant.grant_id, { grant, digest: grantRecordDigest('CapabilityGrant', payload) });
        }
        break;
      }
      case 'grant_revocation': {
        const failures = target.failures.length;
        naSignature(keys => outOfBandSigned('grant_revocation', payload, keys, executorKeys), 'GrantRevocationRecord');
        const authentic = target.failures.length === failures;
        counts.grant_revocations += 1;
        const revocation = payload as unknown as GrantRevocationRecord;
        const held = grantsHeld.get(revocation.grant_id);
        if (held === undefined) {
          // A pack holds (or cites) the grant of every use and revocation in its range.
          if (pack && chained) fail(seq, 'cited_record_missing', `grant ${revocation.grant_id}`);
          else if (chained && contiguous && fromStart) fail(seq, 'grant_missing', revocation.grant_id);
        } else if (revocation.grant_digest !== held.digest) {
          fail(seq, 'grant_mismatch', revocation.grant_id);
        }
        if (revoked.has(revocation.grant_id)) fail(seq, 'duplicate_grant_revocation', revocation.grant_id);
        else if (authentic) revoked.set(revocation.grant_id, revocation.revoked_at);
        break;
      }
      case 'grant_execution': {
        // Signed by the grant's bearer key, a registered executor key of the use's executor sovereign.
        if (!misplaced(fittingKey('grant_execution', payload, executorKeys))) {
          signature(outOfBandSigned('grant_execution', payload, allNaKeys, executorKeys), 'GrantExecutionEvidence');
        }
        counts.grant_executions += 1;
        checkGrantUseEntry(seq, entry, payload as unknown as GrantExecutionEvidence, payload, fail, {
          grantsHeld, revoked, chainHeads, lastAdmitted, admittedUses, useHeads, resourceHeads, executorKeys, naKeys,
          chained, pack, contiguous, fromStart,
        });
        if (otherMatchable.has(recordId)) fail(seq, 'duplicate_record', `grant_execution ${recordId} is another record's ID`);
        useIds.add(recordId);
        matchable.add(recordId);
        break;
      }
      default:
        // Every kind of the registry has a case: a kind added to ENTRY_KINDS fails to compile here.
        kind satisfies never;
    }
  };

  /**
   * v1.6.0: a quarantined use (signed by its grant's bearer key, when the run holds the grant) that
   * continues its grant's use chain is the chain's head: the next use may link to it.
   */
  const quarantinedUse = (raw: unknown) => {
    if (!validGrantUse(raw)) return;
    const use = raw as GrantExecutionEvidence;
    const held = grantsHeld.get(use.grant_id);
    if (held !== undefined) {
      const sig = use.signature;
      if (!sig || sig.key_id !== held.grant.bearer_key_id
        || !signedBy(outOfBandCanonical(use), sig, [held.grant.bearer_public_key])) return;
    }
    const head = chainHeads.get(use.grant_id)
      ?? (fromStart || pack || use.use_sequence === 1 ? { use_sequence: 0, digest: null } : undefined);
    if (head === undefined || !continuesChain(use, head)) return;
    const digest = grantRecordDigest('GrantExecutionEvidence', use);
    chainHeads.set(use.grant_id, { use_sequence: use.use_sequence, digest });
    useHeads.set(`${use.grant_id}\u0000${use.use_sequence}`, { digest, executed_at: use.executed_at });
    if (use.use_sequence === 1 && !admittedUses.has(use.grant_id)) admittedUses.set(use.grant_id, 0);
  };

  const counts = Object.fromEntries(COUNTED.map(name => [name, 0])) as Counts;
  if (pack) {
    // The cited records first, in store order: their failures fail the run, their counts do not count.
    const citedResult: EvidenceStoreVerification = { verified: true, checked_entries: 0, decisions: 0, executions: 0, failures: [] };
    const citedCounts = Object.fromEntries(COUNTED.map(name => [name, 0])) as Counts;
    const prior = [...options.prior!].sort((a, b) => a.entry.store_sequence - b.entry.store_sequence);
    for (const event of prior) visit(event, citedResult, citedCounts, true);
    for (const failure of citedResult.failures) {
      failOn(result)(failure.store_sequence, failure.reason, `cited ${failure.detail}`.trimEnd());
    }
    if (citedResult.warnings) (result.warnings ??= []).push(...citedResult.warnings);
    prev = null;
  }
  for (const event of events) visit(event, result, counts, false);
  for (const name of COUNTED) {
    if (counts[name] > 0) result[name] = counts[name];
  }
  return result;
}

/**
 * v1.5.0: a key succession entry is signed by its outgoing key, an NA key,
 * and by the new key (`succession_invalid_new_key_signature`); given the NA's
 * key history with its root key, it is one of the history's successions
 * (`succession_not_in_history`) and the root key signed it
 * (`succession_invalid_root_signature`). It was not issued after it takes
 * effect, and the store recorded it at least `SUCCESSION_MIN_LEAD_SECONDS`
 * before (`succession_backdated`).
 */
function checkSuccessionEntry(
  seq: number,
  record: KeySuccessionRecord,
  fail: Fail,
  naKeys: readonly string[],
  root: string | null,
  successions: ReadonlySet<string> | null,
  recordedAt: number,
): void {
  const refusal = strictRefusal('KeySuccessionRecord', record,
    [...naKeys, ...(root ? [root] : []), record.new_public_key]);
  if (refusal !== null) {
    fail(seq, refusal === 'unknown_field' ? 'invalid_signature' : refusal, 'key_succession');
    return;
  }
  if (!naKeys.includes(record.previous_public_key) || !successionSignedBy(record, record.previous_public_key)) {
    fail(seq, 'invalid_signature', 'key_succession');
    return;
  }
  if (root && !successionSignedBy(record, root)) {
    fail(seq, 'succession_invalid_root_signature', record.succession_id);
    return;
  }
  if (!successionSignedBy(record, record.new_public_key)) {
    fail(seq, 'succession_invalid_new_key_signature', record.succession_id);
    return;
  }
  if (root && successions && !successions.has(successionDigest(record))) {
    fail(seq, 'succession_not_in_history', record.succession_id);
    return;
  }
  const effective = micros(record.effective_at);
  if (micros(record.issued_at) > effective || recordedAt + SUCCESSION_MIN_LEAD_SECONDS * 1_000_000 > effective) {
    fail(seq, 'succession_backdated', record.succession_id);
  }
}

type Fail = (storeSequence: number | null, reason: string, detail?: string) => void;
/** What a remediation or review checks of its judgement or decision (times in microseconds). */
interface JudgedSubject {
  digest: string;
  resource: string | null;
  change_kind?: string;
  change_id?: string;
  change_sequence?: number;
  changed_at?: number;
}
type JudgedRecords = ReadonlyMap<string, JudgedSubject>;
/** What a remediation checks of execution evidence (`executed_at` in microseconds). */
interface HeldExecution {
  resource: string | null;
  sequence: number;
  executed_at: number;
  executor: string;
  decision_id: string;
}
/** An `operator_key_holder` registry record: when it took effect (microseconds), the key and its holder. */
interface OperatorKeyRecord { at: number; public_key: string | null; holder: string | null }

/**
 * v1.4.0: one remediation per judgement or decision (`duplicate_remediation`), of its subject's change,
 * resource and the version that change made (`remediation_subject_mismatch`), after a forward rotation
 * of the same resource (`remediation_rotation_mismatch`) by its own executor sovereign
 * (`remediation_rotation_other_executor`), made after the change (`remediation_rotation_before_change`)
 * and cited once (`remediation_rotation_reused`). In a run from its start (entry 1, or right after the
 * checkpoint) its subject and rotation are held before it (`remediation_subject_missing`,
 * `remediation_rotation_missing`).
 */
function checkRemediationEntry(
  seq: number,
  record: RemediationRecord,
  fail: Fail,
  judged: JudgedRecords,
  executed: ReadonlyMap<string, HeldExecution>,
  remediated: Set<string>,
  versions: ReadonlyMap<string, string | null>,
  cited: Set<string>,
  heldFromStart: boolean,
): void {
  if (remediated.has(record.subject_id)) fail(seq, 'duplicate_remediation', record.subject_id);
  remediated.add(record.subject_id);
  const subject = judged.get(record.subject_id);
  let changeSequence: number | null = null;
  let changedAt: number | null = null;
  if (subject === undefined) {
    if (heldFromStart) fail(seq, 'remediation_subject_missing', record.subject_id);
  } else if (record.subject_kind === 'judgement') {
    const version = versions.get(subjectKey(record.change_kind, record.change_id)) ?? null;
    const disabled = record.disabled_version_id ?? null;
    if (subject.resource !== record.resource_id || record.change_kind !== subject.change_kind
      || record.change_id !== subject.change_id || (disabled !== null && version !== null && disabled !== version)) {
      fail(seq, 'remediation_subject_mismatch', record.subject_id);
    }
    changeSequence = subject.change_sequence ?? null;
    changedAt = subject.changed_at ?? null;
  } else if (record.change_id !== record.subject_id) {
    // A decision's change is its execution evidence (or, never executed, the decision itself).
    const change = executed.get(record.change_id);
    if (record.change_kind !== 'execution' || (change !== undefined
      && (change.decision_id !== record.subject_id || change.resource !== record.resource_id))) {
      fail(seq, 'remediation_subject_mismatch', record.subject_id);
    } else if (change !== undefined) {
      changeSequence = change.sequence;
      changedAt = change.executed_at;
    }
  }
  const rotation = record.rotation_evidence_id;
  if (rotation !== undefined && rotation !== null) {
    const held = executed.get(rotation);
    if (held !== undefined) {
      if (held.resource !== record.resource_id) fail(seq, 'remediation_rotation_mismatch', rotation);
      const problem = rotationProblem({
        rotation_executor: held.executor, rotation_sequence: held.sequence, rotation_executed_at: held.executed_at,
        record_executor: record.executor_sovereign_id, change_sequence: changeSequence, changed_at: changedAt,
        already_cited: cited.has(rotation),
      });
      if (problem !== null) fail(seq, problem.code, rotation);
    } else if (heldFromStart) {
      fail(seq, 'remediation_rotation_missing', rotation);
    } else if (cited.has(rotation)) {
      fail(seq, 'remediation_rotation_reused', rotation);
    }
    cited.add(rotation);
  }
}

/**
 * v1.4.0: a review's embedded admin requests verify offline (`review_approval_invalid`), with the
 * public key and holder the holder registry (records the NA signed) last recorded for each operator
 * key by then, when the run holds a record for that key (`review_approval_key_mismatch`); a second
 * holder decided it (`review_same_holder`); it names its subject's digest (`review_subject_mismatch`;
 * `review_subject_missing` in a run from its start); and no waiver follows a recorded remediation
 * (`review_waiver_after_remediation`).
 */
function checkReviewEntry(
  seq: number,
  review: ReviewRecord,
  fail: Fail,
  judged: JudgedRecords,
  remediated: ReadonlySet<string>,
  operatorKeys: ReadonlyMap<string, OperatorKeyRecord[]>,
  naPublicKeys: readonly string[],
  heldFromStart: boolean,
): void {
  const problem = reviewApprovalProblem(review, naPublicKeys);
  if (problem !== null) fail(seq, 'review_approval_invalid', problem);
  const signers: [string | undefined, ReviewRecord['approval'] | undefined, string | undefined, string][] = [
    [review.decided_by, review.approval, review.decider_holder, review.decided_at],
    [review.requested_by, review.request_approval, review.requester_holder, review.requested_at],
  ];
  for (const [keyId, approval, holder, at] of signers) {
    if (keyId == null || approval == null || !operatorKeys.has(keyId)) continue;
    // The latest record at or before the time (the first of equal times, as the reference picks it).
    let latest: OperatorKeyRecord | undefined;
    for (const record of operatorKeys.get(keyId)!) {
      if (record.at <= micros(at) && (latest === undefined || record.at > latest.at)) latest = record;
    }
    if (latest === undefined || latest.public_key !== approval.public_key || latest.holder !== (holder ?? null)) {
      fail(seq, 'review_approval_key_mismatch', keyId);
    }
  }
  if (reviewHolderProblem(review) !== null) fail(seq, 'review_same_holder', review.decided_by);
  const subject = judged.get(review.subject_id);
  if (subject === undefined) {
    if (heldFromStart) fail(seq, 'review_subject_missing', review.subject_id);
  } else if (subject.digest !== review.subject_digest) {
    fail(seq, 'review_subject_mismatch', review.subject_id);
  }
  if (review.verdict === 'waive_until' && remediated.has(review.subject_id)) {
    fail(seq, 'review_waiver_after_remediation', review.subject_id);
  }
}

/** What a grant use is checked against: what the run holds so far (v1.6.0). */
interface GrantRun {
  grantsHeld: ReadonlyMap<string, { grant: CapabilityGrant; digest: string }>;
  revoked: ReadonlyMap<string, string>;
  chainHeads: Map<string, UseChainHead>;
  lastAdmitted: Map<string, PreviousUse>;
  admittedUses: Map<string, number>;
  useHeads: Map<string, { digest: string; executed_at: string }>;
  resourceHeads: Map<string, ResourceHead>;
  executorKeys: Record<string, ExecutorKeyInfo>;
  naKeys: NAKeys;
  /** Checks that need the use's predecessors in the run; a pack's cited records are not a run. */
  chained: boolean;
  pack: boolean;
  contiguous: boolean;
  fromStart: boolean;
}

/**
 * v1.6.0: the uses of a grant form a chain, whose head may be a quarantined use
 * that continued it (`grant_use_chain_break`); a use names a grant the run
 * holds when it holds the store from its start (`grant_missing`; in a pack
 * `cited_record_missing`), is signed by its bearer key
 * (`grant_bearer_mismatch`), within the key's resource prefix
 * (`grant_use_out_of_scope`), and names the grant's digest (`grant_mismatch`);
 * then the use rules (`useProblem`, with the admission codes) with what the
 * run holds: the budget counts admitted uses when the run holds the chain from
 * its first use, and the order and time rules compare a use with the last
 * admitted one. A use takes the next position of its resource's chain, which
 * the NA assigns in the envelope (`resource_chain_break`); one without a
 * resource has none (`envelope_mismatch`).
 */
function checkGrantUseEntry(
  seq: number,
  entry: EvidenceEvent['entry'],
  use: GrantExecutionEvidence,
  payload: Record<string, unknown>,
  fail: Fail,
  run: GrantRun,
): void {
  const received = grantRecordDigest('GrantExecutionEvidence', payload);
  const held = run.grantsHeld.get(use.grant_id);
  const grant = held?.grant ?? null;
  const sig = use.signature;
  const signer = keyNamed(run.executorKeys, sig?.key_id);
  const head = run.chainHeads.get(use.grant_id) ?? (run.fromStart ? { use_sequence: 0, digest: null } : undefined);
  if (run.chained && head !== undefined && !continuesChain(use, head)) fail(seq, 'grant_use_chain_break', use.grant_id);
  if (held === undefined) {
    if (run.pack && run.chained) fail(seq, 'cited_record_missing', `grant ${use.grant_id}`);
    else if (run.chained && run.contiguous && run.fromStart) fail(seq, 'grant_missing', use.grant_id);
  } else if (!sig || sig.key_id !== held.grant.bearer_key_id || use.executor_sovereign_id !== held.grant.bearer_sovereign_id
    || (signer !== undefined && signer.public_key !== held.grant.bearer_public_key)) {
    fail(seq, 'grant_bearer_mismatch', use.use_id);
  }
  const prefix = signer?.resource_prefix ?? null;
  if (prefix !== null && !(use.resource_id ?? '').startsWith(prefix)) {
    fail(seq, 'grant_use_out_of_scope', `signing key covers only resources starting with ${prefix}`);
  }
  if (held !== undefined && use.grant_digest !== held.digest) fail(seq, 'grant_mismatch', use.grant_id);
  if (use.use_sequence === 1 && !run.admittedUses.has(use.grant_id)) run.admittedUses.set(use.grant_id, 0);
  const token = use.time_token;
  const tokenKeys = naKeysAt(run.naKeys, token.issued_at);
  if (run.chained) {
    const named = token.use_sequence ? run.useHeads.get(`${use.grant_id}\u0000${token.use_sequence}`) ?? null : null;
    const problem = useProblem(use, {
      grant, previous: run.lastAdmitted.get(use.grant_id) ?? null, admitted: run.admittedUses.get(use.grant_id) ?? null,
      tokenHead: named, tokenKeys, rawToken: payload['time_token'], revokedAt: run.revoked.get(use.grant_id) ?? null,
      recordedAt: entry.recorded_at,
    });
    if (problem !== null) fail(seq, problem.code, problem.detail);
  } else if (!tokenSignatureValid(payload['time_token'], tokenKeys)) {
    fail(seq, 'grant_time_token_invalid', use.use_id);
  }
  run.chainHeads.set(use.grant_id, { use_sequence: use.use_sequence, digest: received });
  run.lastAdmitted.set(use.grant_id, nextPreviousUse(use));
  const admitted = run.admittedUses.get(use.grant_id);
  if (admitted !== undefined) run.admittedUses.set(use.grant_id, admitted + 1);
  run.useHeads.set(`${use.grant_id}\u0000${use.use_sequence}`, { digest: received, executed_at: use.executed_at });
  if (use.resource_id !== undefined && use.resource_id !== null) {
    const resourceHead = run.resourceHeads.get(use.resource_id);
    if (run.chained && (resourceHead !== undefined || run.fromStart)
      && entry.resource_sequence !== (resourceHead ? resourceHead.resource_sequence + 1 : 1)) {
      fail(seq, 'resource_chain_break', use.resource_id);
    }
    run.resourceHeads.set(use.resource_id, { resource_sequence: entry.resource_sequence ?? 0, record_digest: received });
  } else if (entry.resource_sequence !== null && entry.resource_sequence !== undefined) {
    fail(seq, 'envelope_mismatch', 'grant_execution: resource_sequence');
  }
}

/** v1.3.1: judgement subjects are keyed by kind and ID: a break-glass record may share an observation's ID. */
function subjectKey(kind: string, id: string): string {
  return `${kind}\u0000${id}`;
}

/** Each known entry kind's payload check: the record in the shape the reference reads. */
const PAYLOAD_CHECKS: Readonly<Record<EntryKind, (payload: Record<string, unknown>) => boolean>> = {
  decision: payload => validDecision(payload['decision']),
  justification: validJustification,
  execution: validExecution,
  retention_checkpoint: validCheckpoint,
  observation: validObservation,
  break_glass: validBreakGlass,
  judgement: validJudgement,
  quarantine: validQuarantine,
  registry: validRegistry,
  remediation: validRemediation,
  review: validReview,
  // v1.5.0
  key_succession: validKeySuccession,
  archive: validArchive,
  // v1.6.0
  grant: validGrant,
  grant_execution: validGrantUse,
  grant_revocation: validGrantRevocation,
};

/** v1.3.1: the field holding each kind's record ID, which appears once per kind in a run (`duplicate_record`). */
const RECORD_ID: Readonly<Record<EntryKind, string>> = {
  decision: 'decision_id',
  justification: 'proof_id',
  execution: 'evidence_id',
  retention_checkpoint: 'checkpoint_id',
  observation: 'observation_id',
  break_glass: 'break_glass_id',
  judgement: 'judgement_id',
  quarantine: 'quarantine_id',
  registry: 'registry_record_id',
  remediation: 'remediation_id',
  review: 'review_id',
  key_succession: 'succession_id',
  archive: 'archive_id',
  grant: 'grant_id',
  grant_execution: 'use_id',
  grant_revocation: 'revocation_id',
};

/**
 * v1.3.1: envelope field -> record field, for the envelope fields the NA
 * derives from a Stage 2 record. The NA searches and matches on them, so each
 * must name what the signed record says (`envelope_mismatch`). Every kind is
 * listed: the NA derives no envelope field from the records that came before Stage 2.
 */
const ENVELOPE_FIELDS: Readonly<Record<EntryKind, Readonly<Record<string, string>>>> = {
  decision: {},
  justification: {},
  execution: {},
  retention_checkpoint: {},
  observation: {
    record_id: 'observation_id', resource_id: 'resource_id', resource_action: 'action', capability: 'capability',
    executor_sovereign_id: 'observer_sovereign_id',
  },
  break_glass: {
    record_id: 'break_glass_id', resource_id: 'resource_id', resource_action: 'resource_action', capability: 'capability',
    executor_sovereign_id: 'executor_sovereign_id', attestation_id: 'attestation_id', outcome: 'outcome',
  },
  judgement: {
    record_id: 'judgement_id', subject_id: 'subject_id', resource_id: 'resource_id', resource_action: 'action',
    capability: 'capability', outcome: 'verdict', matched_evidence_id: 'matched_evidence_id',
  },
  quarantine: { record_id: 'quarantine_id', resource_id: 'resource_id', outcome: 'rejection_code' },
  registry: { record_id: 'registry_record_id', outcome: 'event' },
  // v1.4.0
  remediation: {
    record_id: 'remediation_id', subject_id: 'subject_id', resource_id: 'resource_id',
    executor_sovereign_id: 'executor_sovereign_id', outcome: 'outcome',
  },
  review: {
    record_id: 'review_id', subject_id: 'subject_id', resource_id: 'resource_id', capability: 'capability',
    outcome: 'verdict',
  },
  // v1.5.0: Stage 4 entries carry their record's ID only.
  key_succession: { record_id: 'succession_id' },
  archive: { record_id: 'archive_id' },
  // v1.6.0 (no new envelope field): a use's grant is its `subject_id`, its place in its chain its
  // `exec_sequence_no`; its `resource_sequence` is the NA's, outside the record.
  grant: { record_id: 'grant_id', executor_sovereign_id: 'bearer_sovereign_id' },
  grant_execution: {
    record_id: 'use_id', subject_id: 'grant_id', resource_id: 'resource_id', resource_action: 'resource_action',
    capability: 'capability', executor_sovereign_id: 'executor_sovereign_id', outcome: 'outcome',
    exec_sequence_no: 'use_sequence',
  },
  grant_revocation: { record_id: 'revocation_id', subject_id: 'grant_id', outcome: 'reason' },
};

/**
 * v1.3.0: the model each Stage 2 entry kind holds (v1.4.0: and each Stage 3 kind, v1.5.0: and an
 * archive record, v1.6.0: and each Stage 5 kind, stored exactly as signed too).
 */
const OUT_OF_BAND_MODELS = {
  observation: 'ObservationRecord',
  break_glass: 'BreakGlassRecord',
  judgement: 'JudgementRecord',
  quarantine: 'QuarantineRecord',
  registry: 'RegistryRecord',
  remediation: 'RemediationRecord',
  review: 'ReviewRecord',
  archive: 'ArchiveRecord',
  grant: 'CapabilityGrant',
  grant_execution: 'GrantExecutionEvidence',
  grant_revocation: 'GrantRevocationRecord',
} as const satisfies Partial<Record<EntryKind, string>>;

/** An entry kind whose record the store holds exactly as signed (a key of `OUT_OF_BAND_MODELS`). */
type OutOfBandKind = keyof typeof OUT_OF_BAND_MODELS;

function isOutOfBand(kind: EntryKind): kind is OutOfBandKind {
  return Object.hasOwn(OUT_OF_BAND_MODELS, kind);
}

/**
 * Who signs each Stage 2, 3 and 5 kind: a registered key with the role named here, or the NA (`na`).
 * v1.6.0: a grant use is signed by its grant's bearer key, a registered executor key.
 */
const KEY_ROLES: Readonly<Record<OutOfBandKind, 'executor' | 'observer' | 'na'>> = {
  observation: 'observer', break_glass: 'executor', remediation: 'executor', grant_execution: 'executor',
  judgement: 'na', quarantine: 'na', registry: 'na', review: 'na', archive: 'na', grant: 'na', grant_revocation: 'na',
};

/** The keys that may sign a Stage 2 record: the registered key it names (with the right sovereign and role), or the NA's. */
function outOfBandKeys(
  kind: OutOfBandKind,
  payload: Record<string, unknown>,
  naPublicKeys: readonly string[],
  executorKeys: Record<string, ExecutorKeyInfo>,
): readonly string[] {
  const role = KEY_ROLES[kind];
  if (role === 'na') return naPublicKeys;
  const signature = payload['signature'] as Signature | null | undefined;
  const key = keyNamed(executorKeys, signature?.key_id);
  const sovereign = kind === 'observation' ? payload['observer_sovereign_id'] : payload['executor_sovereign_id'];
  return key && key.executor_sovereign_id === sovereign && (key.role ?? 'executor') === role ? [key.public_key] : [];
}

/** The registered key that fits a key-signed Stage 2 or 3 record (its sovereign and role), or undefined. */
function fittingKey(
  kind: OutOfBandKind,
  payload: Record<string, unknown>,
  executorKeys: Record<string, ExecutorKeyInfo>,
): ExecutorKeyInfo | undefined {
  const role = KEY_ROLES[kind];
  const key = keyNamed(executorKeys, (payload['signature'] as Signature | null | undefined)?.key_id);
  const sovereign = kind === 'observation' ? payload['observer_sovereign_id'] : payload['executor_sovereign_id'];
  return key && role !== 'na' && key.executor_sovereign_id === sovereign && (key.role ?? 'executor') === role ? key : undefined;
}

/** Whether a Stage 2 record's signature covers it as received, under the key that may sign it. */
function outOfBandSigned(
  kind: OutOfBandKind,
  payload: Record<string, unknown>,
  naPublicKeys: readonly string[],
  executorKeys: Record<string, ExecutorKeyInfo>,
): boolean {
  return signedBy(outOfBandCanonical(payload), payload['signature'] as Signature | null | undefined,
    outOfBandKeys(kind, payload, naPublicKeys, executorKeys))
    && unknownFields(OUT_OF_BAND_MODELS[kind], payload).length === 0;
}

/** The model each kind's payload holds; a decision's payload wraps its decision and context (checked apart). */
const PAYLOAD_MODELS: Readonly<Record<Exclude<EntryKind, 'decision'>, string>> = {
  justification: 'JustificationProof',
  execution: 'ExecutionEvidence',
  retention_checkpoint: 'RetentionCheckpoint',
  ...OUT_OF_BAND_MODELS,
  key_succession: 'KeySuccessionRecord',
};

interface CheckedPayload {
  /** Unknown fields the signature covers: an authentic record from a newer signer. */
  signed: string[];
  /** Unknown fields outside the signature (stored before 1.1.1, or in a decision's wrapper): reported, then ignored. */
  unsigned: string[];
  /** The payload to verify further: without its unsigned unknown fields. */
  payload: Record<string, unknown>;
}

/**
 * Sort an export payload's unknown fields into signed (refused) and unsigned (reported, removed).
 * `naPublicKeys` are every NA key; a key succession is also signed by the root key, when known.
 */
function checkPayloadFields(
  kind: EntryKind,
  payload: Record<string, unknown>,
  naPublicKeys: readonly string[],
  rootPublicKey: string | null,
  executorKeys: Record<string, ExecutorKeyInfo>,
): CheckedPayload {
  if (kind === 'decision') {
    const unsigned = [
      ...Object.keys(payload).filter(k => k !== 'decision' && k !== 'context'),
      ...unknownFields('ContextRecord', payload['context'], 'context.'),
    ];
    const decision = payload['decision'] as BoundaryDecision | undefined;
    const found = unknownFields('BoundaryDecision', decision, 'decision.');
    if (found.length > 0 && decision && decisionSigned(decision, naPublicKeys)) {
      return { signed: found, unsigned, payload };
    }
    const cleaned: Record<string, unknown> = {
      decision: found.length > 0 ? withoutUnknownFields('BoundaryDecision', decision) : decision,
      context: withoutUnknownFields('ContextRecord', payload['context']),
    };
    return { signed: [], unsigned: [...unsigned, ...found], payload: cleaned };
  }
  const model = PAYLOAD_MODELS[kind];
  const found = unknownFields(model, payload);
  if (found.length === 0) return { signed: [], unsigned: [], payload };
  let signedAsReceived = false;
  if (kind === 'execution') {
    const ev = payload as unknown as ExecutionEvidence;
    const key = keyNamed(executorKeys, ev.signature?.key_id);
    signedAsReceived = !!key && signedBy(executionCanonical(ev), ev.signature, [key.public_key]);
  } else if (kind === 'justification') {
    signedAsReceived = signedBy(justificationCanonical(payload as unknown as DecisionJustification),
      (payload as unknown as DecisionJustification).signature, naPublicKeys);
  } else if (kind === 'key_succession') {
    const newKey = typeof payload['new_public_key'] === 'string' ? [payload['new_public_key']] : [];
    signedAsReceived = signedAsReceivedBy(model, payload, [...naPublicKeys, ...(rootPublicKey ? [rootPublicKey] : []), ...newKey]);
  } else if (isOutOfBand(kind)) {
    // The key the signature names, whatever its role: an authentic record with a field this SDK
    // does not know is refused by name first, as the reference refuses it.
    const signature = payload['signature'] as Signature | null | undefined;
    const named = keyNamed(executorKeys, signature?.key_id);
    const keys = KEY_ROLES[kind] === 'na' ? naPublicKeys : named ? [named.public_key] : [];
    signedAsReceived = signedBy(outOfBandCanonical(payload), signature, keys);
  } else {
    signedAsReceived = checkpointSigned(payload as unknown as RetentionCheckpoint, naPublicKeys);
  }
  return signedAsReceived
    ? { signed: found, unsigned: [], payload }
    : { signed: [], unsigned: found, payload: withoutUnknownFields(model, payload) };
}

// ── Agreements (v0.61) ────────────────────────────────────────────────────────

export type AgreementVerificationReason =
  | 'accepted'
  | 'missing_offerer_signature'
  | 'invalid_offerer_signature'
  | 'missing_responder_signature'
  | 'invalid_responder_signature'
  | 'graph_digest_mismatch'
  | 'unknown_field'
  | 'non_canonical_form';

export interface AgreementVerification {
  accepted: boolean;
  reason: AgreementVerificationReason;
  agreement_id: string;
}

/**
 * Verify an AgreementRecord offline: at least one signature by an offerer key
 * and one by a responder key over the shared canonical body, and the graph
 * digest when `expectedGraphDigest` is given. Port of `verify_agreement`.
 */
export function verifyAgreement(
  record: AgreementRecord,
  offererPublicKeys: NAKeys,
  responderPublicKeys: NAKeys,
  expectedGraphDigest?: string,
  now: Date = new Date(),
): AgreementVerification {
  const result = (accepted: boolean, reason: AgreementVerificationReason) =>
    ({ accepted, reason, agreement_id: record.agreement_id });
  // v1.5.0: a party given as the NA's key history signs with the key valid at `agreed_terms.valid_from`
  // (signed; `established_at` is not) that is still accepted `now`: an agreement a succeeded key signed
  // stops vouching when that key's hand-over ends.
  const vouching = (keys: NAKeys) => {
    if (!(keys instanceof NAKeyHistory)) return [...keys];
    const current = new Set(keys.keysAt(now));
    const from = record.agreed_terms?.valid_from;
    return (typeof from === 'string' ? keys.keysAt(from) : []).filter(k => current.has(k));
  };
  const offererKeys = vouching(offererPublicKeys);
  const responderKeys = vouching(responderPublicKeys);
  // 1.3.1: `signatures` that is not a list holds no signature (it threw a TypeError).
  const signatures = signatureList(record.signatures);
  if (signatures.length === 0) return result(false, 'missing_offerer_signature');
  const canonical = agreementCanonical(record);
  if (!anySigned(canonical, signatures, offererKeys)) return result(false, 'invalid_offerer_signature');
  if (!anySigned(canonical, signatures, responderKeys)) {
    return result(false, signatures.length < 2 ? 'missing_responder_signature' : 'invalid_responder_signature');
  }
  if (expectedGraphDigest !== undefined && record.graph_digest !== expectedGraphDigest) {
    return result(false, 'graph_digest_mismatch');
  }
  // v1.2.0: an authentic agreement with a signed field this SDK does not know.
  if (unknownFields('AgreementRecord', record).length > 0) return result(false, 'unknown_field');
  // v1.2.0: an agreement signed over a form the reference does not write.
  if (nonCanonicalFields('AgreementRecord', record).length > 0) return result(false, 'non_canonical_form');
  return result(true, 'accepted');
}

// ── Data usage (v0.61) ────────────────────────────────────────────────────────

/** True when the licensor signed the DataLicensePolicy. */
export function verifyDataLicensePolicySignature(policy: DataLicensePolicy, licensorPublicKeys: readonly string[]): boolean {
  return signedBy(dataLicensePolicyCanonical(policy), policy.signature, licensorPublicKeys)
    && unknownFields('DataLicensePolicy', policy).length === 0
    && nonCanonicalFields('DataLicensePolicy', policy).length === 0;
}

export type DataUsageViolationType =
  | 'intent_exceeds_license'
  | 'intent_expired'
  | 'policy_expired'
  | 'source_not_licensed'
  | 'prohibited_classification'
  | 'access_type_not_permitted'
  | 'volume_cap_exceeded';

export interface DataUsageViolationDetail {
  violation_type: DataUsageViolationType;
  detail: string;
}

export interface DataIntentVerification {
  valid: boolean;
  /** The first violation's type; null when valid. */
  violation_reason: DataUsageViolationType | null;
  violations: DataUsageViolationDetail[];
}

/**
 * Check an agent-signed DataAccessIntent against a DataLicensePolicy offline:
 * the agent signature, then expiry, licensed sources, prohibited
 * classifications, permitted access types and the volume cap, in the order of
 * the reference `verify_data_access_intent`.
 */
export function verifyDataAccessIntent(
  intent: DataAccessIntent,
  policy: DataLicensePolicy,
  agentPublicKeys: readonly string[],
  at: Date | string = new Date(),
): DataIntentVerification {
  const fail = (violations: DataUsageViolationDetail[]): DataIntentVerification =>
    ({ valid: false, violation_reason: violations[0]!.violation_type, violations });
  // v1.2.0: fields this SDK does not know, and forms the reference does not
  // write, as the reference reports them.
  const intentUnknown = unknownFields('DataAccessIntent', intent);
  const intentLoose = nonCanonicalFields('DataAccessIntent', intent);
  if ((intentUnknown.length > 0 || intentLoose.length > 0)
    && !signedBy(dataAccessIntentCanonical(intent), intent.signature, agentPublicKeys)) {
    return fail([{ violation_type: 'intent_exceeds_license', detail: 'Invalid intent signature' }]);
  }
  const unknown = [...intentUnknown, ...unknownFields('DataLicensePolicy', policy, 'policy.')].sort(compareCodePoints);
  if (unknown.length > 0) {
    return fail([{ violation_type: 'intent_exceeds_license', detail: `Unknown field: ${unknown.join(', ')}` }]);
  }
  if (intentLoose.length > 0) {
    return fail([{ violation_type: 'intent_exceeds_license', detail: 'Not in canonical form: intent' }]);
  }
  if (nonCanonicalFields('DataLicensePolicy', policy).length > 0) {
    return fail([{ violation_type: 'intent_exceeds_license', detail: 'Not in canonical form: policy' }]);
  }
  if (!intent.signature) return fail([{ violation_type: 'intent_exceeds_license', detail: 'Missing intent signature' }]);
  if (!signedBy(dataAccessIntentCanonical(intent), intent.signature, agentPublicKeys)) {
    return fail([{ violation_type: 'intent_exceeds_license', detail: 'Invalid intent signature' }]);
  }
  const now = micros(at);
  const violations: DataUsageViolationDetail[] = [];
  const add = (violation_type: DataUsageViolationType, detail: string) => violations.push({ violation_type, detail });
  if (now > micros(intent.expires_at)) add('intent_expired', `Intent expired at ${intent.expires_at}`);
  if (now > micros(policy.valid_until) || now < micros(policy.valid_from)) add('policy_expired', 'Policy not valid at verification time');
  const allowed = new Set(policy.allowed_source_ids);
  const prohibited = new Set(policy.prohibited_classification_tags);
  for (const source of intent.declared_sources) {
    if (!allowed.has(source.source_id)) add('source_not_licensed', `Source '${source.source_id}' not in allowed_source_ids`);
    const overlap = source.classification_tags.filter(t => prohibited.has(t)).sort(compareCodePoints);
    if (overlap.length > 0) {
      add('prohibited_classification', `Source '${source.source_id}' has prohibited tags: ${overlap.join(', ')}`);
    }
  }
  const allowedTypes = new Set(policy.allowed_access_types.length > 0 ? policy.allowed_access_types : ['read']);
  for (const accessType of intent.declared_access_types) {
    if (!allowedTypes.has(accessType)) add('access_type_not_permitted', `Access type '${accessType}' not in allowed_access_types`);
  }
  const cap = policy.max_volume_bytes_per_session;
  const volume = intent.estimated_volume_bytes;
  if (cap !== null && cap !== undefined && volume !== null && volume !== undefined && volume > cap) {
    add('volume_cap_exceeded', `Volume ${volume} > max ${cap}`);
  }
  return violations.length > 0 ? fail(violations) : { valid: true, violation_reason: null, violations: [] };
}
