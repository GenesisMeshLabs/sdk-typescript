import {
  timestamp,
  validBreakGlass,
  validCheckpoint,
  validContext,
  validDecision,
  validEvent,
  validExecution,
  validJudgement,
  validJustification,
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
 */

import { compareCodePoints, parseJson, verifyCanonical } from './auth.js';
import {
  outOfBandCanonical,
  type BreakGlassRecord,
  type JudgementRecord,
  type ObservationRecord,
  type QuarantineRecord,
  type RegistryRecord,
} from './out-of-band.js';
import {
  reviewApprovalProblem, reviewHolderProblem, type RemediationRecord, type ReviewRecord,
} from './remediation.js';
import { isKnownEntryKind, nonCanonicalFields, unknownFields, withoutUnknownFields } from './strict.js';
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

/** True when the decision signature verifies under any of the operator (NA) keys. */
export function verifyDecisionSignature(decision: BoundaryDecision, publicKeys: readonly string[]): boolean {
  return decisionSigned(decision, publicKeys) && unknownFields('BoundaryDecision', decision).length === 0;
}

/** True when any attestation signature verifies under the issuer keys. */
export function verifyAttestationSignature(attestation: MembershipAttestation, publicKeys: readonly string[]): boolean {
  return unknownFields('MembershipAttestation', attestation).length === 0
    && anySigned(attestationCanonical(attestation), attestation.signatures, publicKeys);
}

export function verifyPolicySignature(policy: BoundaryPolicy, publicKeys: readonly string[]): boolean {
  return unknownFields('BoundaryPolicy', policy).length === 0
    && signedBy(policyCanonical(policy), policy.signature, publicKeys);
}

export function verifyJustificationSignature(proof: DecisionJustification, publicKeys: readonly string[]): boolean {
  return unknownFields('JustificationProof', proof).length === 0
    && signedBy(justificationCanonical(proof), proof.signature, publicKeys);
}

export function verifyRevocationFeedSignature(feed: SovereignRevocationFeed, publicKeys: readonly string[]): boolean {
  return unknownFields('SovereignRevocationFeed', feed).length === 0
    && anySigned(revocationFeedCanonical(feed), feed.signatures, publicKeys);
}

function checkpointSigned(checkpoint: RetentionCheckpoint, publicKeys: readonly string[]): boolean {
  return signedBy(checkpointCanonical(checkpoint), checkpoint.signature, publicKeys);
}

export function verifyRetentionCheckpoint(checkpoint: RetentionCheckpoint, publicKeys: readonly string[]): boolean {
  return checkpointSigned(checkpoint, publicKeys) && unknownFields('RetentionCheckpoint', checkpoint).length === 0;
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
  /** NA keys that may sign decisions. */
  operatorPublicKeys: readonly string[];
  /** When set and the decision embeds a FreshnessProof, the proof must verify under these keys. */
  freshnessProofIssuerKeys?: readonly string[];
  now?: Date;
  /** The decision must bind exactly these policy versions, in resolution order. */
  expectedPolicies?: readonly BoundaryPolicy[];
  /** The decision must bind this attestation: id, subject, issuer and digest. */
  expectedAttestation?: MembershipAttestation;
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
  if (micros(options.now ?? new Date()) > micros(decision.decision_valid_until)) return reject('decision_expired');
  if (!decisionSigned(decision, options.operatorPublicKeys)) return reject('invalid_signature');
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
}

export interface VerifyEvidenceOptions {
  /** NA keys that sign decisions, justification proofs and retention checkpoints. */
  naPublicKeys: readonly string[];
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

/** Verify stored entries: envelopes, the store chain, every signature, and the decision and resource chains. */
export function verifyEvidenceEvents(
  events: Iterable<EvidenceEvent>,
  options: VerifyEvidenceOptions,
): EvidenceStoreVerification {
  const result: EvidenceStoreVerification = { verified: true, checked_entries: 0, decisions: 0, executions: 0, failures: [] };
  const fail = (storeSequence: number | null, reason: string, detail = '') => {
    result.verified = false;
    result.failures.push({ store_sequence: storeSequence, reason, detail });
  };
  const warn = (storeSequence: number | null, reason: string, detail = '') => {
    (result.warnings ??= []).push({ store_sequence: storeSequence, reason, detail });
  };
  const executorKeys: Record<string, ExecutorKeyInfo> = Array.isArray(options.executorKeys)
    ? Object.fromEntries((options.executorKeys as readonly ExecutorKeyInfo[]).map(k => [k.key_id, k]))
    : options.executorKeys as Record<string, ExecutorKeyInfo>;
  const contiguous = options.contiguous ?? true;
  const checkpoint = options.checkpoint ?? null;

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
  const counts = { observations: 0, break_glass: 0, judgements: 0, quarantined: 0, remediations: 0, reviews: 0 };
  // v1.4.0: judgements and decisions by ID (payload digest, resource), execution evidence's resources,
  // remediated subjects, and operator keys as the holder registry records them.
  const judgedRecords = new Map<string, { digest: string; resource: string | null }>();
  const executed = new Map<string, string | null>();
  const remediated = new Set<string>();
  const operatorKeys = new Map<string, OperatorKeyRecord[]>();
  let firstSequence: number | null = null;
  let fromStart = false;
  let prev: EvidenceEvent['entry'] | null = null;

  if (checkpoint && (!validCheckpoint(checkpoint) || !checkpointSigned(checkpoint, options.naPublicKeys))) {
    fail(null, 'invalid_signature', 'retention_checkpoint');
    return result;
  }
  if (checkpoint && unknownFields('RetentionCheckpoint', checkpoint).length > 0) {
    fail(null, 'unknown_field', unknownFields('RetentionCheckpoint', checkpoint).map(f => `checkpoint.${f}`).join(', '));
    return result;
  }
  for (const event of events) {
    if (!validEvent(event)) {
      result.checked_entries += 1;
      fail(null, 'payload_invalid', 'event envelope');
      continue;
    }
    const entry = event.entry;
    const seq = entry.store_sequence;
    result.checked_entries += 1;
    if (entryDigest(entry) !== event.entry_digest) fail(seq, 'entry_digest_mismatch');
    if (payloadDigest(event.payload) !== entry.payload_digest) fail(seq, 'payload_digest_mismatch');
    if (prev && (contiguous || seq === prev.store_sequence + 1)) {
      if (seq !== prev.store_sequence + 1) fail(seq, 'store_sequence_gap');
      else if (entry.prev_entry_digest !== entryDigest(prev)) fail(seq, 'store_chain_break');
    } else if (!prev && checkpoint && seq === checkpoint.removed_through_sequence + 1) {
      if (entry.prev_entry_digest !== checkpoint.last_removed_entry_digest) {
        fail(seq, 'store_chain_break', 'does not continue from the checkpoint');
      }
    }
    if (firstSequence === null) {
      firstSequence = seq;
      fromStart = seq === 1 || (checkpoint !== null && seq === checkpoint.removed_through_sequence + 1);
    }
    prev = entry;
    const kind = entry.entry_kind;
    const validPayload = isKnownEntryKind(kind) && Object.hasOwn(PAYLOAD_CHECKS, kind) ? PAYLOAD_CHECKS[kind] : undefined;
    if (!validPayload) {
      // v1.2.0: a kind from a later release; its envelope still chains.
      fail(seq, 'unknown_entry_kind', String(kind));
      continue;
    }

    const checked = checkPayloadFields(kind, event.payload, options.naPublicKeys, executorKeys);
    if (checked.signed.length > 0) {
      fail(seq, 'unknown_field', checked.signed.join(', '));
      continue;
    }
    if (checked.unsigned.length > 0) warn(seq, 'unsigned_field', checked.unsigned.join(', '));
    if (checked.unsigned.length > 0 && kind in OUT_OF_BAND_MODELS) {
      // v1.3.0: the reference stores these records exactly as signed; a field outside the
      // signature is no part of one (the reference refuses it as it reads the record).
      fail(seq, 'payload_invalid', checked.unsigned.join(', '));
      continue;
    }
    const payload = checked.payload;
    if (!validPayload(payload)) {
      fail(seq, 'payload_invalid');
      continue;
    }
    const record = (kind === 'decision' ? payload['decision'] : payload) as Record<string, unknown>;
    // v1.3.0: a record whose signature covers it as received, in a form the reference
    // does not write, is refused by name, as the reference refuses it. v1.3.1: also when
    // fields outside the signature were set aside: what the signer signed is checked.
    const signature = (signed: boolean, model: string) => {
      if (!signed) fail(seq, 'invalid_signature', kind);
      else if (nonCanonicalFields(model, record).length > 0) fail(seq, 'non_canonical_form', kind);
    };
    // v1.3.1: a record's ID appears once per kind: a copy is a replay, still checked like any record.
    const recordId = String(record[RECORD_ID[kind]!]);
    const seen = recordIds.get(kind) ?? new Set<string>();
    if (seen.has(recordId)) fail(seq, 'duplicate_record', `${kind} ${recordId}`);
    recordIds.set(kind, seen.add(recordId));
    // v1.3.1: a Stage 2 entry's envelope names what its record says (an absent field is null).
    const envelope = Object.hasOwn(ENVELOPE_FIELDS, kind) ? ENVELOPE_FIELDS[kind]! : {};
    const envelopeFields = entry as unknown as Record<string, unknown>;
    const wrong = Object.keys(envelope).filter(field => (envelopeFields[field] ?? null) !== (payload[envelope[field]!] ?? null));
    if (wrong.length > 0) fail(seq, 'envelope_mismatch', `${kind}: ${wrong.join(', ')}`);
    switch (kind) {
      case 'decision': {
        const model = record as unknown as BoundaryDecision;
        signature(verifyDecisionSignature(model, options.naPublicKeys), 'BoundaryDecision');
        result.decisions += 1;
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
        signature(verifyJustificationSignature(payload as unknown as DecisionJustification, options.naPublicKeys),
          'JustificationProof');
        break;
      case 'execution': {
        const ev = payload as unknown as ExecutionEvidence;
        const key = keyNamed(executorKeys, ev.signature?.key_id);
        // v1.3.0: only an executor key signs execution evidence.
        signature(!!key && key.executor_sovereign_id === ev.executor_sovereign_id
          && (key.role ?? 'executor') === 'executor' && verifyExecutionSignature(ev, key.public_key), 'ExecutionEvidence');
        result.executions += 1;
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
        }
        // v1.3.0: execution evidence never rests on a judgement or a record of one.
        if (notDecisions.has(ev.decision_id)) fail(seq, 'evidence_cites_judgement', ev.decision_id);
        const prior = lastExec.get(ev.decision_id);
        if (prior) {
          if (ev.sequence_no !== prior.sequence_no + 1 || (ev.prev_evidence_digest ?? null) !== executionDigest(prior)) {
            fail(seq, 'evidence_chain_break');
          }
        } else if (decision && (ev.sequence_no !== 1 || (ev.prev_evidence_digest ?? null) !== null)) {
          fail(seq, 'evidence_chain_break');
        }
        lastExec.set(ev.decision_id, ev);
        matchable.add(ev.evidence_id);
        executed.set(ev.evidence_id, ev.resource_id ?? null);
        if (ev.resource_id !== undefined && ev.resource_id !== null) {
          const head = resourceHeads.get(ev.resource_id);
          // v1.3.1: a run that starts neither at entry 1 nor right after the checkpoint takes
          // the first record it holds of a resource as that chain's start.
          if (head || fromStart) {
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
        signature(verifyRetentionCheckpoint(cp, options.naPublicKeys), 'RetentionCheckpoint');
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
        break;
      }
      case 'observation':
      case 'break_glass': {
        signature(outOfBandSigned(kind, payload, options.naPublicKeys, executorKeys), OUT_OF_BAND_MODELS[kind]!);
        subjects.set(subjectKey(kind, recordId), { digest: entry.payload_digest, sequence: seq });
        notDecisions.add(recordId);
        if (kind === 'observation') {
          counts.observations += 1;
          const resource = (payload as unknown as ObservationRecord).resource_id;
          const position = entry.observation_sequence ?? null;
          if (observationHeads.has(resource) || fromStart) {
            if (position !== (observationHeads.get(resource) ?? 0) + 1) fail(seq, 'observation_chain_break', resource);
          }
          observationHeads.set(resource, position || (observationHeads.get(resource) ?? 0));
        } else {
          counts.break_glass += 1;
          matchable.add(recordId);
        }
        break;
      }
      case 'judgement': {
        signature(outOfBandSigned('judgement', payload, options.naPublicKeys, executorKeys), 'JudgementRecord');
        const judgement = payload as unknown as JudgementRecord;
        counts.judgements += 1;
        notDecisions.add(judgement.judgement_id);
        judgedRecords.set(judgement.judgement_id, { digest: entry.payload_digest, resource: judgement.resource_id });
        const key = subjectKey(judgement.subject_kind, judgement.subject_id);
        if (judged.has(key)) fail(seq, 'duplicate_judgement', judgement.subject_id);
        judged.add(key);
        const subject = subjects.get(key);
        if (subject) {
          if (subject.digest !== judgement.subject_digest || subject.sequence !== judgement.subject_store_sequence) {
            fail(seq, 'judgement_subject_mismatch', judgement.subject_id);
          }
        } else if (contiguous && firstSequence !== null && judgement.subject_store_sequence >= firstSequence) {
          fail(seq, 'judgement_subject_missing', judgement.subject_id);
        }
        const match = judgement.matched_evidence_id;
        if (match !== undefined && match !== null) {
          if (matched.has(match)) fail(seq, 'match_reused', match);
          matched.add(match);
          // v1.3.1: the NA matches a record it already holds, so a run from entry 1 holds it.
          if (contiguous && firstSequence === 1 && !matchable.has(match)) fail(seq, 'judgement_match_missing', match);
        }
        break;
      }
      case 'quarantine': {
        signature(outOfBandSigned('quarantine', payload, options.naPublicKeys, executorKeys), 'QuarantineRecord');
        counts.quarantined += 1;
        const quarantine = payload as unknown as QuarantineRecord;
        if (payloadDigest(quarantine.record) !== quarantine.record_digest) fail(seq, 'quarantine_digest_mismatch');
        break;
      }
      case 'registry': {
        signature(outOfBandSigned('registry', payload, options.naPublicKeys, executorKeys), 'RegistryRecord');
        const registry = payload as unknown as RegistryRecord;
        if (registry.event === 'operator_key_holder' && registry.key_id != null) {
          const list = operatorKeys.get(registry.key_id) ?? [];
          list.push({ at: micros(registry.effective_at), public_key: registry.public_key ?? null, holder: registry.holder ?? null });
          operatorKeys.set(registry.key_id, list);
        }
        break;
      }
      case 'remediation': {
        // v1.4.0: signed by an executor key of the record's sovereign, as execution evidence is.
        signature(outOfBandSigned('remediation', payload, options.naPublicKeys, executorKeys), 'RemediationRecord');
        counts.remediations += 1;
        const remediation = payload as unknown as RemediationRecord;
        notDecisions.add(remediation.remediation_id);
        checkRemediationEntry(seq, remediation, fail, judgedRecords, executed, remediated,
          contiguous && firstSequence === 1);
        break;
      }
      case 'review': {
        signature(outOfBandSigned('review', payload, options.naPublicKeys, executorKeys), 'ReviewRecord');
        counts.reviews += 1;
        const review = payload as unknown as ReviewRecord;
        notDecisions.add(review.review_id);
        checkReviewEntry(seq, review, fail, judgedRecords, remediated, operatorKeys, options.naPublicKeys,
          contiguous && firstSequence === 1);
        break;
      }
    }
  }
  for (const [name, count] of Object.entries(counts)) {
    if (count > 0) result[name as keyof typeof counts] = count;
  }
  return result;
}

type Fail = (storeSequence: number | null, reason: string, detail?: string) => void;
type JudgedRecords = ReadonlyMap<string, { digest: string; resource: string | null }>;
/** An `operator_key_holder` registry record: when it took effect (microseconds), the key and its holder. */
interface OperatorKeyRecord { at: number; public_key: string | null; holder: string | null }

/**
 * v1.4.0: one remediation per judgement or decision (`duplicate_remediation`), of its judgement's
 * resource (`remediation_subject_mismatch`), after its forward rotation, of the same resource
 * (`remediation_rotation_mismatch`). In a run from entry 1 its subject and rotation are held before
 * it (`remediation_subject_missing`, `remediation_rotation_missing`).
 */
function checkRemediationEntry(
  seq: number,
  record: RemediationRecord,
  fail: Fail,
  judged: JudgedRecords,
  executed: ReadonlyMap<string, string | null>,
  remediated: Set<string>,
  heldFromStart: boolean,
): void {
  if (remediated.has(record.subject_id)) fail(seq, 'duplicate_remediation', record.subject_id);
  remediated.add(record.subject_id);
  const subject = judged.get(record.subject_id);
  if (subject === undefined) {
    if (heldFromStart) fail(seq, 'remediation_subject_missing', record.subject_id);
  } else if (record.subject_kind === 'judgement' && subject.resource !== record.resource_id) {
    fail(seq, 'remediation_subject_mismatch', record.subject_id);
  }
  const rotation = record.rotation_evidence_id;
  if (rotation !== undefined && rotation !== null) {
    if (executed.has(rotation)) {
      if (executed.get(rotation) !== record.resource_id) fail(seq, 'remediation_rotation_mismatch', rotation);
    } else if (heldFromStart) {
      fail(seq, 'remediation_rotation_missing', rotation);
    }
  }
}

/**
 * v1.4.0: a review's embedded admin requests verify offline (`review_approval_invalid`), with the
 * public key and holder the holder registry last recorded for each operator key by then, when the
 * run holds a record for that key (`review_approval_key_mismatch`); a second holder decided it
 * (`review_same_holder`); it names its subject's digest (`review_subject_mismatch`;
 * `review_subject_missing` in a run from entry 1); and no waiver follows a recorded remediation
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

/** v1.3.1: judgement subjects are keyed by kind and ID: a break-glass record may share an observation's ID. */
function subjectKey(kind: string, id: string): string {
  return `${kind}\u0000${id}`;
}

/** Each known entry kind's payload check: the record in the shape the reference reads. */
const PAYLOAD_CHECKS: Record<string, (payload: Record<string, unknown>) => boolean> = {
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
};

/** v1.3.1: the field holding each kind's record ID, which appears once per kind in a run (`duplicate_record`). */
const RECORD_ID: Record<string, string> = {
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
};

/**
 * v1.3.1: envelope field -> record field, for the envelope fields the NA
 * derives from a Stage 2 record. The NA searches and matches on them, so each
 * must name what the signed record says (`envelope_mismatch`).
 */
const ENVELOPE_FIELDS: Record<string, Record<string, string>> = {
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
};

/** v1.3.0: the model each Stage 2 entry kind holds (v1.4.0: and each Stage 3 kind, stored exactly as signed too). */
const OUT_OF_BAND_MODELS: Record<string, string> = {
  observation: 'ObservationRecord',
  break_glass: 'BreakGlassRecord',
  judgement: 'JudgementRecord',
  quarantine: 'QuarantineRecord',
  registry: 'RegistryRecord',
  remediation: 'RemediationRecord',
  review: 'ReviewRecord',
};

/** Kinds signed by a registered key, and the role that key must have; the other Stage 2 and 3 kinds are signed by the NA. */
const KEY_ROLES: Record<string, 'executor' | 'observer'> = {
  observation: 'observer', break_glass: 'executor', remediation: 'executor',
};

/** The keys that may sign a Stage 2 record: the registered key it names (with the right sovereign and role), or the NA's. */
function outOfBandKeys(
  kind: string,
  payload: Record<string, unknown>,
  naPublicKeys: readonly string[],
  executorKeys: Record<string, ExecutorKeyInfo>,
): readonly string[] {
  const role = KEY_ROLES[kind];
  if (role === undefined) return naPublicKeys;
  const signature = payload['signature'] as Signature | null | undefined;
  const key = keyNamed(executorKeys, signature?.key_id);
  const sovereign = kind === 'observation' ? payload['observer_sovereign_id'] : payload['executor_sovereign_id'];
  return key && key.executor_sovereign_id === sovereign && (key.role ?? 'executor') === role ? [key.public_key] : [];
}

/** Whether a Stage 2 record's signature covers it as received, under the key that may sign it. */
function outOfBandSigned(
  kind: string,
  payload: Record<string, unknown>,
  naPublicKeys: readonly string[],
  executorKeys: Record<string, ExecutorKeyInfo>,
): boolean {
  return signedBy(outOfBandCanonical(payload), payload['signature'] as Signature | null | undefined,
    outOfBandKeys(kind, payload, naPublicKeys, executorKeys))
    && unknownFields(OUT_OF_BAND_MODELS[kind]!, payload).length === 0;
}

const PAYLOAD_MODELS: Record<string, string> = {
  justification: 'JustificationProof',
  execution: 'ExecutionEvidence',
  retention_checkpoint: 'RetentionCheckpoint',
  ...OUT_OF_BAND_MODELS,
};

interface CheckedPayload {
  /** Unknown fields the signature covers: an authentic record from a newer signer. */
  signed: string[];
  /** Unknown fields outside the signature (stored before 1.1.1, or in a decision's wrapper): reported, then ignored. */
  unsigned: string[];
  /** The payload to verify further: without its unsigned unknown fields. */
  payload: Record<string, unknown>;
}

/** Sort an export payload's unknown fields into signed (refused) and unsigned (reported, removed). */
function checkPayloadFields(
  kind: string,
  payload: Record<string, unknown>,
  naPublicKeys: readonly string[],
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
  const found = model ? unknownFields(model, payload) : [];
  if (!model || found.length === 0) return { signed: [], unsigned: [], payload };
  let signedAsReceived = false;
  if (kind === 'execution') {
    const ev = payload as unknown as ExecutionEvidence;
    const key = keyNamed(executorKeys, ev.signature?.key_id);
    signedAsReceived = !!key && signedBy(executionCanonical(ev), ev.signature, [key.public_key]);
  } else if (kind === 'justification') {
    signedAsReceived = signedBy(justificationCanonical(payload as unknown as DecisionJustification),
      (payload as unknown as DecisionJustification).signature, naPublicKeys);
  } else if (kind in OUT_OF_BAND_MODELS) {
    // The key the signature names, whatever its role: an authentic record with a field this SDK
    // does not know is refused by name first, as the reference refuses it.
    const signature = payload['signature'] as Signature | null | undefined;
    const named = keyNamed(executorKeys, signature?.key_id);
    const keys = KEY_ROLES[kind] === undefined ? naPublicKeys : named ? [named.public_key] : [];
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
  offererPublicKeys: readonly string[],
  responderPublicKeys: readonly string[],
  expectedGraphDigest?: string,
): AgreementVerification {
  const result = (accepted: boolean, reason: AgreementVerificationReason) =>
    ({ accepted, reason, agreement_id: record.agreement_id });
  // 1.3.1: `signatures` that is not a list holds no signature (it threw a TypeError).
  const signatures = signatureList(record.signatures);
  if (signatures.length === 0) return result(false, 'missing_offerer_signature');
  const canonical = agreementCanonical(record);
  if (!anySigned(canonical, signatures, offererPublicKeys)) return result(false, 'invalid_offerer_signature');
  if (!anySigned(canonical, signatures, responderPublicKeys)) {
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
