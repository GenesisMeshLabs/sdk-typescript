import { validDecision, validContext, validExecution, validJustification, validCheckpoint, validEvent, timestamp } from './validation.js';
/**
 * Offline verification of NA-signed artifacts and evidence exports.
 * Direct ports of the Python reference with the same reason codes:
 *   verifyBoundaryDecision  - trust/context/decisions.py verify_boundary_decision
 *   verifyEvidenceEvents    - trust/evidence_store.py verify_evidence_events
 * No network access; every key is supplied by the caller.
 */

import { compareCodePoints, parseJson, verifyCanonical } from './auth.js';
import { isKnownEntryKind, unknownFields, withoutUnknownFields } from './strict.js';
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

function anySigned(canonical: string, signatures: readonly Signature[] | undefined, keys: readonly string[]): boolean {
  return (signatures ?? []).some(sig => verifyCanonical(canonical, sig.sig, keys));
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

/** Parse `gm.evidence.event` JSON Lines (blank lines ignored). */
export function parseExportLines(text: string | Iterable<string>): EvidenceEvent[] {
  const lines = typeof text === 'string' ? text.split('\n') : text;
  const events: EvidenceEvent[] = [];
  for (const raw of lines) {
    const line = raw.trim();
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
    prev = entry;
    if (!isKnownEntryKind(entry.entry_kind)) {
      // v1.2.0: a kind from a later release; its envelope still chains.
      fail(seq, 'unknown_entry_kind', String(entry.entry_kind));
      continue;
    }

    const checked = checkPayloadFields(entry.entry_kind, event.payload, options.naPublicKeys, executorKeys);
    if (checked.signed.length > 0) {
      fail(seq, 'unknown_field', checked.signed.join(', '));
      continue;
    }
    if (checked.unsigned.length > 0) warn(seq, 'unsigned_field', checked.unsigned.join(', '));
    const payload = checked.payload;
    switch (entry.entry_kind) {
      case 'decision': {
        const decision = payload['decision'];
        if (!validDecision(decision)) {
          fail(seq, 'payload_invalid');
          break;
        }
        const model = decision as unknown as BoundaryDecision;
        if (!verifyDecisionSignature(model, options.naPublicKeys)) fail(seq, 'invalid_signature', 'decision');
        result.decisions += 1;
        decisions.set(model.decision_id, model);
        const context = payload['context'];
        if (validContext(context)) {
          contexts.set(model.decision_id, context as unknown as ContextRecord);
        } else {
          fail(seq, 'payload_invalid', 'context');
        }
        break;
      }
      case 'justification': {
        if (!validJustification(payload)) {
          fail(seq, 'payload_invalid');
          break;
        }
        if (!verifyJustificationSignature(payload as unknown as DecisionJustification, options.naPublicKeys)) {
          fail(seq, 'invalid_signature', 'justification');
        }
        break;
      }
      case 'execution': {
        if (!validExecution(payload)) {
          fail(seq, 'payload_invalid');
          break;
        }
        const ev = payload as unknown as ExecutionEvidence;
        const key = ev.signature ? executorKeys[ev.signature.key_id] : undefined;
        if (!key || key.executor_sovereign_id !== ev.executor_sovereign_id || !verifyExecutionSignature(ev, key.public_key)) {
          fail(seq, 'invalid_signature', 'execution');
        }
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
        const prior = lastExec.get(ev.decision_id);
        if (prior) {
          if (ev.sequence_no !== prior.sequence_no + 1 || ev.prev_evidence_digest !== executionDigest(prior)) {
            fail(seq, 'evidence_chain_break');
          }
        } else if (decision && (ev.sequence_no !== 1 || ev.prev_evidence_digest !== null)) {
          fail(seq, 'evidence_chain_break');
        }
        lastExec.set(ev.decision_id, ev);
        if (ev.resource_id !== undefined && ev.resource_id !== null) {
          const head = resourceHeads.get(ev.resource_id);
          const expected = head ? head.resource_sequence + 1 : 1;
          if (ev.resource_sequence !== expected || (ev.prev_resource_digest ?? null) !== (head ? head.record_digest : null)) {
            fail(seq, 'resource_chain_break', ev.resource_id);
          }
          resourceHeads.set(ev.resource_id, { resource_sequence: ev.resource_sequence ?? 0, record_digest: executionDigest(ev) });
        }
        break;
      }
      case 'retention_checkpoint': {
        if (!validCheckpoint(payload)) {
          fail(seq, 'payload_invalid');
          break;
        }
        if (!verifyRetentionCheckpoint(payload as unknown as RetentionCheckpoint, options.naPublicKeys)) {
          fail(seq, 'invalid_signature', 'retention_checkpoint');
        }
        break;
      }
      default:
        fail(seq, 'unknown_entry_kind', String(entry.entry_kind));
    }
  }
  return result;
}

const PAYLOAD_MODELS: Record<string, string> = {
  justification: 'JustificationProof',
  execution: 'ExecutionEvidence',
  retention_checkpoint: 'RetentionCheckpoint',
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
    const key = ev.signature ? executorKeys[ev.signature.key_id] : undefined;
    signedAsReceived = !!key && signedBy(executionCanonical(ev), ev.signature, [key.public_key]);
  } else if (kind === 'justification') {
    signedAsReceived = signedBy(justificationCanonical(payload as unknown as DecisionJustification),
      (payload as unknown as DecisionJustification).signature, naPublicKeys);
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
  | 'unknown_field';

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
  const signatures = record.signatures ?? [];
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
  return result(true, 'accepted');
}

// ── Data usage (v0.61) ────────────────────────────────────────────────────────

/** True when the licensor signed the DataLicensePolicy. */
export function verifyDataLicensePolicySignature(policy: DataLicensePolicy, licensorPublicKeys: readonly string[]): boolean {
  return signedBy(dataLicensePolicyCanonical(policy), policy.signature, licensorPublicKeys)
    && unknownFields('DataLicensePolicy', policy).length === 0;
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
  // v1.2.0: fields this SDK does not know, as the reference reports them.
  const intentUnknown = unknownFields('DataAccessIntent', intent);
  if (intentUnknown.length > 0 && !signedBy(dataAccessIntentCanonical(intent), intent.signature, agentPublicKeys)) {
    return fail([{ violation_type: 'intent_exceeds_license', detail: 'Invalid intent signature' }]);
  }
  const unknown = [...intentUnknown, ...unknownFields('DataLicensePolicy', policy, 'policy.')].sort();
  if (unknown.length > 0) {
    return fail([{ violation_type: 'intent_exceeds_license', detail: `Unknown field: ${unknown.join(', ')}` }]);
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
