/** Runtime checks for complete wire artifacts, without coercion or mutation of signed JSON. */
import { isParsedFloat } from './auth.js';

type Check = (value: unknown) => boolean;
const string: Check = v => typeof v === 'string';
const boolean: Check = v => typeof v === 'boolean';
const integer: Check = v => Number.isSafeInteger(v);
const positive: Check = v => integer(v) && (v as number) > 0;
const nonnegative: Check = v => integer(v) && (v as number) >= 0;
export const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const nullable = (check: Check): Check => v => v === null || check(v);
const optional = (check: Check): Check => v => v === undefined || check(v);
/**
 * A field the reference always writes, as null when it has no value (1.3.1). Left out,
 * the record still reads as the reference reads it (the field is null), so its signature
 * decides the reason: `invalid_signature`, or `non_canonical_form` when it was signed
 * without the field (`nonCanonicalFields`), as the reference refuses it; not
 * `payload_invalid`.
 */
const written = (check: Check): Check => optional(nullable(check));
const array = (check: Check): Check => v => Array.isArray(v) && v.every(check);
const oneOf = (...values: unknown[]): Check => v => values.includes(v);
const dictionary = (check: Check): Check => v => isObject(v) && Object.values(v).every(check);
// Own properties only (1.3.1): a key named `constructor` or `toString` is a field like any other.
const own = (v: Record<string, unknown>, k: string): unknown => (Object.hasOwn(v, k) ? v[k] : undefined);
const shape = (fields: Record<string, Check>, exact = false): Check => v =>
  isObject(v) && Object.entries(fields).every(([k, check]) => check(own(v, k)))
  && (!exact || Object.keys(v).every(k => Object.hasOwn(fields, k)));

export const timestamp: Check = v => {
  if (typeof v !== 'string') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?:Z|[+-](\d{2}):(\d{2}))?$/.exec(v);
  if (!match) return false;
  const [, y, m, d, h, min, sec, zh = '0', zm = '0'] = match;
  const days = new Date(Date.UTC(Number(y), Number(m), 0)).getUTCDate();
  return Number(m) >= 1 && Number(m) <= 12 && Number(d) >= 1 && Number(d) <= days
    && Number(h) < 24 && Number(min) < 60 && Number(sec) < 60 && Number(zh) < 24 && Number(zm) < 60
    && Number.isFinite(Date.parse(v.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(v) ? v : v + 'Z'));
};
const signature = nullable(shape({ key_id: string, sig: string }));
const gateResult = shape({ gate_name: string, passed: boolean, detail: string });
const appliedPolicy = shape({ policy_id: string, version: positive, policy_digest: string, signed_by: string });
const policyGate = shape({
  policy_id: string, policy_version: positive, gate_id: string, gate_type: string, order: nonnegative,
  mode: oneOf('observe', 'enforce'), passed: boolean,
  outcome: oneOf('pass', 'fail', 'missing_context', 'invalid_context', 'gate_error'),
});
const policyBinding = shape({
  policies: array(appliedPolicy), policy_set_digest: string, gate_evaluations: array(policyGate),
  context_digest: string, registry_gate_types: array(string), resolution_status: oneOf('resolved', 'failed'),
  resolution_failure: written(string),
});
const attestationBinding = shape({
  attestation_id: string, subject_id: written(string), issuer_sovereign_id: written(string),
  attestation_digest: written(string), revocation_seq_checked: nonnegative,
});
const freshnessProof = shape({
  proof_id: string, feed_sovereign_id: string, feed_sequence: nonnegative, feed_digest: string,
  attested_at: timestamp, proof_valid_until: timestamp, issuer_sovereign_id: string,
  signature: optional(signature),
});
export const validDecision = shape({
  decision_id: string, context_id: string, agreement_id: string, authorized: boolean,
  // Absent is read as absent, so a decision whose signature covers a null fails at the signature.
  denial_reason: optional(nullable(string)), gate_results: array(gateResult), decision_made_at: timestamp,
  decision_valid_until: timestamp, operator_sovereign_id: string, freshness_proof: optional(nullable(freshnessProof)),
  policy_binding: optional(nullable(policyBinding)), attestation_binding: optional(nullable(attestationBinding)),
  signature: optional(signature),
});
export const validContext = shape({
  context_id: string, agreement_id: string, parent_kind: string, requester_sovereign_id: string,
  provider_sovereign_id: string, requested_capability: string, request_parameters: isObject,
  requested_at: timestamp, context_freshness_seq: nonnegative, attributes: isObject,
  attestation_id: optional(nullable(string)),
});
const action = oneOf('create', 'rotate', 'revoke', 'update', 'delete');
export const validExecution = shape({
  evidence_id: string, sequence_no: positive, decision_id: string, context_id: string, agreement_id: string,
  executor_sovereign_id: string, executed_capability: string, execution_parameters: isObject,
  executed_at: timestamp, outcome: string, outcome_detail: written(string), prev_evidence_digest: written(string),
  resource_id: optional(nullable(v => string(v) && (v as string).length > 0 && Array.from(v as string).length <= 256)),
  resource_action: optional(nullable(action)), resource_sequence: optional(nullable(positive)),
  prev_resource_digest: optional(nullable(string)), signature: optional(signature),
});
const gateTraceEntry = shape({
  gate_name: string, gate_type: string, evaluated_at: timestamp, inputs: isObject,
  result: boolean, reason: string, metadata: isObject,
});
export const validJustification = shape({
  proof_id: string, decision_id: string, proof_issued_at: timestamp, issuer_sovereign_id: string,
  signature: optional(signature), trace: shape({
    trace_id: string, decision_id: string, agreement_id: string, operator_sovereign_id: string,
    traced_at: timestamp, entries: array(gateTraceEntry), short_circuited_at: written(string), final_authorized: boolean,
  }),
});
export const validCheckpoint = shape({
  checkpoint_id: string, created_at: timestamp, cutoff: timestamp, removed_through_sequence: nonnegative,
  last_removed_entry_digest: string, removed_count: nonnegative, previous_checkpoint_id: written(string),
  issued_by: string, signature: optional(signature),
  resource_heads: dictionary(shape({ resource_sequence: positive, record_digest: string }, true)),
  observation_heads: optional(nullable(dictionary(nonnegative))),
});
const entry = shape({
  store_sequence: positive, entry_kind: string,
  recorded_at: timestamp, payload_digest: string, prev_entry_digest: nullable(string),
  decision_id: nullable(string), context_id: nullable(string), vendor_id: nullable(string),
  attestation_id: nullable(string), capability: nullable(string), outcome: nullable(string),
  evidence_id: nullable(string), executor_sovereign_id: nullable(string), exec_sequence_no: nullable(integer),
  resource_id: nullable(string), resource_action: nullable(string), resource_sequence: nullable(integer),
  // v1.3.0, left out when absent (a null reads as absent, as the reference reads it).
  record_id: optional(nullable(string)), subject_id: optional(nullable(string)),
  matched_evidence_id: optional(nullable(string)), observation_sequence: optional(nullable(positive)),
}, true);
// v1.3.0: records of changes made outside the controlled path. An absent
// optional field is left out of the signed form; a null reads as absent.
const absent = (check: Check): Check => optional(nullable(check));
/** A string of `min` to `max` characters, counted as the reference counts them (code points). */
const bounded = (max: number, min = 1): Check => v => {
  if (!string(v)) return false;
  const length = Array.from(v as string).length;
  return length >= min && length <= max;
};
/** The reference keeps 1.3.0 records' timestamps in UTC. */
const utc: Check = v => timestamp(v) && /(?:Z|[+-]00:00)$/.test(v as string);
/** Fields the reference fills when absent: left out, the record is not in its form (`non_canonical_form`). */
const filled = (check: Check): Check => optional(check);
const sha256 = bounded(64, 64);
const verdict = oneOf('allow', 'deny', 'indeterminate');
const observationFields = shape({
  observation_id: bounded(128), observer_sovereign_id: bounded(256), resource_id: bounded(256), action,
  capability: bounded(256), changed_at: absent(utc), changed_not_before: absent(utc),
  changed_not_after: absent(utc), observed_at: utc, actor: absent(bounded(256)), source: bounded(128),
  source_event_id: bounded(256), version_id: absent(bounded(256)), metadata: filled(isObject),
  signature: optional(signature),
});
/** An observation names its change time, or both ends of a window in order, never both. */
export const validObservation: Check = v => {
  if (!observationFields(v)) return false;
  const r = v as Record<string, unknown>;
  const given = (k: string) => r[k] !== undefined && r[k] !== null;
  if (given('changed_at')) return !given('changed_not_before') && !given('changed_not_after');
  if (!given('changed_not_before') || !given('changed_not_after')) return false;
  return timestampOrder(r['changed_not_before'] as string, r['changed_not_after'] as string) <= 0;
};

/**
 * Compare two timestamps with an offset to the microsecond, as the reference
 * compares them (1.3.1; `Date` keeps milliseconds): negative, zero or positive.
 */
export function timestampOrder(a: string, b: string): number {
  const seconds = (t: string) => Date.parse(t.replace(/\.\d+/, ''));
  const micros = (t: string) => Number((/\.(\d+)/.exec(t)?.[1] ?? '').slice(0, 6).padEnd(6, '0'));
  return seconds(a) - seconds(b) || micros(a) - micros(b);
}
export const validBreakGlass = shape({
  break_glass_id: bounded(128), executor_sovereign_id: bounded(256), resource_id: bounded(256), resource_action: action,
  capability: bounded(256), attestation_id: absent(bounded(128)), request_parameters: filled(isObject),
  attributes: filled(isObject), justification: bounded(1024), evaluation_request_digest: sha256,
  evaluation_failure: oneOf('network_error', 'timeout', 'server_error', 'rate_limited'), executed_at: utc,
  outcome: string, outcome_detail: absent(bounded(1024, 0)), execution_parameters: filled(isObject),
  signature: optional(signature),
});
export const validJudgement = shape({
  judgement_id: bounded(128), subject_kind: oneOf('observation', 'break_glass'), subject_id: bounded(128),
  subject_digest: sha256, subject_store_sequence: positive, resource_id: bounded(256), action, capability: bounded(256),
  governed_by: oneOf('prior_decision', 'after_the_fact'), verdict, reason: absent(bounded(1024, 0)),
  evaluated_as_of: utc, evaluated_from: absent(utc), policy_binding: absent(policyBinding),
  gate_results: filled(array(gateResult)), current_verdict: absent(verdict), current_policy_set_digest: absent(string),
  flagged_for_review: absent(boolean), matched_evidence_id: absent(string), matched_decision_id: absent(string),
  possible_match_evidence_id: absent(string), judged_at: utc, issuer_sovereign_id: string, issued_by: string,
  signature: optional(signature),
});
export const validQuarantine = shape({
  // v1.4.0: a refused remediation record is kept too.
  quarantine_id: bounded(128), record_kind: oneOf('execution', 'observation', 'break_glass', 'remediation'), record: isObject,
  record_digest: sha256, rejection_code: bounded(128), detail: filled(bounded(1024, 0)), resource_id: absent(bounded(256)),
  quarantined_at: utc, issuer_sovereign_id: string, issued_by: string, signature: optional(signature),
});
export const validRegistry = shape({
  registry_record_id: bounded(128),
  event: oneOf('policy_history_started', 'policy_activated', 'policy_deactivated', 'executor_key_registered',
    'executor_key_retired', 'operator_key_holder'),
  effective_at: utc, reconstructed: absent(boolean), policy_id: absent(string), policy_version: absent(positive),
  policy_digest: absent(string), key_id: absent(string), public_key: absent(string), executor_sovereign_id: absent(string),
  key_role: absent(oneOf('executor', 'observer')), resource_prefix: absent(string), operator_tier: absent(string),
  holder: absent(string), approved_by: absent(string), recorded_by: absent(string), issuer_sovereign_id: string,
  issued_by: string, signature: optional(signature),
});

// v1.4.0: remediations and reviews of changes governed after the fact.
/** An operator's signed admin request, kept whole (no other field). */
export const validAdminApproval: Check = shape({
  key_id: bounded(256), public_key: bounded(256), method: bounded(16), path: bounded(2048),
  query: filled(dictionary(array(string))), audience: bounded(256), body: filled(isObject), timestamp: bounded(256),
  nonce: bounded(256), admin_signature: bounded(256),
}, true);
const remediationFields = shape({
  remediation_id: bounded(128), executor_sovereign_id: bounded(256), subject_kind: oneOf('judgement', 'decision'),
  subject_id: bounded(128), change_kind: oneOf('observation', 'break_glass', 'execution'), change_id: bounded(128),
  resource_id: bounded(256), outcome: oneOf('cancelled', 'alerted'),
  steps: oneOf('rotate_forward_then_disable', 'disable', 'delete', 'none'), rotation_evidence_id: absent(bounded(128)),
  version_id: absent(bounded(256)), disabled_version_id: absent(bounded(256)), remediated_at: utc,
  detail: absent(bounded(1024)), signature: optional(signature),
});

/**
 * Why a remediation record's steps do not match its outcome and versions, or
 * null (the reference model's rule): it alerts exactly when nothing changed
 * (`none`); a forward rotation names its evidence, the version it issued and
 * the other one it disabled; nothing else names rotation evidence or a new
 * version; an alert disables nothing.
 */
export function remediationStepsProblem(record: Record<string, unknown>): string | null {
  const given = (k: string) => record[k] !== undefined && record[k] !== null;
  if ((record['outcome'] === 'alerted') !== (record['steps'] === 'none')) {
    return 'an alerted remediation changes nothing (steps none); a cancelled one does';
  }
  if (record['steps'] === 'rotate_forward_then_disable') {
    if (!given('rotation_evidence_id') || !given('version_id') || !given('disabled_version_id')) {
      return 'a forward rotation names its evidence, the version it issued and the one disabled';
    }
    if (record['version_id'] === record['disabled_version_id']) {
      return 'the forward rotation issues another version than the one disabled';
    }
  } else if (given('rotation_evidence_id') || given('version_id')) {
    return 'only a forward rotation names rotation evidence or a new version';
  }
  if (record['steps'] === 'none' && given('disabled_version_id')) return 'an alerted remediation disables nothing';
  return null;
}

/** A remediation record in the shape the reference reads, its steps consistent. */
export const validRemediation: Check = v => remediationFields(v) && remediationStepsProblem(v as Record<string, unknown>) === null;

/** Longest a waiver may run, whatever the NA's configuration (90 days, in microseconds). */
const MAX_WAIVER_MICROS = 90 * 24 * 3600 * 1_000_000;

const reviewFields = shape({
  review_id: bounded(128), subject_kind: oneOf('judgement', 'decision'), subject_id: bounded(128), subject_digest: sha256,
  resource_id: absent(bounded(256)), capability: absent(bounded(256)),
  opened_for: oneOf('requested', 'flagged_for_review', 'review_required'), requested_by: absent(bounded(256)),
  requester_holder: absent(bounded(128)), justification: absent(bounded(1024)), request_approval: absent(validAdminApproval),
  requested_at: utc, actor: absent(bounded(256)), actor_holder: absent(bounded(128)),
  verdict: oneOf('uphold', 'deny', 'waive_until'), waive_until: absent(utc), note: absent(bounded(1024)),
  decided_by: bounded(256), decider_holder: bounded(128), approval: validAdminApproval, decided_at: utc,
  issuer_sovereign_id: string, issued_by: string, signature: optional(signature),
});

/**
 * Why a review's fields do not fit together, or null (the reference model's
 * rule): `waive_until` is given exactly for a waiver, after the decision and
 * within 90 days of it; a requested review names its requester, holder,
 * justification and request, and one the NA opened none of them.
 */
export function reviewConsistencyProblem(record: Record<string, unknown>): string | null {
  const given = (k: string) => record[k] !== undefined && record[k] !== null;
  if ((record['verdict'] === 'waive_until') !== given('waive_until')) return 'waive_until is given exactly for a waiver';
  if (given('waive_until')) {
    const decided = timestampMicros(record['decided_at'] as string);
    const until = timestampMicros(record['waive_until'] as string);
    if (!(decided < until && until <= decided + MAX_WAIVER_MICROS)) {
      return 'a waiver ends after it is decided and within the longest waiver';
    }
  }
  const requested = record['opened_for'] === 'requested';
  const named = ['requested_by', 'requester_holder', 'justification', 'request_approval'].map(given);
  if (requested && named.includes(false)) return 'a requested review names its requester, holder, justification and request';
  if (!requested && named.includes(true)) return 'a review the NA opened has no requester';
  return null;
}

/** A review record in the shape the reference reads, its fields consistent. */
export const validReview: Check = v => reviewFields(v) && reviewConsistencyProblem(v as Record<string, unknown>) === null;

/**
 * Microseconds since the epoch of a timestamp `timestamp` accepts (a value
 * without an offset is UTC), to the microsecond as the reference keeps it.
 */
export function timestampMicros(value: string): number {
  const m = /^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$/.exec(value);
  if (!m) return NaN;
  const [, base, fraction = '', zone = 'Z'] = m;
  return Date.parse(base + zone) * 1000 + Number(fraction.slice(0, 6).padEnd(6, '0'));
}

const eventShape = shape({
  schema: oneOf('gm.evidence.event'), schema_version: oneOf(1), entry,
  entry_digest: string, payload: isObject,
}, true);
/** The envelope's integers, which a float with the same value (`7.0`) does not stand for. */
const ENVELOPE_INTEGERS = ['store_sequence', 'exec_sequence_no', 'resource_sequence', 'observation_sequence'];
/** An export event; `schema_version: 1.0` or an envelope integer written as a float is refused (1.3.1), as the reference refuses it. */
export const validEvent: Check = v => eventShape(v)
  && !isParsedFloat(v as object, 'schema_version')
  && !ENVELOPE_INTEGERS.some(k => isParsedFloat((v as { entry: object }).entry, k));

// v1.5.0: the key history, anchors, archives and audit packs.
const signatures = array(shape({ key_id: string, sig: string }));
/** A genesis block as the reference reads it (unknown fields are ignored, not refused). */
export const validGenesis = shape({
  network_name: string, network_version: string, root_public_key: string,
  network_authority: shape({ public_key: string, valid_from: timestamp, valid_to: timestamp }),
  allowed_crypto_suites: optional(array(string)), allowed_transports: optional(array(string)),
  policy_manifest: shape({ hash: string, url: optional(nullable(string)) }),
  bootstrap_anchors: optional(array(shape({ id: string, endpoint: string }))), signatures: optional(signatures),
});
/** A key succession record (its `succession_id` the reference fills when absent). */
export const validKeySuccession = shape({
  succession_id: filled(bounded(128)), sovereign_id: bounded(256), key_sequence: v => integer(v) && (v as number) >= 2,
  previous_key_id: bounded(128), previous_public_key: bounded(128), previous_succession_digest: absent(sha256),
  new_key_id: bounded(128), new_public_key: bounded(128), effective_at: utc, new_valid_to: utc, issued_at: utc,
  signatures: filled(signatures),
}, true);
export const validAnchor = shape({
  anchor_sequence: positive, sovereign_id: string, store_sequence: positive, entry_digest: string, anchored_at: utc,
  previous_anchor_digest: absent(string), issued_by: string, signature: optional(signature),
}, true);
export const validArchive = shape({
  archive_id: filled(bounded(128)), pack_id: bounded(128), from_sequence: positive, through_sequence: positive,
  through_entry_digest: sha256, end_anchor_sequence: positive, manifest_sha256: sha256, location: bounded(1024),
  archived_at: utc, recorded_by: absent(string), issuer_sovereign_id: string, issued_by: string,
  signature: optional(signature),
}, true);
const packFile = shape({ path: bounded(256), sha256, bytes: nonnegative }, true);
export const validManifest = shape({
  format: filled(oneOf('gm.audit.pack')), format_version: filled(oneOf(1)), pack_id: filled(bounded(128)),
  sovereign_id: bounded(256), created_at: utc, requested_by: absent(bounded(256)), from_sequence: positive,
  through_sequence: positive, start_anchor_sequence: absent(positive), end_anchor_sequence: positive,
  period_from: absent(utc), period_until: absent(utc), files: array(packFile), issued_by: string,
  signature: optional(signature),
}, true);
/** The records an audit pack carries outside the store: what a verifier reads of each. */
export const validPolicyRecord = shape({
  policy_id: string, version: positive, valid_from: timestamp, valid_until: timestamp, issued_at: timestamp,
  issued_by: string, issuer_sovereign_id: string, signature: optional(signature),
});
export const validAttestationRecord = shape({
  attestation_id: string, issuer_sovereign_id: string, subject_id: string, issued_at: timestamp,
  valid_from: timestamp, expires_at: timestamp, issued_by: string, signatures: filled(signatures),
});
export const validTreaty = shape({
  treaty_id: string, issuer_sovereign_id: string, subject_sovereign_id: string, subject_public_keys: array(string),
  issued_at: timestamp, valid_from: timestamp, expires_at: timestamp, issued_by: string, signatures: filled(signatures),
});
export const validFeed = shape({
  feed_id: string, issuer_sovereign_id: string, sequence: nonnegative, issued_at: timestamp, issued_by: string,
  signatures: filled(signatures),
});
