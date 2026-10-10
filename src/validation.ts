/** Runtime checks for complete wire artifacts, without coercion or mutation of signed JSON. */
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
const array = (check: Check): Check => v => Array.isArray(v) && v.every(check);
const oneOf = (...values: unknown[]): Check => v => values.includes(v);
const dictionary = (check: Check): Check => v => isObject(v) && Object.values(v).every(check);
const shape = (fields: Record<string, Check>, exact = false): Check => v =>
  isObject(v) && Object.entries(fields).every(([k, check]) => check(v[k]))
  && (!exact || Object.keys(v).every(k => k in fields));

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
  resolution_failure: nullable(string),
});
const attestationBinding = shape({
  attestation_id: string, subject_id: nullable(string), issuer_sovereign_id: nullable(string),
  attestation_digest: nullable(string), revocation_seq_checked: nonnegative,
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
  executed_at: timestamp, outcome: string, outcome_detail: nullable(string), prev_evidence_digest: nullable(string),
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
    traced_at: timestamp, entries: array(gateTraceEntry), short_circuited_at: nullable(string), final_authorized: boolean,
  }),
});
export const validCheckpoint = shape({
  checkpoint_id: string, created_at: timestamp, cutoff: timestamp, removed_through_sequence: nonnegative,
  last_removed_entry_digest: string, removed_count: nonnegative, previous_checkpoint_id: nullable(string),
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
const bounded = (max: number, min = 1): Check => v => string(v) && (v as string).length >= min && (v as string).length <= max;
const sha256 = bounded(64, 64);
const verdict = oneOf('allow', 'deny', 'indeterminate');
export const validObservation = shape({
  observation_id: bounded(128), observer_sovereign_id: bounded(256), resource_id: bounded(256), action,
  capability: bounded(256), changed_at: absent(timestamp), changed_not_before: absent(timestamp),
  changed_not_after: absent(timestamp), observed_at: timestamp, actor: absent(bounded(256)), source: bounded(128),
  source_event_id: bounded(256), version_id: absent(bounded(256)), metadata: isObject, signature: optional(signature),
});
export const validBreakGlass = shape({
  break_glass_id: bounded(128), executor_sovereign_id: bounded(256), resource_id: bounded(256), resource_action: action,
  capability: bounded(256), attestation_id: absent(bounded(128)), request_parameters: isObject, attributes: isObject,
  justification: bounded(1024), evaluation_request_digest: sha256,
  evaluation_failure: oneOf('network_error', 'timeout', 'server_error', 'rate_limited'), executed_at: timestamp,
  outcome: string, outcome_detail: absent(bounded(1024, 0)), execution_parameters: isObject, signature: optional(signature),
});
export const validJudgement = shape({
  judgement_id: bounded(128), subject_kind: oneOf('observation', 'break_glass'), subject_id: bounded(128),
  subject_digest: sha256, subject_store_sequence: positive, resource_id: bounded(256), action, capability: bounded(256),
  governed_by: oneOf('prior_decision', 'after_the_fact'), verdict, reason: absent(bounded(1024, 0)),
  evaluated_as_of: timestamp, evaluated_from: absent(timestamp), policy_binding: absent(policyBinding),
  gate_results: array(gateResult), current_verdict: absent(verdict), current_policy_set_digest: absent(string),
  flagged_for_review: absent(boolean), matched_evidence_id: absent(string), matched_decision_id: absent(string),
  possible_match_evidence_id: absent(string), judged_at: timestamp, issuer_sovereign_id: string, issued_by: string,
  signature: optional(signature),
});
export const validQuarantine = shape({
  quarantine_id: bounded(128), record_kind: oneOf('execution', 'observation', 'break_glass'), record: isObject,
  record_digest: sha256, rejection_code: bounded(128), detail: bounded(1024, 0), resource_id: absent(bounded(256)),
  quarantined_at: timestamp, issuer_sovereign_id: string, issued_by: string, signature: optional(signature),
});
export const validRegistry = shape({
  registry_record_id: bounded(128),
  event: oneOf('policy_history_started', 'policy_activated', 'policy_deactivated', 'executor_key_registered',
    'executor_key_retired', 'operator_key_holder'),
  effective_at: timestamp, reconstructed: absent(boolean), policy_id: absent(string), policy_version: absent(positive),
  policy_digest: absent(string), key_id: absent(string), public_key: absent(string), executor_sovereign_id: absent(string),
  key_role: absent(oneOf('executor', 'observer')), resource_prefix: absent(string), operator_tier: absent(string),
  holder: absent(string), approved_by: absent(string), recorded_by: absent(string), issuer_sovereign_id: string,
  issued_by: string, signature: optional(signature),
});

export const validEvent = shape({
  schema: oneOf('gm.evidence.event'), schema_version: oneOf(1), entry,
  entry_digest: string, payload: isObject,
}, true);
