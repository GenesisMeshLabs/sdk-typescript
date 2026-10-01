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
  denial_reason: nullable(string), gate_results: array(gateResult), decision_made_at: timestamp,
  decision_valid_until: timestamp, operator_sovereign_id: string, freshness_proof: nullable(freshnessProof),
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
});
const entry = shape({
  store_sequence: positive, entry_kind: oneOf('decision', 'justification', 'execution', 'retention_checkpoint'),
  recorded_at: timestamp, payload_digest: string, prev_entry_digest: nullable(string),
  decision_id: nullable(string), context_id: nullable(string), vendor_id: nullable(string),
  attestation_id: nullable(string), capability: nullable(string), outcome: nullable(string),
  evidence_id: nullable(string), executor_sovereign_id: nullable(string), exec_sequence_no: nullable(integer),
  resource_id: nullable(string), resource_action: nullable(string), resource_sequence: nullable(integer),
}, true);
export const validEvent = shape({
  schema: oneOf('gm.evidence.event'), schema_version: oneOf(1), entry,
  entry_digest: string, payload: isObject,
}, true);
