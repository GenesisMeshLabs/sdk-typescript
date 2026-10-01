/**
 * TypeScript interfaces for all stable Genesis Mesh protocol models.
 * Field names match the Python Pydantic models exactly - JSON serialization
 * is snake_case throughout the HTTP API.
 */

// ── Common ────────────────────────────────────────────────────────────────────

export interface Signature {
  key_id: string;
  sig: string;
}

// ── Agreement ─────────────────────────────────────────────────────────────────

export interface AgreementTerms {
  capabilities: string[];
  scope: Record<string, unknown>;
  valid_from: string;
  valid_until: string;
}

export interface CapabilityOffer {
  offer_id: string;
  offerer_sovereign_id: string;
  responder_sovereign_id: string;
  requested_terms: AgreementTerms;
  expires_at: string;
  graph_digest: string;
  issued_by: string;
  issued_at: string;
  signatures: Signature[];
}

export interface CapabilityCounter {
  counter_id: string;
  original_offer_id: string;
  offerer_sovereign_id: string;
  responder_sovereign_id: string;
  counter_terms: AgreementTerms;
  graph_digest: string;
  issued_by: string;
  issued_at: string;
  signatures: Signature[];
}

export interface AgreementRecord {
  agreement_id: string;
  offerer_sovereign_id: string;
  responder_sovereign_id: string;
  agreed_terms: AgreementTerms;
  signed_at: string;
  graph_digest: string;
  issued_by: string;
  signatures: Signature[];
}

export interface AgreementVerification {
  accepted: boolean;
  reason: string;
  agreement_id: string | null;
}

// ── Boundary ──────────────────────────────────────────────────────────────────

export interface GateResult {
  gate_name: string;
  passed: boolean;
  detail: string;
}

export interface FreshnessProof {
  proof_id: string;
  feed_sovereign_id: string;
  feed_sequence: number;
  feed_digest: string;
  attested_at: string;
  proof_valid_until: string;
  issuer_sovereign_id: string;
  signature?: Signature | null;
  [key: string]: unknown;
}

/** "enforce" denies on failure; "observe" records the failure only. */
export type GateMode = 'enforce' | 'observe';

export type GateOutcome = 'pass' | 'fail' | 'missing_context' | 'invalid_context' | 'gate_error';

export interface AppliedPolicy {
  policy_id: string;
  version: number;
  policy_digest: string;
  signed_by: string;
}

export interface PolicyGateEvaluation {
  policy_id: string;
  policy_version: number;
  gate_id: string;
  gate_type: string;
  order: number;
  mode: GateMode;
  passed: boolean;
  outcome: GateOutcome;
}

/** Policy basis of a decision (v0.58); covered by the decision signature. */
export interface PolicyBinding {
  policies: AppliedPolicy[];
  policy_set_digest: string;
  gate_evaluations: PolicyGateEvaluation[];
  context_digest: string;
  registry_gate_types: string[];
  resolution_status: 'resolved' | 'failed';
  resolution_failure: string | null;
}

/** Attestation basis of a decision (v0.58.1); covered by the decision signature. */
export interface AttestationBinding {
  attestation_id: string;
  subject_id: string | null;
  issuer_sovereign_id: string | null;
  attestation_digest: string | null;
  revocation_seq_checked: number;
}

/** Signed BoundaryEngine output. `policy_binding` / `attestation_binding` are absent on older decisions. */
export interface BoundaryDecision {
  decision_id: string;
  context_id: string;
  agreement_id: string;
  authorized: boolean;
  denial_reason: string | null;
  gate_results: GateResult[];
  decision_made_at: string;
  decision_valid_until: string;
  operator_sovereign_id: string;
  freshness_proof: FreshnessProof | null;
  policy_binding?: PolicyBinding | null;
  attestation_binding?: AttestationBinding | null;
  signature: Signature | null;
}

/** Denial reasons on an attestation-basis decision (v0.58.1). */
export type AttestationDenialReason =
  | 'attestation_not_found'
  | 'attestation_invalid'
  | 'attestation_revoked'
  | 'attestation_expired'
  | 'attestation_not_yet_valid'
  | 'attestation_subject_mismatch';

/** Unsigned request record the decision was made for. */
export interface ContextRecord {
  context_id: string;
  agreement_id: string;
  parent_kind: 'agreement' | 'delegation' | 'direct' | 'attestation' | string;
  requester_sovereign_id: string;
  provider_sovereign_id: string;
  requested_capability: string;
  request_parameters: Record<string, unknown>;
  requested_at: string;
  context_freshness_seq: number;
  attributes: Record<string, unknown>;
  attestation_id?: string | null;
}

export interface GateTraceEntry {
  gate_name: string;
  gate_type: string;
  evaluated_at: string;
  inputs: Record<string, unknown>;
  result: boolean;
  reason: string;
  metadata: Record<string, unknown>;
}

export interface GateTrace {
  trace_id: string;
  decision_id: string;
  agreement_id: string;
  operator_sovereign_id: string;
  traced_at: string;
  entries: GateTraceEntry[];
  short_circuited_at: string | null;
  final_authorized: boolean;
}

/** NA-signed record of every gate the engine ran for a decision. */
export interface DecisionJustification {
  proof_id: string;
  decision_id: string;
  trace: GateTrace;
  proof_issued_at: string;
  issuer_sovereign_id: string;
  signature: Signature | null;
}

/** `POST /admin/boundary/evaluate` response. */
export interface BoundaryEvaluation {
  decision: BoundaryDecision;
  justification_proof: DecisionJustification;
}

export type BoundaryVerificationReason =
  | 'payload_invalid'
  | 'authorized'
  | 'unauthorized_capability_out_of_scope'
  | 'unauthorized_outside_validity_window'
  | 'unauthorized_insufficient_freshness'
  | 'unauthorized_gate_failure'
  | 'invalid_signature'
  | 'decision_expired'
  | 'missing_signature'
  | 'freshness_proof_expired'
  | 'freshness_proof_invalid_signature'
  | 'unauthorized_policy_gate_failure'
  | 'unauthorized_policy_resolution_failed'
  | 'policy_binding_mismatch'
  | 'policy_binding_missing'
  | 'unauthorized_attestation_basis'
  | 'attestation_binding_mismatch'
  | 'attestation_binding_missing';

export interface BoundaryVerification {
  accepted: boolean;
  authorized: boolean;
  reason: BoundaryVerificationReason | string;
  decision_id: string | null;
}

// ── Boundary policy ───────────────────────────────────────────────────────────

export type JsonScalar = string | number | boolean | null;

export interface PolicySelector {
  capabilities?: string[];
  requester_sovereign_ids?: string[];
  provider_sovereign_ids?: string[];
  agreement_ids?: string[];
  parent_kinds?: string[];
  parameter_equals?: Record<string, JsonScalar[]>;
}

export interface GateSpec {
  gate_id: string;
  /** Trusted registry key, e.g. "max_value.v1", "attestation_claim.v1". */
  gate_type: string;
  order: number;
  mode?: GateMode;
  config?: Record<string, unknown>;
  disclose_input?: boolean;
}

/** Declared policy intent; the NA assigns version, issuer and signature. */
export interface BoundaryPolicyIntent {
  policy_id: string;
  description?: string;
  valid_from: string;
  valid_until: string;
  selector?: PolicySelector;
  gates?: GateSpec[];
}

/** Signed, versioned declarative policy as stored by the NA. */
export interface BoundaryPolicy {
  policy_id: string;
  version: number;
  description: string;
  valid_from: string;
  valid_until: string;
  selector: Required<PolicySelector>;
  gates: Required<GateSpec>[];
  issued_at: string;
  issued_by: string;
  issuer_sovereign_id: string;
  signature: Signature | null;
}

export interface PolicyIssue {
  code: string;
  message: string;
  gate_id?: string;
}

export interface PolicyValidation {
  valid: boolean;
  issues: PolicyIssue[];
  policy_id: string;
  next_version: number;
}

export interface PolicyVersionSummary {
  policy_id: string;
  version: number;
  active: boolean;
  policy_digest: string;
  created_at: string;
  activated_at: string | null;
  deactivated_at: string | null;
  integrity_ok: boolean;
  description?: string;
  valid_from?: string;
  valid_until?: string;
  gate_count?: number;
  global?: boolean;
  policy?: BoundaryPolicy;
}

export interface PolicyHistory {
  policy_id: string;
  versions: PolicyVersionSummary[];
}

export interface ActivePolicyStatus {
  enforcement: string;
  policy_set_healthy: boolean;
  problems: { policy: string; reason: string }[];
  registry_gate_types: string[];
  active: {
    policy_id: string;
    version: number;
    policy_digest: string;
    valid_from: string;
    valid_until: string;
    gate_count: number;
    selector: Required<PolicySelector>;
    policy: BoundaryPolicy;
  }[];
}

export interface PolicyActivation {
  policy_id: string;
  version: number;
  previous_version?: number | null;
  active: boolean;
}

export interface PolicyVerification {
  valid: boolean;
  reason: string;
  policy_id: string | null;
  version: number | null;
  policy_digest: string | null;
}

// ── Evidence ──────────────────────────────────────────────────────────────────

export interface TrustSignal {
  signal_id: string;
  signal_type: string;
  value: unknown;
  [key: string]: unknown;
}

export interface TrustDecision {
  source_sovereign_id: string;
  target_sovereign_id: string;
  verdict: string;
  reason?: string;
  signals?: TrustSignal[];
  [key: string]: unknown;
}

export interface TrustEvidence {
  evidence_id: string;
  source_sovereign_id: string;
  target_sovereign_id: string;
  verdict: string;
  reason: string;
  graph_digest: string;
  issued_at: string;
  issued_by: string;
  signals: TrustSignal[];
  signatures: Signature[];
}

export interface EvidenceVerification {
  accepted: boolean;
  reason: string;
  evidence_id: string | null;
  issuer_sovereign_id: string | null;
  verdict: string | null;
}

// ── Attestation ───────────────────────────────────────────────────────────────

export type AttestationStatus = 'active' | 'suspended' | 'revoked';

/** NA-signed membership attestation. `claims` carries e.g. `capabilities`, `apps`, `subscriptions`. */
export interface MembershipAttestation {
  attestation_id: string;
  issuer_sovereign_id: string;
  subject_id: string;
  subject_public_key: string | null;
  roles: string[];
  status: AttestationStatus;
  issued_at: string;
  valid_from: string;
  expires_at: string;
  issued_by: string;
  claims: Record<string, unknown>;
  signatures: Signature[];
}

/** A stored attestation with its current status (the signed body keeps the issue-time status). */
export interface AttestationRecord {
  attestation: MembershipAttestation;
  status: AttestationStatus;
  revoked_at: string | null;
  revocation_reason: string | null;
}

export interface AttestationList {
  count: number;
  attestations: AttestationRecord[];
}

export interface AttestationRevocation {
  attestation_id: string;
  status: string;
}

export interface AttestationVerification {
  accepted: boolean;
  reason: string;
  issuer_sovereign_id: string | null;
  attestation_id: string | null;
}

export interface RecognitionPolicyRecord {
  policy_id: string;
  local_sovereign_id: string;
  active: boolean;
}

export interface RecognizedIssuer {
  sovereign_id: string;
  public_keys: string[];
  allowed_roles: string[];
  accepted_statuses: AttestationStatus[];
  [key: string]: unknown;
}

export interface RecognitionPolicy {
  local_sovereign_id: string;
  recognized_issuers: RecognizedIssuer[];
  revoked_attestation_ids: string[];
  [key: string]: unknown;
}

/** NA-signed list of revoked attestations for one issuer. */
export interface SovereignRevocationFeed {
  feed_id: string;
  issuer_sovereign_id: string;
  sequence: number;
  issued_at: string;
  revoked_attestation_ids: string[];
  revocation_reasons: Record<string, string>;
  issued_by: string;
  signatures: Signature[];
}

// ── Disclosure ────────────────────────────────────────────────────────────────

export interface CapabilityCommitment {
  commitment_id: string;
  agreement_id: string;
  capabilities: string[];
  merkle_root: string;
  committed_at: string;
  issued_by: string;
  signatures: Signature[];
}

export interface CapabilityMembershipProof {
  proof_id: string;
  commitment_id: string;
  capability: string;
  merkle_path: string[];
  prover_sovereign_id: string;
  proved_at: string;
}

export interface CapabilityNullifier {
  nullifier_id: string;
  proof_id: string;
  commitment_id: string;
  issued_at: string;
  issued_by: string;
  signatures: Signature[];
}

export interface DisclosureVerification {
  valid: boolean;
  reason: string;
  commitment_id: string | null;
}

// ── Consensus ─────────────────────────────────────────────────────────────────

export interface JustificationProof {
  proof_id: string;
  decision_id: string;
  [key: string]: unknown;
}

export interface ValidatorVote {
  vote_id: string;
  proof_id: string;
  decision_id: string;
  validator_sovereign_id: string;
  vote: boolean;
  reason: string | null;
  voted_at: string;
  signatures: Signature[];
}

export interface ConsensusProof {
  consensus_id: string;
  proof_id: string;
  decision_id: string;
  votes: ValidatorVote[];
  required_threshold: number;
  validator_sovereign_ids: string[];
  assembled_at: string;
  issued_by: string;
  signatures: Signature[];
}

export interface ConsensusVerification {
  valid: boolean;
  reason: string;
  consensus_id: string | null;
}

// ── Data Usage ────────────────────────────────────────────────────────────────

export interface DataSourceDescriptor {
  source_id: string;
  /** "personal" | "proprietary" | "public" | "synthetic" */
  source_type: string;
  owner_sovereign_id: string;
  classification_tags: string[];
  estimated_volume_bytes?: number | null;
}

export interface DataLicensePolicy {
  policy_id: string;
  licensor_sovereign_id: string;
  licensee_sovereign_id: string;
  allowed_source_ids: string[];
  allowed_access_types: string[];
  max_volume_bytes_per_session: number | null;
  prohibited_classification_tags: string[];
  valid_from: string;
  valid_until: string;
  signature: Signature | null;
}

export interface DataAccessIntent {
  intent_id: string;
  agent_sovereign_id: string;
  decision_id: string;
  sources: DataSourceDescriptor[];
  access_types: string[];
  estimated_volume_bytes: number | null;
  declared_at: string;
  signatures: Signature[];
}

export interface DataViolation {
  violation_type: string;
  description: string;
  [key: string]: unknown;
}

export interface DataUsageVerification {
  valid: boolean;
  violation_reason: string | null;
  violation_count: number;
  violations: DataViolation[];
}

// ── Execution evidence and evidence store (v0.59) ─────────────────────────────

export type ResourceAction = 'create' | 'rotate' | 'revoke' | 'update' | 'delete';

export type ExecutionOutcome = 'success' | 'failure' | 'partial';

/**
 * Executor-signed record of one execution under a decision. The v0.59
 * resource fields are absent (not null) on records that do not name a resource.
 */
export interface ExecutionEvidence {
  evidence_id: string;
  sequence_no: number;
  decision_id: string;
  context_id: string;
  agreement_id: string;
  executor_sovereign_id: string;
  executed_capability: string;
  execution_parameters: Record<string, unknown>;
  executed_at: string;
  outcome: ExecutionOutcome | string;
  outcome_detail: string | null;
  prev_evidence_digest: string | null;
  resource_id?: string;
  resource_action?: ResourceAction;
  resource_sequence?: number;
  prev_resource_digest?: string | null;
  signature: Signature | null;
}

export type EntryKind = 'decision' | 'justification' | 'execution' | 'retention_checkpoint';

/** Store envelope; every entry commits to the previous one. */
export interface EvidenceStoreEntry {
  store_sequence: number;
  entry_kind: EntryKind;
  recorded_at: string;
  payload_digest: string;
  prev_entry_digest: string | null;
  decision_id: string | null;
  context_id: string | null;
  vendor_id: string | null;
  attestation_id: string | null;
  capability: string | null;
  outcome: string | null;
  evidence_id: string | null;
  executor_sovereign_id: string | null;
  exec_sequence_no: number | null;
  resource_id: string | null;
  resource_action: string | null;
  resource_sequence: number | null;
}

/** `gm.evidence.event` schema version 1: one stored entry with its signed payload. */
export interface EvidenceEvent {
  schema: 'gm.evidence.event';
  schema_version: 1;
  entry: EvidenceStoreEntry;
  entry_digest: string;
  payload: Record<string, unknown>;
}

export interface ResourceHead {
  resource_sequence: number;
  record_digest: string;
}

/** NA-signed record of a retention run; keeps the remaining store verifiable. */
export interface RetentionCheckpoint {
  checkpoint_id: string;
  created_at: string;
  cutoff: string;
  removed_through_sequence: number;
  last_removed_entry_digest: string;
  removed_count: number;
  resource_heads: Record<string, ResourceHead>;
  previous_checkpoint_id: string | null;
  issued_by: string;
  signature: Signature | null;
}

/** `POST /evidence/execution` response: the stored entry, for a new record and for an identical resubmission. */
export interface EvidenceSubmission {
  status: 'recorded' | 'duplicate';
  entry: EvidenceStoreEntry;
  entry_digest: string;
}

export type EvidenceVerificationFailureReason =
  | 'entry_digest_mismatch'
  | 'payload_digest_mismatch'
  | 'store_sequence_gap'
  | 'store_chain_break'
  | 'payload_invalid'
  | 'invalid_signature'
  | 'evidence_decision_denied'
  | 'evidence_outside_decision_window'
  | 'evidence_capability_mismatch'
  | 'evidence_chain_break'
  | 'resource_chain_break';

export interface EvidenceVerificationFailure {
  store_sequence: number | null;
  reason: EvidenceVerificationFailureReason | string;
  detail: string;
}

export interface EvidenceStoreVerification {
  verified: boolean;
  checked_entries: number;
  decisions: number;
  executions: number;
  failures: EvidenceVerificationFailure[];
}

export interface EvidenceSearchResult {
  count: number;
  next_after_sequence: number | null;
  entries: EvidenceEvent[];
}

export interface ResourceHistory {
  resource_id: string;
  entries: EvidenceEvent[];
  verification: EvidenceStoreVerification;
}

export interface VendorHistory {
  vendor_id: string;
  entries: EvidenceEvent[];
  verification: EvidenceStoreVerification;
}

export interface EvidenceStoreStatus {
  evidence_store: string;
  entries?: number;
  last_store_sequence?: number | null;
  rejections?: number;
  active_executor_keys?: number;
  retention_checkpoint: number | null;
}

export interface ExecutorKeyRecord {
  key_id: string;
  public_key: string;
  executor_sovereign_id: string;
  registered_at: string;
  retired_at: string | null;
  [key: string]: unknown;
}

export interface ExecutorKeyState {
  key_id: string;
  executor_sovereign_id?: string;
  active: boolean;
}

export interface RetentionResult {
  removed_count: number;
  checkpoint: RetentionCheckpoint | null;
}

/** Rejection codes from `POST /evidence/execution` (422, or 409 for `evidence_conflict`). */
export type EvidenceRejectionCode =
  | 'evidence_malformed'
  | 'evidence_unknown_executor'
  | 'evidence_invalid_signature'
  | 'evidence_decision_not_found'
  | 'evidence_decision_denied'
  | 'evidence_decision_mismatch'
  | 'evidence_outside_decision_window'
  | 'evidence_capability_mismatch'
  | 'evidence_chain_gap'
  | 'evidence_chain_mismatch'
  | 'resource_chain_gap'
  | 'resource_chain_mismatch'
  | 'evidence_conflict'
  | 'evidence_secret_material';

// ── Health and readiness (v0.60) ──────────────────────────────────────────────

export interface ReadinessDatabase {
  backend: 'sqlite' | 'postgres' | string;
  writable: boolean;
  schema_version?: number;
  expected_schema_version: number;
  /** Present when not ready: e.g. "schema_version_mismatch" or the error type. */
  error?: string;
}

export interface ReadinessSigningKey {
  key_id: string;
  provider: 'file' | 'env' | 'azure-keyvault' | string;
  /** SHA-256 (hex) of the NA public key; identical on every instance of one NA. */
  fingerprint: string;
}

/** `GET /readyz`, normalised: `ready` is false when the NA answered 503 not ready. */
export interface Readiness {
  ready: boolean;
  status: 'ready' | 'not_ready';
  instance: string;
  ha_mode: 'on' | 'off' | string;
  database: ReadinessDatabase;
  signing_key: ReadinessSigningKey;
  rate_limiter: 'memory' | 'database' | string;
  /** The SQLite path, or the PostgreSQL URL without its password (ready responses only). */
  db_path?: string;
}

/** Readiness of one configured endpoint, probed directly (no failover). */
export interface EndpointReadiness {
  base_url: string;
  reachable: boolean;
  ready: boolean;
  readiness?: Readiness;
  error?: string;
}

export interface HealthStatus {
  status: string;
  network: string;
  version: string;
  boundary_policies: 'healthy' | 'unhealthy' | string;
  boundary_policy_enforcement: string;
  evidence_store: string;
}

/** 409 codes for a race another NA instance won (v0.60). Retrying is safe. */
export type HaConflictCode =
  | 'boundary_policy_activation_conflict'
  | 'boundary_policy_version_conflict'
  | 'crl_publish_contention'
  | 'retention_in_progress';
