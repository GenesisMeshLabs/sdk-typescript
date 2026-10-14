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
  /** Minimum revocation-feed sequence the responder guarantees. */
  freshness_commitment: number;
}

export interface CapabilityOffer {
  offer_id: string;
  offerer_sovereign_id: string;
  responder_sovereign_id: string;
  requested_terms: AgreementTerms;
  graph_digest: string;
  offerer_evidence: Record<string, unknown>;
  expires_at: string;
  created_at: string;
  signatures: Signature[];
}

export interface CapabilityCounter {
  offer_id: string;
  offerer_sovereign_id: string;
  responder_sovereign_id: string;
  agreed_terms: AgreementTerms;
  offerer_evidence: Record<string, unknown>;
  responder_evidence: Record<string, unknown>;
  graph_digest: string;
  expires_at: string;
  signatures: Signature[];
}

/** Dual-signed agreement. Both parties sign the same canonical body (see `agreementCanonical`). */
export interface AgreementRecord {
  agreement_id: string;
  offer_id: string;
  offerer_sovereign_id: string;
  responder_sovereign_id: string;
  agreed_terms: AgreementTerms;
  offerer_evidence: Record<string, unknown>;
  responder_evidence: Record<string, unknown>;
  graph_digest: string;
  established_at: string;
  expires_at: string;
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
  | 'attestation_binding_missing'
  | 'unknown_field'
  | 'non_canonical_form'
  // v1.5.0: signed by a key of the NA's history, but not the one valid when the decision was made.
  | 'na_key_not_valid_at_time'
  // v1.5.0: valid longer than the key that signed it may vouch for.
  | 'decision_outlives_key';

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

/** What a change judged DENY by a gate leads to (v1.4.0): see *Remediation and Reviews* in the SDK docs. */
export interface GateRemediation {
  /** `cancel`: the controller cancels the change once the grace has passed; `alert_only`: the denial is recorded and its author told. */
  mode: 'cancel' | 'alert_only';
  /** 0 to 2592000 (30 days). */
  grace_seconds: number;
}

/** Marks a policy's one capability as the emergency form of an ordinary one (v1.4.0). */
export interface EmergencyCapability {
  /** The ordinary capability the emergency capability performs (an exact ID). */
  stands_for: string;
  /** The request parameter holding the justification; an enforce-mode `required_parameter.v1` gate must require it. */
  justification_parameter: string;
  /** 60 to 2592000: how long what the emergency capability creates may stand. */
  max_lifetime_seconds: number;
}

/**
 * The sections a policy may carry since 1.4.0, each left out when absent, so
 * a policy without them keeps its 1.3 bytes and digest. The NA refuses them
 * unless `EVIDENCE_REMEDIATION=on` (`policy_remediation_disabled`).
 */
export interface PolicyRemediationSections {
  /** `gate_id` (or `"*"` for every other gate) to what a DENY by that gate leads to. */
  remediation?: Record<string, GateRemediation>;
  /** Present (true) when every change allowed under the policy is reviewed by a second holder. */
  review_required?: true;
  emergency?: EmergencyCapability;
}

/** Declared policy intent; the NA assigns version, issuer and signature. */
export interface BoundaryPolicyIntent extends PolicyRemediationSections {
  policy_id: string;
  description?: string;
  valid_from: string;
  valid_until: string;
  selector?: PolicySelector;
  gates?: GateSpec[];
}

/** Signed, versioned declarative policy as stored by the NA. */
export interface BoundaryPolicy extends PolicyRemediationSections {
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

/** One reason behind a trust verdict, as the NA reads and signs it. */
export interface TrustSignal {
  code: string;
  severity: 'info' | 'warn' | 'escalate' | 'block' | string;
  detail: string;
  /** @deprecated Never sent or read by the NA; see `code`. */
  signal_id?: string;
  /** @deprecated Never sent or read by the NA; see `code` and `severity`. */
  signal_type?: string;
  /** @deprecated Never sent or read by the NA; see `detail`. */
  value?: unknown;
  [key: string]: unknown;
}

/**
 * The decision `evidence.build` signs. The NA signs what it is given: set
 * `trusted`, `hop_count` and the other fields from the decision being recorded.
 */
export interface TrustDecision {
  source_sovereign_id: string;
  target_sovereign_id: string;
  verdict: string;
  reason?: string;
  requested_roles?: string[];
  trusted?: boolean;
  trust_path?: Record<string, unknown>[];
  hop_count?: number;
  signals?: TrustSignal[];
  evaluated_at?: string;
  [key: string]: unknown;
}

export interface TrustEvidence {
  evidence_id: string;
  issuer_sovereign_id: string;
  source_sovereign_id: string;
  target_sovereign_id: string;
  verdict: string;
  reason: string;
  trusted: boolean;
  hop_count: number;
  requested_roles: string[];
  signals: TrustSignal[];
  graph_digest: string;
  evaluated_at: string;
  issued_at: string;
  issued_by: string;
  metadata: Record<string, unknown>;
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
  /** Present for operator-signed requests, or when the NA publishes the list. */
  attestations?: AttestationRecord[];
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
  /**
   * v1.6.0: the grants the issuer revoked that are not yet past their end,
   * sorted. Left out of every form when absent, as an NA without
   * `EVIDENCE_GRANTS=on` writes the feed.
   */
  revoked_grant_ids?: string[];
}

// ── Disclosure ────────────────────────────────────────────────────────────────

/** A signed Merkle commitment: it reveals how many capabilities, not which. */
export interface CapabilityCommitment {
  commitment_id: string;
  agreement_id: string;
  issuer_sovereign_id: string;
  merkle_root: string;
  capability_count: number;
  committed_at: string;
  signature: Signature | null;
  /** @deprecated Never sent by the NA: a commitment does not reveal its capabilities. */
  capabilities?: string[];
  /** @deprecated Never sent by the NA; see `issuer_sovereign_id` and `signature.key_id`. */
  issued_by?: string;
  /** @deprecated Never sent by the NA; a commitment carries one `signature`. */
  signatures?: Signature[];
}

/** One step from a leaf to the Merkle root. */
export interface MerklePathStep {
  sibling_hash: string;
  is_left: boolean;
}

export interface CapabilityMembershipProof {
  proof_id: string;
  commitment_id: string;
  revealed_capability: string;
  leaf_hash: string;
  merkle_path: MerklePathStep[];
  prover_sovereign_id: string;
  proved_at: string;
  /** @deprecated Never sent by the NA; see `revealed_capability`. */
  capability?: string;
}

export interface CapabilityNullifier {
  nullifier_id: string;
  proof_id: string;
  prover_sovereign_id: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  signature: Signature | null;
  /** @deprecated Never sent by the NA. */
  commitment_id?: string;
  /** @deprecated Never sent by the NA; see `signature.key_id`. */
  issued_by?: string;
  /** @deprecated Never sent by the NA; a nullifier carries one `signature`. */
  signatures?: Signature[];
}

export interface DisclosureVerification {
  valid: boolean;
  reason: string;
  commitment_id: string | null;
}

// ── Consensus ─────────────────────────────────────────────────────────────────

/**
 * The proof validators vote on: the NA-signed justification returned with a
 * decision by `boundary.evaluate` (`justification_proof`).
 */
export type JustificationProof = DecisionJustification;

/** A validator's signed vote on a JustificationProof (Python `ValidatorVote`). */
export interface ValidatorVote {
  vote_id: string;
  proof_id: string;
  decision_id: string;
  validator_sovereign_id: string;
  /** true approves, false rejects. */
  vote: boolean;
  reason: string | null;
  voted_at: string;
  /** SHA-256 binding the vote to the validator's view of the proof (v0.38). Required on approve votes. */
  context_digest: string | null;
  signature: Signature | null;
}

/** K-of-N approval over a JustificationProof, signed by the assembler (Python `ConsensusProof`). */
export interface ConsensusProof {
  consensus_id: string;
  proof_id: string;
  decision_id: string;
  /** K in K-of-N: distinct named validators that must approve. */
  required_threshold: number;
  /** The N named validators. */
  validator_sovereign_ids: string[];
  votes: ValidatorVote[];
  reached_at: string;
  expires_at: string;
  /** Digest of the cascade assessment that cleared the proof; null on pre-v0.38 proofs. */
  cascade_assessment_digest: string | null;
  signature: Signature | null;
}

export type ConsensusVerificationReason =
  | 'valid'
  | 'missing_signature'
  | 'invalid_assembler_signature'
  | 'threshold_not_met'
  | 'invalid_vote_signature'
  | 'unknown_validator_key'
  | 'vote_not_in_validator_set'
  | 'expired'
  | 'proof_id_mismatch'
  | 'cascade_detected'
  | 'missing_context_digest';

export interface ConsensusVerification {
  valid: boolean;
  reason: ConsensusVerificationReason;
  consensus_id: string | null;
}

// ── Data Usage ────────────────────────────────────────────────────────────────

export interface DataSourceDescriptor {
  source_id: string;
  /** "personal" | "proprietary" | "public" | "synthetic" */
  source_type: string;
  owner_sovereign_id: string;
  classification_tags: string[];
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

/** Agent-signed declaration of the data an execution will access. */
export interface DataAccessIntent {
  intent_id: string;
  agent_sovereign_id: string;
  decision_id: string;
  declared_sources: DataSourceDescriptor[];
  declared_access_types: string[];
  estimated_volume_bytes: number | null;
  declared_at: string;
  expires_at: string;
  signature: Signature | null;
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

export type EntryKind =
  | 'decision'
  | 'justification'
  | 'execution'
  | 'retention_checkpoint'
  // v1.3.0: changes made outside the controlled path, and the NA's registry.
  | 'observation'
  | 'break_glass'
  | 'judgement'
  | 'quarantine'
  | 'registry'
  // v1.4.0: remediations and reviews, written only with EVIDENCE_REMEDIATION=on.
  | 'remediation'
  | 'review'
  // v1.5.0: NA key successions and archives (never pruned: carried past retention).
  | 'key_succession'
  | 'archive'
  // v1.6.0: pre-issued grants, their uses and revocations, written only with EVIDENCE_GRANTS=on.
  | 'grant'
  | 'grant_execution'
  | 'grant_revocation';

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
  /** v1.3.0, left out when absent: the Stage 2 record's id (observation, break-glass, judgement, quarantine, registry). */
  record_id?: string;
  /** v1.3.0: the observation or break-glass record a judgement judges. */
  subject_id?: string;
  /** v1.3.0: the execution evidence a judgement matched (consumed by the match). */
  matched_evidence_id?: string;
  /** v1.3.0: an observation's position among the resource's observations, gap-free from 1. */
  observation_sequence?: number;
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
  /** v1.3.0, left out when absent: the last removed observation position per resource. */
  observation_heads?: Record<string, number>;
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
  | 'resource_chain_break'
  | 'unknown_entry_kind'
  | 'unknown_field'
  // v1.3.0
  | 'envelope_mismatch'
  | 'observation_chain_break'
  | 'duplicate_judgement'
  | 'judgement_subject_mismatch'
  | 'judgement_subject_missing'
  | 'match_reused'
  | 'quarantine_digest_mismatch'
  | 'evidence_cites_judgement'
  // v1.4.0
  | 'duplicate_remediation'
  | 'remediation_subject_mismatch'
  | 'remediation_subject_missing'
  | 'remediation_rotation_missing'
  | 'remediation_rotation_mismatch'
  | 'review_approval_invalid'
  | 'review_approval_key_mismatch'
  | 'review_same_holder'
  | 'review_subject_mismatch'
  | 'review_subject_missing'
  | 'review_waiver_after_remediation';

export interface EvidenceVerificationFailure {
  store_sequence: number | null;
  reason: EvidenceVerificationFailureReason | string;
  detail: string;
}

/** How a run of entries ties to the anchors held (`EvidenceStoreVerification.anchors`, v1.5.0). */
export interface AnchorSummary {
  anchors_checked: number;
  anchors_matched: number;
  anchors_before_export: number;
  anchors_after_export: number;
  linked_start: boolean;
  anchored_through_sequence: number | null;
  unanchored_entries: number;
}

export interface EvidenceStoreVerification {
  verified: boolean;
  checked_entries: number;
  decisions: number;
  executions: number;
  /** v1.3.0, present when nonzero. */
  observations?: number;
  break_glass?: number;
  judgements?: number;
  quarantined?: number;
  /** v1.4.0, present when nonzero. */
  remediations?: number;
  reviews?: number;
  /** v1.5.0, present when nonzero. */
  key_successions?: number;
  archives?: number;
  /** v1.6.0, present when nonzero. */
  grants?: number;
  grant_executions?: number;
  grant_revocations?: number;
  failures: EvidenceVerificationFailure[];
  /** Set by `checkEventsAgainstAnchors` (v1.5.0); absent otherwise. */
  anchors?: AnchorSummary;
  /** Findings that do not fail verification (v1.2.0), such as `unsigned_field`. */
  warnings?: EvidenceVerificationFailure[];
}

export interface EvidenceSearchResult {
  count: number;
  next_after_sequence: number | null;
  entries: EvidenceEvent[];
}

export interface ResourceHistory {
  resource_id: string;
  /** True when the chain is longer than one response holds (v0.63.1); read it through the export. */
  truncated?: boolean;
  entries: EvidenceEvent[];
  verification: EvidenceStoreVerification;
}

export interface VendorHistory {
  vendor_id: string;
  /** True when the vendor has more decisions than one response holds (v0.63.1). */
  truncated?: boolean;
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
  /** v1.2.0, with the store on: the latest anchor, null before the first. */
  latest_anchor?: { anchor_sequence: number; store_sequence: number; anchored_at: string } | null;
  /** v1.2.0: entries after the latest anchor. */
  unanchored_entries?: number;
  /** v1.3.1: why this instance cannot anchor (the latest anchor is dated ahead of its clock); absent when it can. */
  anchoring_blocked?: string;
  /** v1.3.0: observations and break-glass records not judged yet (they hold retention back). */
  unjudged_records?: number;
  /** v1.3.1, with the out-of-band records on: when the policy history starts, null before it does. */
  policy_history_started?: string | null;
  /** v1.3.1, with the out-of-band records on: whether the registry can be judged on. */
  registry_healthy?: boolean;
  /** v1.3.1, with the out-of-band records on: what keeps the registry from being healthy. */
  registry_problems?: string[];
  /** v1.4.0: `on` when the NA records remediations and reviews. */
  evidence_remediation?: string;
  /** v1.4.0, with the records on: the number of remediation states by state. */
  remediation?: Record<string, number>;
}

export interface ExecutorKeyRecord {
  key_id: string;
  public_key: string;
  executor_sovereign_id: string;
  registered_at: string;
  retired_at: string | null;
  /** v1.3.0: `executor` signs execution evidence and break-glass records; `observer` signs observations. */
  role?: 'executor' | 'observer';
  /** v1.3.0: the key signs only for resources whose ID starts with this. */
  resource_prefix?: string | null;
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
  /**
   * v1.3.1: why retention stopped short, when it did: records not judged yet, or (v1.5.0)
   * `not_archived`, entries no archive covers yet (with `archived_through_sequence`).
   */
  held_back?: { reason: string; message: string; [key: string]: unknown };
}

/** Rejection codes from `POST /evidence/execution` (422, or 409 for `evidence_conflict`). */
export type EvidenceRejectionCode =
  | 'evidence_malformed'
  | 'evidence_unknown_executor'
  | 'evidence_executor_key_retired'
  | 'evidence_out_of_scope'
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

/**
 * Rejection codes from `POST /evidence/observations` and `/evidence/break-glass`
 * (v1.3.0; 422, or 409 for `*_conflict`).
 */
export type OutOfBandRejectionCode =
  | 'observation_malformed'
  | 'observation_invalid_signature'
  | 'observation_unknown_key'
  | 'observation_key_retired'
  | 'observation_out_of_scope'
  | 'observation_secret_material'
  | 'observation_conflict'
  | 'break_glass_malformed'
  | 'break_glass_invalid_signature'
  | 'break_glass_unknown_key'
  | 'break_glass_key_retired'
  | 'break_glass_out_of_scope'
  | 'break_glass_secret_material'
  | 'break_glass_conflict';

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
  /**
   * v1.5.0: this instance's NA key. `signing`; `pending`, a new key started before its succession
   * takes effect (`signs_from`); `stopped`, succeeded or expired. Anything but `signing` is not ready.
   */
  na_key?: { state: 'signing' | 'pending' | 'stopped' | string; key_sequence?: number; signs_from?: string };
  /** The SQLite path, or the PostgreSQL URL without its password (ready responses only). */
  db_path?: string;
}

/**
 * Error codes of the 1.5.0 routes (`GenesisMeshError.code`): key successions
 * (`POST /admin/na/succession`), the NA key, audit packs (`429` beyond
 * `NA_RATE_LIMIT_AUDIT_PACKS_PER_HOUR`), archives and retention.
 */
export type AuditErrorCode =
  | 'invalid_succession' | 'succession_after_expiry' | 'succession_backdated' | 'succession_chain_break'
  | 'succession_invalid_new_key_signature' | 'succession_invalid_root_signature' | 'succession_key_reused'
  | 'succession_not_increasing' | 'succession_pending' | 'succession_sovereign_mismatch' | 'succession_times_invalid'
  | 'na_key_expired' | 'na_key_not_yet_effective' | 'na_key_succeeded'
  | 'audit_pack_not_anchored' | 'audit_pack_too_large' | 'invalid_audit_pack' | 'evidence_store_incomplete'
  | 'rate_limit_exceeded'
  | 'archive_anchor_mismatch' | 'archive_conflict' | 'archive_manifest_invalid' | 'archive_not_contiguous'
  | 'archive_pack_unknown' | 'archive_pack_unverified' | 'invalid_archive'
  | 'invalid_retention';

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
