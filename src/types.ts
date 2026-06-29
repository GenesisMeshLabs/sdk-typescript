/**
 * TypeScript interfaces for all stable Genesis Mesh protocol models.
 * Field names match the Python Pydantic models exactly — JSON serialization
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

export interface BoundaryDecision {
  decision_id: string;
  agreement_id: string;
  requested_capability: string;
  authorized: boolean;
  reason: string;
  context: Record<string, unknown>;
  decided_at: string;
  issued_by: string;
  operator_id: string;
  signatures: Signature[];
}

export interface BoundaryVerification {
  accepted: boolean;
  authorized: boolean;
  reason: string;
  decision_id: string | null;
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

export interface MembershipAttestation {
  attestation_id: string;
  subject_id: string;
  roles: string[];
  issuer_sovereign_id: string;
  subject_public_key: string | null;
  claims: Record<string, unknown>;
  issued_at: string;
  expires_at: string;
  issued_by: string;
  status: string;
  signatures: Signature[];
}

export interface AttestationRevocation {
  attestation_id: string;
  status: string;
}

export interface RecognitionPolicyRecord {
  policy_id: string;
  local_sovereign_id: string;
  active: boolean;
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
