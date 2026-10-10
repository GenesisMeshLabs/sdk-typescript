import { HttpTransport, type ClientOptions } from './client.js';
import { AgreementClient } from './agreement.js';
import { BoundaryClient } from './boundary.js';
import { EvidenceClient } from './evidence.js';
import { AttestationClient } from './attestation.js';
import { DisclosureClient } from './disclosure.js';
import { ConsensusClient } from './consensus.js';
import { DataUsageClient } from './data_usage.js';
import { PolicyClient } from './policy.js';
import { EvidenceStoreClient } from './evidence_store.js';
import { HealthClient } from './health.js';

export class GenesisMeshClient {
  readonly agreement: AgreementClient;
  readonly boundary: BoundaryClient;
  readonly policy: PolicyClient;
  /** Trust evidence (v0.53). For the v0.59 execution evidence store, see `evidenceStore`. */
  readonly evidence: EvidenceClient;
  readonly evidenceStore: EvidenceStoreClient;
  readonly attestation: AttestationClient;
  readonly disclosure: DisclosureClient;
  readonly consensus: ConsensusClient;
  readonly dataUsage: DataUsageClient;
  /** Liveness, readiness and health (v0.60). */
  readonly health: HealthClient;

  constructor(options: ClientOptions) {
    const http = new HttpTransport(options);
    this.agreement     = new AgreementClient(http);
    this.boundary      = new BoundaryClient(http);
    this.policy        = new PolicyClient(http);
    this.evidence      = new EvidenceClient(http);
    this.evidenceStore = new EvidenceStoreClient(http, options.outbox, options.recordOutbox);
    this.health        = new HealthClient(http);
    this.attestation   = new AttestationClient(http);
    this.disclosure    = new DisclosureClient(http);
    this.consensus     = new ConsensusClient(http);
    this.dataUsage     = new DataUsageClient(http);
  }
}

// Sub-client classes (for composition / dependency injection)
export { AgreementClient } from './agreement.js';
export { BoundaryClient } from './boundary.js';
export { PolicyClient } from './policy.js';
export { EvidenceClient } from './evidence.js';
export { EvidenceStoreClient } from './evidence_store.js';
export { HealthClient } from './health.js';
export { AttestationClient } from './attestation.js';
export { DisclosureClient } from './disclosure.js';
export { ConsensusClient } from './consensus.js';
export { DataUsageClient } from './data_usage.js';

// Transport
export { HttpTransport, buildPath } from './client.js';
export type { ClientOptions, RetryOptions, Query } from './client.js';

// Key operations (canonical JSON, digests, signing, verification)
export {
  canonicalJson,
  canonicalDigest,
  checkSignable,
  parseJson,
  sha256Hex,
  signBytes,
  verifyBytes,
  publicKeyFromSeed,
  seedSigner,
  signCanonical,
  verifyCanonical,
  pythonTimestamp,
  buildAdminHeaders,
  buildAdminHeadersWithSigner,
  adminSigningPayload,
  ADMIN_SIGNATURE_VERSION,
} from './auth.js';
export type { AdminHeaders, AdminRequest, AdminSigningOptions, Signer } from './auth.js';

// Canonical bodies and digests of protocol models
export {
  RESOURCE_CHAIN_FIELDS,
  decisionCanonical,
  executionCanonical,
  executionDigest,
  attestationCanonical,
  attestationDigest,
  revocationFeedCanonical,
  policyCanonical,
  policyDigest,
  policySetDigest,
  agreementCanonical,
  dataLicensePolicyCanonical,
  dataAccessIntentCanonical,
  justificationCanonical,
  checkpointCanonical,
  entryDigest,
  payloadDigest,
} from './canonical.js';

// Execution evidence
export { ExecutionRecorder, checkMetadataOnly, SecretMaterialError, MAX_METADATA_BYTES } from './execution.js';
export type { RecordExecutionParams, ExecutionRecorderOptions, PriorResource } from './execution.js';

// Offline verification
export {
  verifyBoundaryDecision,
  verifyDecisionSignature,
  verifyAttestationSignature,
  verifyPolicySignature,
  verifyJustificationSignature,
  verifyRevocationFeedSignature,
  verifyRetentionCheckpoint,
  verifyExecutionSignature,
  verifyEvidenceEvents,
  parseExportLines,
  parseTimestampMicros,
  verifyAgreement,
  verifyDataLicensePolicySignature,
  verifyDataAccessIntent,
} from './verify.js';
export type {
  VerifyDecisionOptions, VerifyEvidenceOptions, ExecutorKeyInfo,
  AgreementVerification, AgreementVerificationReason, DataIntentVerification, DataUsageViolationDetail, DataUsageViolationType,
} from './verify.js';

// Strict verification: the field registry of signed records (v1.2.0)
export { unknownFields, isKnownEntryKind, canonicalTimestamp, nonCanonicalTimestamps } from './strict.js';
export { checkStrictJson, StrictJsonError } from './strict-json.js';
export type { StrictJsonReason } from './strict-json.js';

// Data access intents (v0.61)
export { createDataAccessIntent } from './data_intent.js';
export type { CreateDataAccessIntentParams } from './data_intent.js';

// Governed lifecycles
export {
  governedAction,
  summarizeDecision,
  reconcileResources,
  GovernedActionError,
  MetadataRefusedError,
  EvidenceNotKeptError,
  DecisionVerificationError,
  withoutRefusedMetadata,
} from './governance.js';

// Evidence outbox (v1.2.0) and record outbox (v1.3.0)
export {
  FileOutbox,
  FileRecordOutbox,
  MemoryOutbox,
  classifySubmissionError,
  recordOutboxEntry,
  retryDelayMs,
  nextAttemptAt,
  LOCAL_ERROR,
  PREDECESSOR_DEAD_LETTERED,
  PERMANENT_REFUSALS,
  RECORD_PERMANENT_REFUSALS,
} from './outbox.js';
export type {
  EvidenceOutbox,
  Outbox,
  OutboxEntry,
  RecordOutbox,
  RecordOutboxEntry,
  Delivery,
  SubmissionFailure,
  FlushResult,
  FlushOptions,
} from './outbox.js';

// Changes outside the controlled path (v1.3.0)
export {
  ObservationRecorder,
  OutOfBandRecordError,
  metadataProblem,
  observationFromFinding,
  observationId,
  outOfBandCanonical,
  outOfBandDigest,
  signBreakGlass,
  verifyOutOfBandRecord,
} from './out-of-band.js';
export type {
  BreakGlassInput,
  BreakGlassRecord,
  EvaluationFailure,
  FindingObservationOptions,
  GovernedBy,
  JudgementRecord,
  ObservationInput,
  ObservationRecord,
  ObservationRecorderOptions,
  OutOfBandRecord,
  QuarantineRecord,
  RegistryRecord,
  Verdict,
} from './out-of-band.js';
export type {
  ActionReport,
  DecisionSummary,
  GateFailure,
  GovernanceClients,
  GovernedActionParams,
  GovernedActionResult,
  BreakGlassOptions,
  BreakGlassResult,
  ObservedResource,
  ReconcileOptions,
  ReconciliationFinding,
  ReconciliationStatus,
} from './governance.js';

// Errors
export {
  GenesisMeshError,
  UnauthorizedError,
  ForbiddenError,
  ValidationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ServiceUnavailableError,
  isRetryableConflict,
  NetworkError,
  BadRequestError,
} from './errors.js';

// Types
export type * from './types.js';

// Sub-client param types
export type * from './agreement.js';
export type * from './boundary.js';
export type * from './policy.js';
export type * from './evidence.js';
export type * from './evidence_store.js';
export type * from './health.js';
export type * from './attestation.js';
export type * from './disclosure.js';
export type * from './consensus.js';
export type * from './data_usage.js';
