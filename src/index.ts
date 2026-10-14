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
import { NetworkAuthorityClient } from './network_authority.js';
import { GrantsClient } from './grants-client.js';

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
  /** The NA's own keys: its key history (v1.5.0). */
  readonly na: NetworkAuthorityClient;
  /** Pre-issued grants, their time tokens and uses (v1.6.0, beta routes). */
  readonly grants: GrantsClient;

  constructor(options: ClientOptions) {
    const http = new HttpTransport(options);
    this.agreement     = new AgreementClient(http);
    this.boundary      = new BoundaryClient(http);
    this.policy        = new PolicyClient(http);
    this.evidence      = new EvidenceClient(http);
    this.evidenceStore = new EvidenceStoreClient(http, options.outbox, options.recordOutbox);
    this.health        = new HealthClient(http);
    this.na            = new NetworkAuthorityClient(http);
    this.grants        = new GrantsClient(http);
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
export { NetworkAuthorityClient, KeyHistoryError } from './network_authority.js';
export { GrantsClient } from './grants-client.js';
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
  POLICY_OMITTED_WHEN_ABSENT,
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
  treatyCanonical,
  verifyTreatySignature,
  CARRIED_KINDS,
  carriedSequences,
  isoMicros,
  keyPlacementProblem,
} from './verify.js';
export type {
  VerifyDecisionOptions, VerifyEvidenceOptions, ExecutorKeyInfo, RecognitionTreaty,
  AgreementVerification, AgreementVerificationReason, DataIntentVerification, DataUsageViolationDetail, DataUsageViolationType,
} from './verify.js';

// NA key succession and the key history (v1.5.0)
export {
  NAKeyHistory,
  MAX_DECISION_LIFETIME_SECONDS,
  NA_RECORD_TIME_FIELDS,
  RECORD_TIME_TOLERANCE_SECONDS,
  SUCCESSION_HANDOVER_SECONDS,
  SUCCESSION_MIN_LEAD_SECONDS,
  decisionOutlivesKey,
  genesisRefusal,
  naKeysAt,
  naSignatureAt,
  successionCanonical,
  successionDigest,
  successionRefusal,
  successionSignedBy,
  validPublicKey,
  verifyKeyHistory,
  verifyKeyHistoryView,
} from './key-history.js';
export type {
  GenesisBlock,
  KeyHistoryFailure,
  KeyHistoryVerification,
  KeyHistoryView,
  KeySuccessionRecord,
  NAKey,
  NAKeys,
  SuccessionContext,
} from './key-history.js';

// Store anchors (offline, v1.5.0)
export {
  anchorCanonical,
  anchorDigest,
  checkEventsAgainstAnchors,
  parseAnchors,
  startingCheckpoint,
  verifyStoreAnchors,
} from './anchors.js';
export type { AnchorFailure, AnchorVerification, CheckAnchorsOptions, StoreAnchor, VerifyAnchorsOptions } from './anchors.js';

// Audit packs, archives and the completeness check (v1.5.0)
export {
  AGREEMENTS_FILE,
  ANCHORS_FILE,
  ATTESTATIONS_FILE,
  CHANGE_COLUMNS,
  CHECKS_FILE,
  CITED_FILE,
  ENTRIES_FILE,
  EXECUTOR_KEYS_FILE,
  FEEDS_FILE,
  GENESIS_FILE,
  KEY_HISTORY_FILE,
  MANIFEST_FILE,
  OPTIONAL_PACK_FILES,
  PACK_FILES,
  PACK_FORMAT,
  PACK_FORMAT_VERSION,
  POLICIES_FILE,
  REPORT_FILE,
  STATES_FILE,
  TREATIES_FILE,
  archiveCanonical,
  auditPackFiles,
  checkCompleteness,
  packEntryDigests,
  packJsonBytes,
  packReasons,
  parseChanges,
  parseRfc3339,
  readAuditPackDir,
  receivedSignatureReason,
  registryKeys,
  renderReport,
  reportCell,
  reportHeader,
  verifyArchiveRecord,
  verifyAuditPack,
} from './audit-pack.js';
export type {
  ArchiveRecord,
  AuditPackManifest,
  AuditPackResponse,
  Change,
  CompletenessOptions,
  CompletenessPair,
  CompletenessReport,
  PackFile,
  PackFinding,
  PackPeriod,
  PackVerification,
  ReportHeader,
  VerifyAuditPackOptions,
} from './audit-pack.js';

// Strict verification: the field registry of signed records (v1.2.0)
export {
  unknownFields, isKnownEntryKind, canonicalTimestamp, nonCanonicalTimestamps, receivedCanonical, signedAsReceived,
  strictRefusal,
} from './strict.js';
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
  cancelByRotatingForward,
  urgentAction,
  RemediationNotRecordedError,
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
  RecordOutboxKind,
  OutboxRecord,
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
  recordMetadataProblem,
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
  EmergencyOptions,
  RotatedVersion,
  RotateForwardOptions,
  RotateForwardResult,
  UrgentActionResult,
} from './governance.js';

// Pre-issued grants (v1.6.0)
export {
  GRANT_CLOCK_SKEW_SECONDS,
  GRANT_MAX_USES,
  GRANT_MAX_USES_PER_TIME_TOKEN,
  GRANT_MAX_VALIDITY_SECONDS,
  GRANT_USE_REJECTION_CODES,
  MAX_ENVELOPE_PARAMETERS,
  MAX_ENVELOPE_VALUES,
  MAX_GRANT_CAPABILITIES,
  QUARANTINED_USE_CODES,
  GrantRecordError,
  checkGrantUse,
  continuesChain,
  envelopeParameter,
  envelopeProblem,
  envelopeShapeProblem,
  grantDigest,
  grantRecordCanonical,
  grantRecordDigest,
  grantUseDigest,
  grantUseRecord,
  inRange,
  nextPreviousUse,
  normalizeNumber,
  parameterValueProblem,
  scalarEquals,
  signGrantUse,
  signTimeTokenRequest,
  tokenSignatureValid,
  useProblem,
  useSecretProblem,
  validGrant,
  validGrantRevocation,
  validGrantUse,
  validTimeToken,
  validTimeTokenRequest,
  verifyCapabilityGrant,
  verifyGrantRevocation,
  verifyGrantUse,
  verifyTimeToken,
  verifyTimeTokenRequest,
} from './grants.js';
export type {
  CapabilityGrant,
  EnvelopeParameter,
  EnvelopeParameterInput,
  GrantBasisKind,
  GrantExecutionEvidence,
  GrantGateDecision,
  GrantGateOutcome,
  GrantNumber,
  GrantPolicyBinding,
  GrantRevocationReason,
  GrantRevocationRecord,
  GrantScalar,
  GrantUseInput,
  GrantUseOutcome,
  GrantUseRejectionCode,
  NumericRange,
  PreviousUse,
  TimeToken,
  TimeTokenRequest,
  TimeTokenRequestInput,
  UseChainHead,
  UseCheck,
  UseProblem,
} from './grants.js';

export {
  GRANT_FALLBACK_CODES,
  GrantHolder,
  GrantRefusedError,
  GrantStateNotKeptError,
  GrantUnusableError,
} from './grant-holder.js';
export type {
  GrantAction,
  GrantActParams,
  GrantActResult,
  GrantAuthority,
  GrantFallback,
  GrantFallbackResult,
  GrantHolderClients,
  GrantHolderOptions,
  GrantHolderState,
  GrantSyncResult,
  GrantUnusableCode,
  GrantUseResult,
} from './grant-holder.js';

// Remediation, reviews and emergency changes (v1.4.0)
export {
  DEFAULT_REMEDIATION,
  OPEN_STATES,
  QUEUE_FILTERS,
  REVIEW_REQUEST_PATH,
  STANDING_STATES,
  STORED_STATES,
  TransitionRefusedError,
  adminApprovalValid,
  cancelSteps,
  changeFacts,
  checkRemediation,
  checkRemediationRecord,
  decisionPlan,
  dueAfterDenial,
  dueAfterWaiver,
  emergencyMap,
  judgementState,
  nextState,
  policySectionIssues,
  remediationCanonical,
  remediationDueAt,
  remediationFormProblem,
  remediationGuidance,
  remediationPlan,
  remediationRecord,
  remediationRecordProblem,
  remediationSecretProblem,
  remediationSubject,
  reviewApprovalProblem,
  reviewDecisionPath,
  reviewHolderProblem,
  reviewRecordProblem,
  reviewRequestProblem,
  requestApprovalProblem,
  rfc3339,
  rotationProblem,
  signRemediation,
  stepsProblem,
  verifyRemediationRecord,
  verifyReviewRecord,
} from './remediation.js';
export type {
  AdminApproval,
  ChangeKind,
  GuidanceSource,
  PlannedSteps,
  RemediationDefaults,
  RemediationFallback,
  RemediationInput,
  RemediationKey,
  RemediationMode,
  RemediationOutcome,
  RemediationPlan,
  RemediationPlanInput,
  RemediationQueueFilter,
  RemediationRecord,
  RemediationState,
  RemediationStatus,
  RemediationSteps,
  RemediationSubject,
  RemediationSubjectKind,
  ReviewOpenedFor,
  ReviewRecord,
  ReviewSummary,
  ReviewVerdict,
  StoredRecord,
  TransitionEvent,
  TransitionRefusal,
} from './remediation.js';

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
export type * from './network_authority.js';
export type * from './grants-client.js';
export type * from './attestation.js';
export type * from './disclosure.js';
export type * from './consensus.js';
export type * from './data_usage.js';
