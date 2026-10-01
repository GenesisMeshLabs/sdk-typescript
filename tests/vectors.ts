import { readFileSync } from 'node:fs';
import { parseJson } from '../src/auth.js';
import type { BoundaryEvaluation, BoundaryPolicy, ExecutionEvidence, MembershipAttestation, RetentionCheckpoint } from '../src/types.js';
import type { ExecutorKeyInfo } from '../src/verify.js';

interface Vectors {
  na_public_key: string;
  executor_keys: ExecutorKeyInfo[];
  resource_id: string;
  vendor_id: string;
  attestation: MembershipAttestation;
  attestation_digest: string;
  policy: BoundaryPolicy;
  policy_digest: string;
  allowed: BoundaryEvaluation;
  denied: BoundaryEvaluation;
  executions: ExecutionEvidence[];
  execution_digests: string[];
  checkpoint: RetentionCheckpoint;
  export: string;
}
export function vectors(): Vectors {
  return parseJson(readFileSync(new URL('./fixtures/python-vectors.json', import.meta.url), 'utf8')) as Vectors;
}
