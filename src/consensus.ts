import type { HttpTransport } from './client.js';
import type {
  ConsensusProof,
  ConsensusVerification,
  JustificationProof,
  ValidatorVote,
} from './types.js';

export interface VoteParams {
  justification_proof: JustificationProof;
  vote: boolean;
  reason?: string;
}

export interface AssembleProofParams {
  justification_proof: JustificationProof;
  votes: ValidatorVote[];
  required_threshold: number;
  validator_sovereign_ids: string[];
}

export interface VerifyConsensusParams {
  proof: ConsensusProof;
  validator_public_keys?: Record<string, string>;
  assembler_public_keys?: string[];
}

export class ConsensusClient {
  constructor(private readonly http: HttpTransport) {}

  /** Cast a validator vote signed by the NA (admin). */
  vote(params: VoteParams): Promise<ValidatorVote> {
    return this.http.adminPost<ValidatorVote>('/admin/consensus/vote', params);
  }

  /** Assemble a consensus proof from votes (admin). */
  proof(params: AssembleProofParams): Promise<ConsensusProof> {
    return this.http.adminPost<ConsensusProof>('/admin/consensus/proof', params);
  }

  /** Verify consensus proof signature and threshold (unauthenticated). */
  verify(params: VerifyConsensusParams): Promise<ConsensusVerification> {
    return this.http.publicPost<ConsensusVerification>('/consensus/verify', params);
  }
}
