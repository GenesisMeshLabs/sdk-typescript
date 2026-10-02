/**
 * Agent-side data access intents (v0.61): build and sign a DataAccessIntent
 * exactly as the Python reference `create_data_access_intent` does, so the NA
 * and every SDK verify it.
 */

import { randomUUID } from 'node:crypto';
import { pythonTimestamp, signCanonical, type Signer } from './auth.js';
import { dataAccessIntentCanonical } from './canonical.js';
import type { DataAccessIntent, DataSourceDescriptor } from './types.js';

export interface CreateDataAccessIntentParams {
  /** Sovereign the intent is declared by; the signer's key must belong to it. */
  agent_sovereign_id: string;
  /** The boundary decision this access is authorized under. */
  decision_id: string;
  sources: DataSourceDescriptor[];
  access_types: string[];
  estimated_volume_bytes?: number | null;
  /** Validity window in seconds. Default 300, as in the reference. */
  valid_for_seconds?: number;
  now?: Date;
  intent_id?: string;
}

/**
 * Build and sign a DataAccessIntent with the agent's signer. The reference
 * implementation uses the agent sovereign id as the signature key id, so pass
 * a signer whose `keyId` is the agent sovereign id for byte-identical output.
 */
export async function createDataAccessIntent(
  params: CreateDataAccessIntentParams,
  signer: Signer,
): Promise<DataAccessIntent> {
  const validFor = params.valid_for_seconds ?? 300;
  if (!Number.isSafeInteger(validFor) || validFor <= 0) throw new Error('valid_for_seconds must be a positive integer');
  const now = params.now ?? new Date();
  const intent: DataAccessIntent = {
    intent_id: params.intent_id ?? randomUUID(),
    agent_sovereign_id: params.agent_sovereign_id,
    decision_id: params.decision_id,
    declared_sources: params.sources.map(s => ({ ...s, classification_tags: [...(s.classification_tags ?? [])] })),
    declared_access_types: [...params.access_types],
    estimated_volume_bytes: params.estimated_volume_bytes ?? null,
    declared_at: pythonTimestamp(now),
    expires_at: pythonTimestamp(new Date(now.getTime() + validFor * 1000)),
    signature: null,
  };
  intent.signature = await signCanonical(dataAccessIntentCanonical(intent), signer);
  return intent;
}
