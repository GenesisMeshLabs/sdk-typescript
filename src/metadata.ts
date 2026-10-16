/**
 * Metadata guards shared by every signed record that carries metadata (execution
 * evidence, out-of-band records, boundary context): the size limit and the
 * reference's secret-material check. A leaf module: execution.ts and
 * out-of-band.ts both use it, and execution.ts re-exports it.
 */

import { jsonUtf8Size } from './auth.js';
import { GenesisMeshError } from './errors.js';

/** Limit on execution_parameters + outcome_detail, as enforced by the NA. */
export const MAX_METADATA_BYTES = 16 * 1024;

const SECRET_KEYS = new Set([
  'value', 'secret', 'secretvalue', 'password', 'passwd', 'passphrase', 'token',
  'accesstoken', 'refreshtoken', 'bearer', 'privatekey', 'keymaterial',
  'credential', 'credentials', 'clientsecret', 'apikey', 'pem', 'connectionstring',
]);
// `\n?$`: the reference's `$` also matches before a final newline (1.3.1).
const LONG_OPAQUE = /^[A-Za-z0-9+/=_-]{120,}\n?$/;
const JWT = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\n?$/;

/** Thrown before signing when a record would carry secret material; the NA would refuse it. */
export class SecretMaterialError extends GenesisMeshError {
  constructor(message: string) {
    super(message, 'evidence_secret_material', 0);
    this.name = 'SecretMaterialError';
  }
}

function normaliseKey(key: string): string {
  return key.toLowerCase().replace(/[-_.]/g, '');
}

/** The reference's `_secret_material`: the first field named like a secret, or holding a PEM block, key or token. */
export function secretMaterial(value: unknown, path = ''): string | null {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const found = secretMaterial(value[i], `${path}${i}.`);
      if (found) return found;
    }
  } else if (value !== null && typeof value === 'object') {
    for (const [key, inner] of Object.entries(value)) {
      if (SECRET_KEYS.has(normaliseKey(key))) return `field '${path}${key}' is not allowed in evidence metadata`;
      const found = secretMaterial(inner, `${path}${key}.`);
      if (found) return found;
    }
  } else if (typeof value === 'string') {
    const field = path.replace(/\.$/, '');
    if (value.includes('-----BEGIN')) return `field '${field}' contains a PEM block`;
    if (LONG_OPAQUE.test(value) || JWT.test(value)) return `field '${field}' looks like key or token material`;
  }
  return null;
}

/**
 * Why the metadata would be refused as secret material, or null. A guard, not a
 * guarantee: send identifiers, versions and timestamps, never secret values.
 */
export function checkMetadataOnly(
  executionParameters: Record<string, unknown>,
  outcomeDetail: string | null = null,
): string | null {
  // 1.3.1: sized as the NA sizes it, without JSON.stringify (which throws on a `bigint` read back from the outbox).
  const size = jsonUtf8Size({ execution_parameters: executionParameters, outcome_detail: outcomeDetail });
  if (size > MAX_METADATA_BYTES) return `metadata is ${size} bytes, over the ${MAX_METADATA_BYTES}-byte limit`;
  return secretMaterial(executionParameters) ?? (outcomeDetail ? secretMaterial({ outcome_detail: outcomeDetail }) : null);
}
