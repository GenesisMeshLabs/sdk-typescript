/**
 * Strict verification (v1.2.0): every field of a signed record is known.
 *
 * A verifier that copies every received field into the signed form accepts a
 * field it does not understand whenever the signer covered it, so a field
 * added in a later release could change what a record means. The registry
 * (src/canonical-registry.ts, generated from the Python reference) lists
 * every field of every record this SDK verifies; anything else is refused as
 * `unknown_field`, and an evidence export entry of another kind as
 * `unknown_entry_kind`. See the core's reference page "Canonical Form of
 * Signed Records".
 */

import { CANONICAL_REGISTRY } from './canonical-registry.js';

/** A field is a value (null), free-form JSON ('open'), or one, a list or a map of a nested model. */
export type FieldKind = null | 'open' | { object: string } | { list: string } | { map: string };

export interface ModelSpec {
  fields: Record<string, FieldKind>;
  root?: boolean;
  signature_field?: string | null;
  omit_when_none?: string[];
  canonical_fields?: string[];
}

export interface CanonicalRegistry {
  version: number;
  entry_kinds: string[];
  models: Record<string, ModelSpec>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Dotted paths of the fields in `data` that `model` does not define, at any
 * depth (`policy_binding.policies.0.extra`). Free-form fields are not
 * inspected; values of the wrong type are left to validation.
 */
export function unknownFields(
  model: string,
  data: unknown,
  registry: CanonicalRegistry = CANONICAL_REGISTRY,
  path = '',
): string[] {
  const spec = registry.models[model];
  if (!spec || !isRecord(data)) return [];
  const found: string[] = [];
  for (const [key, value] of Object.entries(data)) {
    if (!Object.prototype.hasOwnProperty.call(spec.fields, key)) {
      found.push(`${path}${key}`);
      continue;
    }
    const kind = spec.fields[key];
    if (value === null || value === undefined || kind === null || kind === 'open' || kind === undefined) continue;
    if ('object' in kind) {
      found.push(...unknownFields(kind.object, value, registry, `${path}${key}.`));
    } else if ('list' in kind && Array.isArray(value)) {
      value.forEach((item, i) => found.push(...unknownFields(kind.list, item, registry, `${path}${key}.${i}.`)));
    } else if ('map' in kind && isRecord(value)) {
      for (const [k, item] of Object.entries(value)) {
        found.push(...unknownFields(kind.map, item, registry, `${path}${key}.${k}.`));
      }
    }
  }
  return found;
}

/** True when the record has no field outside `model`. */
export function knownFieldsOnly(model: string, data: unknown): boolean {
  return unknownFields(model, data).length === 0;
}

/** True when this SDK knows the evidence entry kind. */
export function isKnownEntryKind(kind: unknown, registry: CanonicalRegistry = CANONICAL_REGISTRY): boolean {
  return typeof kind === 'string' && registry.entry_kinds.includes(kind);
}
