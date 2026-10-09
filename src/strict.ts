/**
 * Strict verification (v1.2.0): every signed field of a record is known.
 *
 * Before 1.2.0 this SDK copied every received field into the signed form, so
 * a field a newer signer covered verified here and could change what a record
 * means. The registry (src/canonical-registry.ts, generated from the Python
 * reference and shipped in the shared conformance suite `field_registry`)
 * lists every field of every record this SDK verifies. Verifiers check the
 * signature over the record as received first; a signed field the registry
 * does not list is then refused as `unknown_field`, and an evidence export
 * entry of another kind as `unknown_entry_kind`. See the core's reference
 * page "Canonical Form of Signed Records".
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

function spec(model: string): ModelSpec {
  const found = CANONICAL_REGISTRY.models[model];
  if (!found) throw new Error(`no registry entry for ${model}`);
  return found;
}

/** Whether a root's field is outside its signed projection (the signature, an agreement's unsigned fields). */
function outsideProjection(model: ModelSpec, key: string): boolean {
  return key === model.signature_field || (model.canonical_fields !== undefined && !model.canonical_fields.includes(key));
}

type Step = string | number;

function collect(model: string, data: unknown, path: Step[], projection: boolean, found: Step[][]): void {
  const s = CANONICAL_REGISTRY.models[model];
  if (!s || !isRecord(data)) return;
  for (const [key, value] of Object.entries(data)) {
    if (projection && outsideProjection(s, key)) continue;
    if (!Object.prototype.hasOwnProperty.call(s.fields, key)) {
      found.push([...path, key]);
      continue;
    }
    const kind = s.fields[key];
    if (value === null || value === undefined || kind === null || kind === 'open' || kind === undefined) continue;
    if ('object' in kind) {
      collect(kind.object, value, [...path, key], false, found);
    } else if ('list' in kind && Array.isArray(value)) {
      value.forEach((item, i) => collect(kind.list, item, [...path, key, i], false, found));
    } else if ('map' in kind && isRecord(value)) {
      for (const [k, item] of Object.entries(value)) collect(kind.map, item, [...path, key, k], false, found);
    }
  }
}

/**
 * Dotted paths of the signed fields in `record` that `model` does not define,
 * at any depth (`policy_binding.policies.0.extra`), sorted. Only the signed
 * projection is checked; free-form fields are not inspected; values of the
 * wrong type are left to validation.
 */
export function unknownFields(model: string, record: unknown, path = ''): string[] {
  const found: Step[][] = [];
  collect(model, record, [], true, found);
  return found.map(steps => path + steps.join('.')).sort();
}

/** True when this SDK knows the evidence entry kind. */
export function isKnownEntryKind(kind: unknown): boolean {
  return typeof kind === 'string' && CANONICAL_REGISTRY.entry_kinds.includes(kind);
}

/** The optional fields a root omits from its signed form when absent. */
export function omittedWhenAbsent(model: string): readonly string[] {
  return spec(model).omit_when_none ?? [];
}

/** The fixed signed fields of a root signed over a field list (agreements). */
export function canonicalFieldsOf(model: string): readonly string[] {
  return spec(model).canonical_fields ?? [];
}

/** A copy of `record` without its unknown signed fields (used to verify what the signer did sign). */
export function withoutUnknownFields<T>(model: string, record: T): T {
  const copy = JSON.parse(JSON.stringify(record)) as T;
  const found: Step[][] = [];
  collect(model, copy, [], true, found);
  for (const steps of found) {
    let node: unknown = copy;
    for (const step of steps.slice(0, -1)) node = (node as Record<string, unknown>)[step as string];
    if (isRecord(node)) delete node[steps[steps.length - 1] as string];
  }
  return copy;
}
