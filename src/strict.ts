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
 * entry of another kind as `unknown_entry_kind`. A record signed over a form
 * the reference does not write is refused as `non_canonical_form`; this SDK
 * checks the form of the timestamps the registry marks. See the core's
 * reference page "Canonical Form of Signed Records".
 */

import { CANONICAL_REGISTRY } from './canonical-registry.js';

/**
 * A field is a value (null), a timestamp ('timestamp', v1.2.0), free-form JSON
 * ('open'), or one, a list or a map of a nested model.
 */
export type FieldKind = null | 'open' | 'timestamp' | { object: string } | { list: string } | { map: string };

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
    if (value === null || value === undefined || kind === null || kind === undefined || typeof kind !== 'object') continue;
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

const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{6}))?(Z|[+-](\d{2}):(\d{2}))?$/;

/**
 * True when `value` is a timestamp in canonical form (v1.2.0): what the
 * reference writes, `YYYY-MM-DDTHH:MM:SS`, six digits of microseconds when not
 * all zero, then `Z` for UTC or `+HH:MM` / `-HH:MM` for another offset (none
 * for a timestamp without one), naming an instant that exists.
 */
export function canonicalTimestamp(value: unknown): boolean {
  const m = typeof value === 'string' ? TIMESTAMP.exec(value) : null;
  if (!m) return false;
  const [, year, month, day, hour, minute, second, fraction, zone, zoneHour, zoneMinute] = m;
  if (fraction === '000000' || zone === '+00:00' || zone === '-00:00') return false;
  if (zoneHour !== undefined && (Number(zoneHour) > 23 || Number(zoneMinute) > 59)) return false;
  const y = Number(year), mo = Number(month), d = Number(day);
  if (y < 1 || mo < 1 || mo > 12 || d < 1 || Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]!;
  return d <= days;
}

/**
 * Dotted paths, sorted, of the timestamps in `record`'s signed projection that
 * are not in canonical form (v1.2.0). Values that are not strings are left to
 * validation.
 */
export function nonCanonicalTimestamps(model: string, record: unknown, path = ''): string[] {
  const found: string[] = [];
  const walk = (name: string, data: unknown, prefix: string, projection: boolean) => {
    const s = CANONICAL_REGISTRY.models[name];
    if (!s || !isRecord(data)) return;
    for (const [key, value] of Object.entries(data)) {
      if (projection && outsideProjection(s, key)) continue;
      const kind = Object.prototype.hasOwnProperty.call(s.fields, key) ? s.fields[key] : null;
      if (value === null || value === undefined || kind === null || kind === undefined) continue;
      if (kind === 'timestamp') {
        const items = Array.isArray(value) ? value : [value];
        if (items.some(item => typeof item === 'string' && !canonicalTimestamp(item))) found.push(prefix + key);
      } else if (typeof kind === 'object' && 'object' in kind) {
        walk(kind.object, value, `${prefix}${key}.`, false);
      } else if (typeof kind === 'object' && 'list' in kind && Array.isArray(value)) {
        value.forEach((item, i) => walk(kind.list, item, `${prefix}${key}.${i}.`, false));
      } else if (typeof kind === 'object' && 'map' in kind && isRecord(value)) {
        for (const [k, item] of Object.entries(value)) walk(kind.map, item, `${prefix}${key}.${k}.`, false);
      }
    }
  };
  walk(model, record, path, true);
  return found.sort();
}
