/**
 * Audit packs and archives (Genesis Mesh 1.5.0): offline verification of a
 * pack and the completeness check. Port of the reference's
 * `workflows/audit_pack.py` (`verify_audit_pack`, `check_completeness`), with
 * the same reason codes; the format is `docs/reference/audit-pack-format.md`
 * in the core.
 *
 * A pack holds one range of the evidence store between two anchors,
 * everything the range's records cite, the NA's key history and a manifest
 * the NA signs. It is verified with no network and no private key, from what
 * the auditor holds itself: the root public key and its copies of the
 * anchors. Keys inside the pack prove nothing alone: NA keys are accepted only
 * through the key history, from the root key down; executor and observer keys
 * only through registry records the NA signed, or keys the auditor supplies.
 */

import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { canonicalJsonUnescaped, compareCodePoints, copyPythonFloats, defineMember, parseJson, verifyCanonical } from './auth.js';
import { checkEventsAgainstAnchors, startingCheckpoint, verifyStoreAnchors, type StoreAnchor } from './anchors.js';
import { agreementCanonical, attestationDigest, entryDigest, policyDigest, policySetDigest } from './canonical.js';
import { validGrant, type CapabilityGrant } from './grants.js';
import { naSignatureAt, verifyKeyHistory, type NAKey, type NAKeyHistory, type NAKeys } from './key-history.js';
import { outOfBandCanonical } from './out-of-band.js';
import { nonCanonicalFields, signedAsReceived, strictRefusal, unknownFields } from './strict.js';
import type {
  AgreementRecord, AnchorSummary, BoundaryDecision, BoundaryPolicy, EvidenceEvent, EvidenceStoreVerification, MembershipAttestation,
  PolicyBinding, Signature, SovereignRevocationFeed,
} from './types.js';
import {
  isObject, timestamp, timestampMicros, validAnchor, validArchive, validAttestationRecord, validDecision, validFeed, validJudgement,
  validManifest, validPolicyRecord, validRegistry, validTreaty,
} from './validation.js';
import {
  carriedSequences, isoMicros, parseExportLines, verifyAgreement, verifyBoundaryDecision, verifyEvidenceEvents,
  type ExecutorKeyInfo, type RecognitionTreaty,
} from './verify.js';

export const PACK_FORMAT = 'gm.audit.pack';
export const PACK_FORMAT_VERSION = 1;

export const MANIFEST_FILE = 'manifest.json';
export const REPORT_FILE = 'report.md';
export const CHECKS_FILE = 'checks.json';
export const GENESIS_FILE = 'genesis.json';
export const KEY_HISTORY_FILE = 'keys/na-key-history.json';
export const EXECUTOR_KEYS_FILE = 'keys/executor-keys.json';
export const ANCHORS_FILE = 'anchors.jsonl';
export const ENTRIES_FILE = 'entries.jsonl';
export const CITED_FILE = 'cited.jsonl';
export const POLICIES_FILE = 'policies.jsonl';
export const ATTESTATIONS_FILE = 'trust/attestations.jsonl';
export const TREATIES_FILE = 'trust/treaties.jsonl';
export const FEEDS_FILE = 'trust/feeds.jsonl';
/** The NA's remediation states and notices at pack time (operational records, not signed), which `report.md` shows. */
export const STATES_FILE = 'states.json';

/** Every file of a pack (format version 1) but the manifest, which lists them. */
export const PACK_FILES: readonly string[] = [
  ANCHORS_FILE, CHECKS_FILE, CITED_FILE, ENTRIES_FILE, EXECUTOR_KEYS_FILE, GENESIS_FILE, KEY_HISTORY_FILE,
  POLICIES_FILE, REPORT_FILE, STATES_FILE, ATTESTATIONS_FILE, FEEDS_FILE, TREATIES_FILE,
];
/**
 * v1.6.0: the agreements the pack's grants rest on, each as received. A pack holds it only when it
 * holds a grant under an agreement, so a pack without one keeps the 1.5 file set.
 */
export const AGREEMENTS_FILE = 'trust/agreements.jsonl';
/** Files of the format a pack holds only when it has something to put in them (v1.6.0). */
export const OPTIONAL_PACK_FILES: readonly string[] = [AGREEMENTS_FILE];

/** One file of a pack: its `/`-separated relative path, SHA-256 and size. */
export interface PackFile {
  path: string;
  sha256: string;
  bytes: number;
}

/** `manifest.json`: every other file of a pack and its digest, signed by the NA key valid at `created_at`. */
export interface AuditPackManifest {
  format: 'gm.audit.pack';
  format_version: 1;
  pack_id: string;
  sovereign_id: string;
  created_at: string;
  requested_by?: string | null;
  from_sequence: number;
  through_sequence: number;
  /** The anchor that names the entry before the range; absent when the range starts at entry 1 or after a checkpoint. */
  start_anchor_sequence?: number | null;
  /** The anchor that names the range's last entry. */
  end_anchor_sequence: number;
  /** The period the pack was asked for (`since`, `until`), when it was; the period it covers is the verifier's to compute. */
  period_from?: string | null;
  period_until?: string | null;
  files: PackFile[];
  issued_by: string;
  signature?: Signature | null;
}

/** A pack written to immutable storage and read back intact (entry kind `archive`), signed by the NA. */
export interface ArchiveRecord {
  archive_id: string;
  pack_id: string;
  from_sequence: number;
  through_sequence: number;
  through_entry_digest: string;
  end_anchor_sequence: number;
  /** SHA-256 of `manifest.json` as written. */
  manifest_sha256: string;
  location: string;
  archived_at: string;
  recorded_by?: string | null;
  issuer_sovereign_id: string;
  issued_by: string;
  signature?: Signature | null;
}

/** The signed form of an archive record or a manifest: every field but `signature`, absent optional fields left out. */
export function archiveCanonical(record: ArchiveRecord | AuditPackManifest): string {
  return outOfBandCanonical(record);
}

/**
 * True when an archive record is well formed and signed by the NA (v1.5.0:
 * given the key history, by the key valid at its `archived_at`), in the
 * reference's form, with no field this SDK does not know.
 */
export function verifyArchiveRecord(record: ArchiveRecord, naPublicKeys: NAKeys): boolean {
  if (!validArchive(record) || unknownFields('ArchiveRecord', record).length > 0
    || nonCanonicalFields('ArchiveRecord', record).length > 0) {
    return false;
  }
  const sig = record.signature;
  return naSignatureAt(keys => typeof sig?.sig === 'string' && verifyCanonical(archiveCanonical(record), sig.sig, keys),
    naPublicKeys, record.archived_at) === 'ok';
}

/** A JSON file of a pack: canonical JSON (non-ASCII text kept) and a final newline. */
export function packJsonBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJsonUnescaped(value) + '\n', 'utf-8');
}

/** `POST /admin/evidence/audit-pack`: the signed manifest and every other file as text. */
export interface AuditPackResponse {
  manifest: AuditPackManifest;
  files: Record<string, string>;
}

/** The files of a pack the NA returned, with `manifest.json` written as the NA writes it: ready to save or verify. */
export function auditPackFiles(response: AuditPackResponse): Record<string, Buffer> {
  const files: Record<string, Buffer> = {};
  for (const [path, text] of Object.entries(response.files)) defineMember(files, path, Buffer.from(text, 'utf-8'));
  defineMember(files, MANIFEST_FILE, packJsonBytes(withoutNulls(response.manifest)));
  return files;
}

/** Every file under `directory`, by its `/`-separated relative path. */
export async function readAuditPackDir(directory: string): Promise<Record<string, Buffer>> {
  const files: Record<string, Buffer> = {};
  const items = await readdir(directory, { recursive: true, withFileTypes: true });
  const paths = items.filter(item => item.isFile())
    .map(item => relative(directory, join(item.parentPath, item.name)).split(sep).join('/'))
    .sort(compareCodePoints);
  for (const path of paths) defineMember(files, path, await readFile(join(directory, path)));
  return files;
}

// ── Verification ──────────────────────────────────────────────────────────────

export interface PackFinding {
  /** The pack file the finding is reported against (`known-anchors` for the anchors held, `changes`). */
  file: string | null;
  store_sequence: number | null;
  reason: string;
  detail: string;
}

/** The period a pack covers, and the ones it was asked for (`requested_*`) and checked against (`asked_*`). */
export interface PackPeriod {
  from: string;
  until: string;
  requested_from?: string;
  requested_until?: string;
  asked_from?: string;
  asked_until?: string;
}

export interface PackVerification {
  verified: boolean;
  failures: PackFinding[];
  /** `no_held_anchors`, `cited_entry_unanchored` and other findings that do not fail the pack. */
  warnings: PackFinding[];
  /** The counts of the entries' verification. */
  counts: Record<string, number>;
  /** The range the entries hold. */
  range: { from_sequence: number; through_sequence: number; entries: number; first_recorded_at: string; last_recorded_at: string } | null;
  /** How the entries tie to the anchors held; null without them. */
  anchors: AnchorSummary | null;
  /** The NA's keys, as the key history verified from the root key gives them. */
  keys: NAKey[];
  /** The period the pack covers: from its start anchor (or the checkpoint it starts after, or its first entry) to its end anchor. */
  period: PackPeriod | null;
  /** The lines where `report.md` differs from the report the pack renders to (`report_mismatch`). */
  report_differences: Array<{ line: number; pack: string | null; verifier: string | null }>;
  /** With `changes`: the completeness check. */
  completeness: CompletenessReport | null;
}

/** The failure reason codes, sorted (what two verifiers compare). */
export function packReasons(result: PackVerification): string[] {
  return [...new Set(result.failures.map(f => f.reason))].sort(compareCodePoints);
}

export interface VerifyAuditPackOptions {
  /** The root public key, held out of band (`root.pub`). */
  rootPublicKey: string;
  /**
   * The anchors the verifier holds (its copies, kept outside the operator's
   * reach). Null verifies the pack's integrity only, not that nothing was
   * removed, and says so (`no_held_anchors`).
   */
  heldAnchors: readonly StoreAnchor[] | null;
  /** Executor and observer keys supplied out of band, for a store without registry records (a key the pack's registry records place wins). */
  executorKeys?: Record<string, ExecutorKeyInfo> | readonly ExecutorKeyInfo[];
  /** Changes from a log outside Genesis Mesh: runs the completeness check (`change_unmatched`). */
  changes?: readonly Change[] | null;
  /** The completeness check's time tolerance (default 300 seconds). */
  toleranceSeconds?: number;
  /** A period the pack must cover, [from, until] (`pack_period_not_covered`). */
  period?: readonly [string, string] | null;
  /**
   * The entries of packs verified before, by store position (`packEntryDigests`):
   * the entries this pack cites must equal them (`cited_entry_mismatch`).
   */
  priorEntries?: Readonly<Record<number, string>> | ReadonlyMap<number, string> | null;
}

const DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function text(data: Uint8Array): string {
  return DECODER.decode(data);
}

function json(data: Uint8Array | undefined): unknown {
  if (data === undefined) throw new Error('missing file');
  return parseJson(text(data));
}

/** JSON Lines: one value per LF-separated line, blank lines ignored. */
function jsonLines(data: Uint8Array | undefined): unknown[] {
  if (data === undefined) throw new Error('missing file');
  return text(data).split('\n').filter(line => line.replace(/^[ \t\r]+|[ \t\r]+$/g, '') !== '').map(line => parseJson(line));
}

function events(data: Uint8Array | undefined): EvidenceEvent[] {
  if (data === undefined) throw new Error('missing file');
  return parseExportLines(text(data).split('\n'));
}

function withoutNulls(record: object): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (value !== null && value !== undefined) defineMember(out, key, value);
  }
  copyPythonFloats(record, out);
  return out;
}

function message(err: unknown): string {
  return String(err instanceof Error ? err.message : err).slice(0, 200);
}

/** A timestamp as the reference writes it in a report: UTC, six fraction digits when not zero, `Z`. */
function iso(value: string): string {
  return isoMicros(timestampMicros(value));
}

/** Two anchors are the same when their wire forms are (timestamps compared as instants). */
function sameAnchor(a: StoreAnchor, b: StoreAnchor): boolean {
  const wire = (x: StoreAnchor) => canonicalJsonUnescaped({ ...withoutNulls(x), anchored_at: timestampMicros(x.anchored_at) });
  return wire(a) === wire(b);
}

function normalizeFiles(files: Record<string, Uint8Array | string>): Map<string, Uint8Array> {
  return new Map(Object.entries(files).map(([path, body]) => [path, typeof body === 'string' ? Buffer.from(body, 'utf-8') : body]));
}

function digestMatches(body: Uint8Array, item: PackFile): boolean {
  return createHash('sha256').update(body).digest('hex') === item.sha256 && body.length === item.bytes;
}

type PackFail = (file: string | null, storeSequence: number | null, reason: string, detail?: string) => void;

/** The entries a pack holds, by store position: their digests as received (for `priorEntries`). */
export function packEntryDigests(files: Record<string, Uint8Array | string>): Record<number, string> {
  const out: Record<number, string> = {};
  for (const event of events(normalizeFiles(files).get(ENTRIES_FILE))) out[event.entry.store_sequence] = entryDigest(event.entry);
  return out;
}

/**
 * Why a record's signature does not verify, over the record as received, with
 * the NA key valid at `at`, or null: `unknown_field` or `non_canonical_form`
 * for a record its signer signed in another form, `na_key_not_valid_at_time`
 * for one signed by another key of the history, `invalid_signature` otherwise.
 */
export function receivedSignatureReason(model: string, raw: unknown, history: NAKeyHistory, at: string): string | null {
  if (!isObject(raw)) return 'invalid_signature';
  const keys = history.keysAt(at);
  if (signedAsReceived(model, raw, keys)) return strictRefusal(model, raw, keys);
  const others = history.allKeys().filter(k => !keys.includes(k));
  if (others.length > 0 && signedAsReceived(model, raw, others)) return 'na_key_not_valid_at_time';
  return 'invalid_signature';
}

/** As `receivedSignatureReason`, for keys with no time (a treaty's subject keys). */
function receivedBy(model: string, raw: unknown, keys: readonly string[]): string | null {
  if (!isObject(raw) || !signedAsReceived(model, raw, keys)) return 'invalid_signature';
  return strictRefusal(model, raw, keys);
}

function checkManifest(files: ReadonlyMap<string, Uint8Array>, fail: PackFail): AuditPackManifest | null {
  const raw = files.get(MANIFEST_FILE);
  if (raw === undefined) {
    fail(MANIFEST_FILE, null, 'manifest_missing');
    return null;
  }
  let data: unknown;
  try {
    data = json(raw);
    if (isObject(data) && unknownFields('AuditPackManifest', data).length > 0) throw new Error('unknown field');
    if (!validManifest(data)) throw new Error('not an audit pack manifest');
  } catch (err) {
    fail(MANIFEST_FILE, null, 'manifest_invalid', message(err));
    return null;
  }
  const manifest = data as unknown as AuditPackManifest;
  // The bytes the NA writes: canonical JSON of the record, integers as integers, timestamps in canonical form.
  const written = packJsonBytes(JSON.parse(JSON.stringify(withoutNulls(manifest))));
  if (nonCanonicalFields('AuditPackManifest', manifest).length > 0 || !written.equals(raw)) {
    fail(MANIFEST_FILE, null, 'manifest_invalid', 'not in canonical form');
  }
  const listed = new Map<string, PackFile>();
  for (const item of manifest.files) {
    if (listed.has(item.path) || item.path === MANIFEST_FILE) {
      fail(MANIFEST_FILE, null, 'manifest_invalid', `lists ${item.path} twice or itself`);
    }
    listed.set(item.path, item);
  }
  for (const path of PACK_FILES) {
    if (!listed.has(path)) fail(MANIFEST_FILE, null, 'manifest_file_missing', `${path} is not listed`);
  }
  for (const path of [...listed.keys()].sort(compareCodePoints)) {
    if (!PACK_FILES.includes(path) && !OPTIONAL_PACK_FILES.includes(path)) {
      // A pack holds the files of its format and nothing else.
      fail(MANIFEST_FILE, null, 'manifest_unknown_file', `${path} is not a file of the format`);
      continue;
    }
    const body = files.get(path);
    if (body === undefined) fail(path, null, 'manifest_file_missing');
    else if (!digestMatches(body, listed.get(path)!)) fail(path, null, 'manifest_digest_mismatch');
  }
  for (const path of [...files.keys()].sort(compareCodePoints)) {
    if (path !== MANIFEST_FILE && !listed.has(path)) fail(path, null, 'manifest_unlisted_file');
  }
  return manifest;
}

/**
 * Executor and observer keys from the registry records the NA signed (by the
 * key valid then), each placed where the store registered and retired it: by
 * store position, or by `effective_at` for a record backfilled at an upgrade
 * (`reconstructed`) or carried past retention.
 */
export function registryKeys(all: readonly EvidenceEvent[], history: NAKeyHistory): Record<string, ExecutorKeyInfo> {
  const ordered = [...all].sort((a, b) => a.entry.store_sequence - b.entry.store_sequence);
  const carried = carriedSequences(ordered);
  const keys: Record<string, ExecutorKeyInfo> = {};
  for (const event of ordered) {
    if (event.entry.entry_kind !== 'registry') continue;
    const record = event.payload;
    if (!validRegistry(record) || unknownFields('RegistryRecord', record).length > 0) continue;
    if (receivedSignatureReason('RegistryRecord', record, history, event.entry.recorded_at) !== null) continue;
    const r = record as Record<string, unknown>;
    const seq = event.entry.store_sequence;
    const byTime = r['reconstructed'] === true || carried.has(seq);
    const keyId = typeof r['key_id'] === 'string' ? r['key_id'] : '';
    if (r['event'] === 'executor_key_registered' && keyId && r['public_key'] && r['executor_sovereign_id']) {
      const held = Object.hasOwn(keys, keyId) ? keys[keyId] : undefined;
      if (held !== undefined && held.public_key === r['public_key']) continue; // the first registration places it
      defineMember(keys as Record<string, unknown>, keyId, {
        key_id: keyId, public_key: r['public_key'], executor_sovereign_id: r['executor_sovereign_id'],
        role: (r['key_role'] as ExecutorKeyInfo['role']) || 'executor', resource_prefix: r['resource_prefix'] ?? null,
        registered_sequence: byTime ? null : seq, registered_at_time: byTime ? r['effective_at'] : null,
        retired_sequence: null, retired_at_time: null,
      });
    } else if (r['event'] === 'executor_key_retired' && keyId && Object.hasOwn(keys, keyId)) {
      const held = keys[keyId]!;
      if ((held.retired_sequence ?? null) === null && (held.retired_at_time ?? null) === null) {
        defineMember(keys as Record<string, unknown>, keyId, {
          ...held, retired_sequence: byTime ? null : seq, retired_at_time: byTime ? r['effective_at'] as string : null,
        });
      }
    }
  }
  return keys;
}

/**
 * Verify an audit pack offline, in the reference's order, each failure named
 * by a reason code:
 *
 * 1. the manifest (`manifest_missing`, `manifest_invalid`,
 *    `manifest_unknown_file`, `manifest_file_missing`,
 *    `manifest_digest_mismatch`, `manifest_unlisted_file`), signed as received
 *    by the NA key valid at its `created_at` (`manifest_invalid_signature`): a
 *    pack whose manifest fails is not checked further;
 * 2. the key history, from the root key down (`genesis_*`, `succession_*`,
 *    `key_history_invalid`);
 * 3. the anchors (the anchor reasons, `pack_end_anchor_mismatch`,
 *    `pack_end_anchor_not_held`, `pack_start_not_tied`, `manifest_backdated`,
 *    `anchor_mismatch`, `anchor_entry_missing`,
 *    `export_not_linked_to_anchors`; without held anchors the warning
 *    `no_held_anchors`), and each cited entry against a prior pack or a held
 *    anchor (`cited_entry_mismatch`; the warning `cited_entry_unanchored`);
 * 4. the entries (`entries_invalid`, `pack_range_mismatch`,
 *    `cited_out_of_range`, then every export reason);
 * 5. what the records rest on, each checked as received
 *    (`cited_trust_invalid`, `policy_invalid_signature`,
 *    `treaty_invalid_signature`, `attestation_invalid_signature`,
 *    `feed_invalid_signature`, `cited_policy_missing`,
 *    `cited_policy_mismatch`, `cited_attestation_missing`,
 *    `cited_attestation_mismatch`);
 * 6. the report, rendered from the pack's own files (`report_mismatch`);
 * 7. with `period`, that the pack covers it (`pack_period_not_covered`);
 * 8. with `changes`, completeness (`change_unmatched`; the warnings
 *    `changes_outside_period` and `change_duplicate`).
 *
 * Decisions are judged as of their own time: one that expired since it was
 * made and used is not a failure.
 */
export function verifyAuditPack(
  files: Record<string, Uint8Array | string>,
  options: VerifyAuditPackOptions,
): PackVerification {
  const result: PackVerification = {
    verified: true, failures: [], warnings: [], counts: {}, range: null, anchors: null, keys: [], period: null,
    report_differences: [], completeness: null,
  };
  const fail: PackFail = (file, storeSequence, reason, detail = '') => {
    result.verified = false;
    result.failures.push({ file, store_sequence: storeSequence, reason, detail });
  };
  const warn: PackFail = (file, storeSequence, reason, detail = '') => {
    result.warnings.push({ file, store_sequence: storeSequence, reason, detail });
  };
  const pack = normalizeFiles(files);
  const manifest = checkManifest(pack, fail);

  // 2. The key history, from the root key down.
  let genesis: unknown;
  let successions: unknown;
  try {
    genesis = json(pack.get(GENESIS_FILE));
    const keyHistory = json(pack.get(KEY_HISTORY_FILE));
    if (!isObject(keyHistory)) throw new Error('the key history is not an object');
    successions = Object.hasOwn(keyHistory, 'successions') ? keyHistory['successions'] : [];
  } catch (err) {
    fail(KEY_HISTORY_FILE, null, 'key_history_invalid', message(err));
    return result;
  }
  const keyed = verifyKeyHistory(genesis, Array.isArray(successions) ? successions : [], options.rootPublicKey);
  for (const failure of keyed.failures) {
    fail(failure.key_sequence === 1 ? GENESIS_FILE : KEY_HISTORY_FILE, null, failure.reason, `key ${failure.key_sequence}`);
  }
  if (!keyed.verified || keyed.history === null) return result;
  const history = keyed.history;
  result.keys = [...history.keys];

  if (manifest !== null) {
    if (manifest.sovereign_id !== history.sovereign_id) fail(MANIFEST_FILE, null, 'manifest_invalid', 'names another sovereign');
    // Over the manifest as received, not a form with its defaults filled in.
    const reason = receivedSignatureReason('AuditPackManifest', manifest, history, manifest.created_at);
    if (reason !== null) fail(MANIFEST_FILE, null, reason === 'invalid_signature' ? 'manifest_invalid_signature' : reason);
  }
  // Files that do not match a manifest the NA signed are not the pack: nothing else is checked.
  if (!result.verified) return result;

  // 3 and 4. Anchors and entries.
  let packAnchors: StoreAnchor[];
  let entries: EvidenceEvent[];
  let cited: EvidenceEvent[];
  try {
    const anchors = jsonLines(pack.get(ANCHORS_FILE));
    if (!anchors.every(validAnchor)) throw new Error('an anchor is not a StoreAnchor');
    packAnchors = (anchors as StoreAnchor[]).sort((a, b) => a.anchor_sequence - b.anchor_sequence);
    entries = events(pack.get(ENTRIES_FILE));
    cited = events(pack.get(CITED_FILE));
  } catch (err) {
    fail(ENTRIES_FILE, null, 'entries_invalid', message(err));
    return result;
  }
  if (entries.length === 0) {
    fail(ENTRIES_FILE, null, 'pack_range_mismatch', 'the pack holds no entry');
    return result;
  }
  const head = entries[0]!;
  const tail = entries[entries.length - 1]!;
  const first = head.entry.store_sequence;
  const last = tail.entry.store_sequence;
  const fromSequence = manifest ? manifest.from_sequence : first;
  const through = manifest ? manifest.through_sequence : last;
  result.range = {
    from_sequence: first, through_sequence: last, entries: entries.length,
    first_recorded_at: head.entry.recorded_at, last_recorded_at: tail.entry.recorded_at,
  };
  if (first !== fromSequence || last !== through || entries.length !== through - fromSequence + 1) {
    fail(ENTRIES_FILE, null, 'pack_range_mismatch',
      `the entries run ${first}..${last}, the manifest says ${fromSequence}..${through}`);
  }
  for (const event of cited) {
    if (event.entry.store_sequence >= fromSequence) fail(CITED_FILE, event.entry.store_sequence, 'cited_out_of_range');
  }

  const chain = verifyStoreAnchors(packAnchors, { naPublicKeys: history, sovereignId: history.sovereign_id });
  for (const failure of chain.failures) fail(ANCHORS_FILE, null, failure.reason, `anchor ${failure.anchor_sequence}`);
  const bySequence = new Map(packAnchors.map(a => [a.anchor_sequence, a]));
  const end = manifest ? bySequence.get(manifest.end_anchor_sequence) : packAnchors[packAnchors.length - 1];
  if (end === undefined || end.store_sequence !== last || end.entry_digest !== entryDigest(tail.entry)) {
    fail(ANCHORS_FILE, last, 'pack_end_anchor_mismatch', "no anchor of the pack names the range's last entry");
  }
  const startSequence = manifest?.start_anchor_sequence ?? null;
  const startAnchor = manifest
    ? (startSequence ? bySequence.get(startSequence) : undefined)
    : [...packAnchors].reverse().find(a => a.store_sequence === first - 1);
  if (startSequence && (startAnchor === undefined || startAnchor.store_sequence !== first - 1
    || startAnchor.entry_digest !== head.entry.prev_entry_digest)) {
    fail(ANCHORS_FILE, first, 'pack_start_not_tied', 'the start anchor does not name the entry before the range');
  }
  if (manifest !== null) {
    // The NA writes a pack after its end anchor and its last entry.
    const latest = Math.max(timestampMicros(tail.entry.recorded_at), ...(end ? [timestampMicros(end.anchored_at)] : []));
    if (timestampMicros(manifest.created_at) < latest) {
      fail(MANIFEST_FILE, null, 'manifest_backdated', `created at ${iso(manifest.created_at)}, before ${isoMicros(latest)}`);
    }
  }

  // The start checkpoint: a retention checkpoint (in the range or cited) that removed the entries before it.
  const startCheckpoint = startingCheckpoint([...entries, ...cited].reverse(), head);
  if (first === 1 && head.entry.prev_entry_digest !== null) {
    fail(ENTRIES_FILE, 1, 'store_chain_break', 'entry 1 names a previous entry');
  }

  const held = options.heldAnchors === null ? null : [...options.heldAnchors];
  if (held === null) {
    warn(null, null, 'no_held_anchors',
      'verified without anchors held out of band: the pack\'s integrity, not that nothing was removed');
  } else {
    const heldChain = verifyStoreAnchors(held, { naPublicKeys: history, sovereignId: history.sovereign_id });
    for (const failure of heldChain.failures) {
      fail('known-anchors', null, failure.reason, `held anchor ${failure.anchor_sequence}`);
    }
    const heldBySequence = new Map(held.map(a => [a.anchor_sequence, a]));
    for (const anchor of packAnchors) {
      const mine = heldBySequence.get(anchor.anchor_sequence);
      if (mine !== undefined && !sameAnchor(mine, anchor)) {
        fail(ANCHORS_FILE, anchor.store_sequence, 'anchor_mismatch', `anchor ${anchor.anchor_sequence} differs from the one held`);
      }
    }
    if (end !== undefined && !heldBySequence.has(end.anchor_sequence)) {
      fail(ANCHORS_FILE, last, 'pack_end_anchor_not_held', `anchor ${end.anchor_sequence} is not among the anchors held`);
    }
    const inside = held.filter(a => a.store_sequence <= last);
    const tied: EvidenceStoreVerification = { verified: true, checked_entries: 0, decisions: 0, executions: 0, failures: [] };
    checkEventsAgainstAnchors(entries, inside, tied, { fromAnchor: true });
    for (const failure of tied.failures) fail(ENTRIES_FILE, failure.store_sequence, failure.reason, failure.detail);
    result.anchors = tied.anchors ?? null;
  }

  // A cited entry is checked against what the verifier holds at its position: an entry of a pack
  // verified before, or an anchor naming that very entry. Neither: a warning.
  const prior = options.priorEntries ?? null;
  const priorAt = (seq: number): string | undefined => (prior === null ? undefined
    : prior instanceof Map ? prior.get(seq) : (prior as Readonly<Record<number, string>>)[seq]);
  const heldAt = new Map((held ?? []).map(a => [a.store_sequence, a]));
  for (const event of cited) {
    const seq = event.entry.store_sequence;
    const digest = entryDigest(event.entry);
    const known = priorAt(seq);
    const anchor = heldAt.get(seq);
    if (known !== undefined && known !== digest) {
      fail(CITED_FILE, seq, 'cited_entry_mismatch', 'differs from the entry a prior pack holds');
    } else if (anchor !== undefined && anchor.entry_digest !== digest) {
      fail(CITED_FILE, seq, 'cited_entry_mismatch', `differs from held anchor ${anchor.anchor_sequence}`);
    } else if (known === undefined && anchor === undefined) {
      warn(CITED_FILE, seq, 'cited_entry_unanchored', 'signed, but neither a prior pack nor a held anchor covers this entry');
    }
  }

  // 4. Executor keys: keys supplied out of band, and registry records the NA signed (which win).
  const supplied = options.executorKeys ?? {};
  const keys = {
    ...(Array.isArray(supplied) ? Object.fromEntries((supplied as readonly ExecutorKeyInfo[]).map(k => [k.key_id, k])) : supplied),
    ...registryKeys([...cited, ...entries], history),
  };
  const verification = verifyEvidenceEvents(entries, {
    naPublicKeys: history, executorKeys: keys, contiguous: true, checkpoint: startCheckpoint, prior: cited,
  });
  const fileOf = (seq: number | null) => (seq !== null && seq < fromSequence ? CITED_FILE : ENTRIES_FILE);
  for (const failure of verification.failures) {
    fail(fileOf(failure.store_sequence), failure.store_sequence, failure.reason, failure.detail);
  }
  for (const warning of verification.warnings ?? []) {
    warn(fileOf(warning.store_sequence), warning.store_sequence, warning.reason, warning.detail);
  }
  for (const [name, value] of Object.entries(verification)) {
    if (typeof value === 'number') result.counts[name] = value;
  }

  // 5. What the records cite outside the store.
  checkCitedTrust(pack, entries, cited, history, fail);

  // 6. The report renders from the pack's own files.
  if (manifest !== null) checkReport(pack, manifest, entries, result, fail);

  // 7. The period the pack covers: from its start anchor (or the retention checkpoint it starts after,
  // or its first entry, at the start of the store) to its end anchor.
  const coveredFrom = startAnchor !== undefined ? timestampMicros(startAnchor.anchored_at)
    : startCheckpoint !== null ? timestampMicros(startCheckpoint.created_at) : timestampMicros(head.entry.recorded_at);
  const coveredUntil = end !== undefined ? timestampMicros(end.anchored_at) : timestampMicros(tail.entry.recorded_at);
  const period: PackPeriod = { from: isoMicros(coveredFrom), until: isoMicros(coveredUntil) };
  if (manifest?.period_from) period.requested_from = iso(manifest.period_from);
  if (manifest?.period_until) period.requested_until = iso(manifest.period_until);
  result.period = period;
  if (options.period) {
    const wantedFrom = timestampMicros(options.period[0]);
    const wantedUntil = timestampMicros(options.period[1]);
    period.asked_from = isoMicros(wantedFrom);
    period.asked_until = isoMicros(wantedUntil);
    if (wantedFrom < coveredFrom || wantedUntil > coveredUntil) {
      fail(null, null, 'pack_period_not_covered', `the pack covers ${period.from} to ${period.until}`);
    }
  }

  // 8. Completeness.
  if (options.changes !== undefined && options.changes !== null) {
    const report = checkCompleteness(options.changes, entries, cited, {
      period: [period.from, period.until], toleranceSeconds: options.toleranceSeconds,
    });
    result.completeness = report;
    for (const item of report.unmatched_changes) {
      fail('changes', null, 'change_unmatched', `${item.source || '-'} ${item.source_event_id || '-'} ${item.resource_id} `
        + `${item.action} ${item.changed_at}`);
    }
    if (report.outside_period.length > 0) {
      warn('changes', null, 'changes_outside_period', `${report.outside_period.length} change(s) dated outside the period `
        + `the pack covers (${period.from} to ${period.until})`);
    }
    for (const item of report.duplicate_changes) {
      warn('changes', null, 'change_duplicate', `change ${item.index} repeats ${item.source} ${item.source_event_id}`);
    }
  }
  return result;
}

/** `report.md` is the report `renderReport` writes from the pack's own files (`report_mismatch`). */
function checkReport(
  files: ReadonlyMap<string, Uint8Array>,
  manifest: AuditPackManifest,
  entries: readonly EvidenceEvent[],
  result: PackVerification,
  fail: PackFail,
): void {
  let checks: unknown;
  let states: unknown;
  let claimed: string;
  try {
    checks = json(files.get(CHECKS_FILE));
    states = json(files.get(STATES_FILE));
    const report = files.get(REPORT_FILE);
    if (report === undefined) throw new Error('missing file');
    claimed = text(report);
  } catch (err) {
    fail(REPORT_FILE, null, 'report_mismatch', `cannot be rendered: ${message(err).slice(0, 160)}`);
    return;
  }
  if (!isObject(checks) || !isObject(states)) {
    fail(REPORT_FILE, null, 'report_mismatch', 'checks.json and states.json are JSON objects');
    return;
  }
  const expected = renderReport({
    manifest: reportHeader(manifest), entries, checks,
    states: (isObject(states['states']) ? states['states'] : {}) as Record<string, unknown>,
    notices: (isObject(states['notices']) ? states['notices'] : {}) as Record<string, unknown>,
  });
  if (expected === claimed) return;
  const ours = expected.split('\n');
  const theirs = claimed.split('\n');
  for (let i = 0; i < Math.max(ours.length, theirs.length); i++) {
    const mine = i < ours.length ? ours[i]! : null;
    const pack = i < theirs.length ? theirs[i]! : null;
    if (mine !== pack) result.report_differences.push({ line: i + 1, pack, verifier: mine });
  }
  fail(REPORT_FILE, null, 'report_mismatch',
    `${result.report_differences.length} line(s) differ from the report the pack renders to`);
}

/** Policies, attestations, treaties and feeds the records rest on (outside the store), each checked as received. */
function checkCitedTrust(
  files: ReadonlyMap<string, Uint8Array>,
  entries: readonly EvidenceEvent[],
  cited: readonly EvidenceEvent[],
  history: NAKeyHistory,
  fail: PackFail,
): void {
  let policies: BoundaryPolicy[];
  let attestations: MembershipAttestation[];
  let treaties: RecognitionTreaty[];
  let feeds: SovereignRevocationFeed[];
  const agreements = new Map<string, unknown>();
  try {
    const read = <T>(path: string, valid: (v: unknown) => boolean, model?: string): T[] => {
      const items = jsonLines(files.get(path));
      if (!items.every(item => valid(item) && (model === undefined || unknownFields(model, item).length === 0))) {
        throw new Error(`${path}: a record is not in its model's shape`);
      }
      return items as T[];
    };
    policies = read<BoundaryPolicy>(POLICIES_FILE, validPolicyRecord, 'BoundaryPolicy');
    attestations = read<MembershipAttestation>(ATTESTATIONS_FILE, validAttestationRecord);
    treaties = read<RecognitionTreaty>(TREATIES_FILE, validTreaty);
    feeds = read<SovereignRevocationFeed>(FEEDS_FILE, validFeed);
    // v1.6.0: optional; each agreement as received, by its ID.
    for (const raw of files.has(AGREEMENTS_FILE) ? jsonLines(files.get(AGREEMENTS_FILE)) : []) {
      if (isObject(raw)) agreements.set(String(raw['agreement_id']), raw);
    }
  } catch (err) {
    fail(POLICIES_FILE, null, 'cited_trust_invalid', message(err));
    return;
  }
  const named = (reason: string, invalid: string) => (reason === 'invalid_signature' ? invalid : reason);
  const byVersion = new Map<string, BoundaryPolicy>();
  for (const policy of policies) {
    const reason = receivedSignatureReason('BoundaryPolicy', policy, history, policy.issued_at);
    if (reason !== null) fail(POLICIES_FILE, null, named(reason, 'policy_invalid_signature'), `${policy.policy_id} v${policy.version}`);
    byVersion.set(`${policy.policy_id}\u0000${policy.version}`, policy);
  }
  const own = history.sovereign_id;
  const issuerKeys = new Map<string, string[]>();
  for (const treaty of treaties) {
    const reason = receivedSignatureReason('RecognitionTreaty', treaty, history, treaty.issued_at);
    if (reason !== null) {
      fail(TREATIES_FILE, null, named(reason, 'treaty_invalid_signature'), treaty.treaty_id);
      continue;
    }
    issuerKeys.set(treaty.subject_sovereign_id, [...(issuerKeys.get(treaty.subject_sovereign_id) ?? []), ...treaty.subject_public_keys]);
  }
  const byAttestation = new Map<string, MembershipAttestation>();
  for (const attestation of attestations) {
    const reason = attestation.issuer_sovereign_id === own
      ? receivedSignatureReason('MembershipAttestation', attestation, history, attestation.issued_at)
      : receivedBy('MembershipAttestation', attestation, issuerKeys.get(attestation.issuer_sovereign_id) ?? []);
    if (reason !== null) fail(ATTESTATIONS_FILE, null, named(reason, 'attestation_invalid_signature'), attestation.attestation_id);
    byAttestation.set(attestation.attestation_id, attestation);
  }
  for (const feed of feeds) {
    const reason = receivedBy('SovereignRevocationFeed', feed, issuerKeys.get(feed.issuer_sovereign_id) ?? []);
    if (reason !== null) fail(FEEDS_FILE, null, named(reason, 'feed_invalid_signature'), feed.feed_id);
  }

  const fromSequence = entries.length > 0 ? entries[0]!.entry.store_sequence : 0;
  for (const event of [...cited, ...entries]) {
    const kind = event.entry.entry_kind;
    const seq = event.entry.store_sequence;
    const where = seq < fromSequence ? CITED_FILE : ENTRIES_FILE;
    let binding: Pick<PolicyBinding, 'policies' | 'policy_set_digest'> | null | undefined = null;
    if (kind === 'decision') {
      const decision = event.payload['decision'];
      if (!validDecision(decision)) continue;
      const made = decision as unknown as BoundaryDecision;
      binding = made.policy_binding;
      const attestationBinding = made.attestation_binding;
      if (attestationBinding && attestationBinding.attestation_digest) {
        const bound = byAttestation.get(attestationBinding.attestation_id);
        if (bound === undefined) {
          fail(where, seq, 'cited_attestation_missing', attestationBinding.attestation_id);
        } else {
          // As of the decision's own time: its expiry since then says nothing against it.
          const verdict = verifyBoundaryDecision(made, { operatorPublicKeys: history, expectedAttestation: bound, atRecordTime: true });
          if (verdict.reason === 'attestation_binding_mismatch' || verdict.reason === 'attestation_binding_missing') {
            fail(where, seq, 'cited_attestation_mismatch', bound.attestation_id);
          }
        }
      }
    } else if (kind === 'judgement') {
      if (!validJudgement(event.payload)) continue;
      binding = (event.payload as { policy_binding?: PolicyBinding | null }).policy_binding;
    } else if (kind === 'grant') {
      // v1.6.0: the policy versions a grant is bound to, and the attestation it rests on.
      if (!validGrant(event.payload)) continue;
      const grant = event.payload as unknown as CapabilityGrant;
      binding = grant.policy_binding;
      if (grant.basis_kind === 'attestation') {
        const bound = byAttestation.get(grant.basis_id);
        if (bound === undefined) fail(where, seq, 'cited_attestation_missing', grant.basis_id);
        else if (attestationDigest(bound) !== grant.basis_digest) fail(where, seq, 'cited_attestation_mismatch', grant.basis_id);
      } else {
        // v1.6.0 review fixes: an agreement basis too: held, the one the grant names, between the
        // grant's parties, and signed by both with keys the pack vouches for.
        const problem = agreementProblem(grant, agreements.get(grant.basis_id), history, issuerKeys);
        if (problem !== null) {
          fail(problem === 'cited_agreement_missing' ? where : AGREEMENTS_FILE, seq, problem, grant.basis_id);
        }
      }
    }
    if (binding === null || binding === undefined) continue;
    if (policySetDigest(binding.policies) !== binding.policy_set_digest) {
      fail(where, seq, 'cited_policy_mismatch', 'policy_set_digest');
    }
    for (const applied of binding.policies) {
      const heldPolicy = byVersion.get(`${applied.policy_id}\u0000${applied.version}`);
      if (heldPolicy === undefined) fail(where, seq, 'cited_policy_missing', `${applied.policy_id} v${applied.version}`);
      else if (policyDigest(heldPolicy) !== applied.policy_digest) {
        fail(where, seq, 'cited_policy_mismatch', `${applied.policy_id} v${applied.version}`);
      }
    }
  }
}

/**
 * Why the agreement a grant rests on does not hold up in a pack, or null
 * (v1.6.0): `cited_agreement_missing` when the pack does not hold it;
 * `cited_agreement_mismatch` when it is not the one the grant's
 * `basis_digest` names, or its parties are not the grant's (the responder is
 * the requester, the offerer the provider); `agreement_invalid_signature`
 * when its two parties did not sign it, as received, with keys the pack
 * vouches for (the NA's key valid at `agreed_terms.valid_from` for its own
 * sovereign, a treaty's subject keys for another; an agreement the NA offered
 * and accepted itself carries the NA's signature for both).
 */
function agreementProblem(
  grant: CapabilityGrant,
  raw: unknown,
  history: NAKeyHistory,
  treatyKeys: ReadonlyMap<string, string[]>,
): string | null {
  if (raw === undefined) return 'cited_agreement_missing';
  if (!validAgreementRecord(raw)) return 'cited_agreement_mismatch';
  const agreement = raw as unknown as AgreementRecord;
  const digest = createHash('sha256').update(agreementCanonical(agreement), 'utf-8').digest('hex');
  if (digest !== grant.basis_digest || agreement.responder_sovereign_id !== grant.requester_sovereign_id
    || agreement.offerer_sovereign_id !== grant.provider_sovereign_id) {
    return 'cited_agreement_mismatch';
  }
  const own = history.sovereign_id;
  const naKeys = history.keysAt(agreement.agreed_terms.valid_from);
  const keys = (party: string) => (party === own ? naKeys : (treatyKeys.get(party) ?? []).filter(k => !naKeys.includes(k)));
  const pairs: Array<[string[], string[]]> = [[keys(agreement.offerer_sovereign_id), keys(agreement.responder_sovereign_id)]];
  if (agreement.offerer_sovereign_id === own) pairs.push([naKeys, naKeys]);
  for (const [offerer, responder] of pairs) {
    if (offerer.length > 0 && responder.length > 0 && verifyAgreement(agreement, offerer, responder).accepted) return null;
  }
  return 'agreement_invalid_signature';
}

/** An agreement in the shape the reference reads (its parties, terms and signatures). */
const validAgreementRecord = (v: unknown): boolean => isObject(v) && typeof v['agreement_id'] === 'string'
  && typeof v['offerer_sovereign_id'] === 'string' && typeof v['responder_sovereign_id'] === 'string'
  && isObject(v['agreed_terms']) && timestamp(v['agreed_terms']['valid_from']) && Array.isArray(v['signatures']);

// ── The report ────────────────────────────────────────────────────────────────

/**
 * One value of the report, on one line: a backslash is written `\\`, a `|`
 * `\|`; a line feed, carriage return or tab `\n`, `\r`, `\t`; any other
 * control character (U+0000 to U+001F, U+007F to U+009F) and U+2028, U+2029
 * `\uXXXX` (upper-case hex). A string is written as itself, an integer in
 * decimal, a boolean `true` or `false`, an absent value empty, anything else
 * as canonical JSON (non-ASCII kept).
 */
export function reportCell(value: unknown): string {
  let raw: string;
  if (value === null || value === undefined) raw = '';
  else if (typeof value === 'boolean') raw = value ? 'true' : 'false';
  else if (typeof value === 'string') raw = value;
  else if (typeof value === 'bigint' || (typeof value === 'number' && Number.isInteger(value))) raw = String(value);
  else raw = canonicalJsonUnescaped(value);
  let out = '';
  for (const ch of raw) {
    const code = ch.codePointAt(0)!;
    if (ch === '\\') out += '\\\\';
    else if (ch === '|') out += '\\|';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029) {
      out += `\\u${code.toString(16).toUpperCase().padStart(4, '0')}`;
    } else out += ch;
  }
  return out;
}

function table(headers: readonly string[], rows: readonly (readonly unknown[])[]): string[] {
  if (rows.length === 0) return ['None.', ''];
  return [
    `| ${headers.join(' | ')} |`, `|${headers.map(() => '---').join('|')}|`,
    ...rows.map(row => `| ${row.map(reportCell).join(' | ')} |`), '',
  ];
}

/** The reference's `str()` of a value read from a record (`None` when absent). */
function pyStr(value: unknown): string {
  if (value === null || value === undefined) return 'None';
  if (typeof value === 'boolean') return value ? 'True' : 'False';
  return String(value);
}

/** Python truthiness of a value read from JSON. */
function truthy(value: unknown): boolean {
  if (value === null || value === undefined || value === false || value === 0 || value === '') return false;
  if (Array.isArray(value)) return value.length > 0;
  if (isObject(value)) return Object.keys(value).length > 0;
  return true;
}

/** `a or b` as the reference evaluates it. */
function or(...values: unknown[]): unknown {
  for (const value of values.slice(0, -1)) if (truthy(value)) return value;
  return values[values.length - 1];
}

/** What `renderReport` reads of a manifest. */
export interface ReportHeader {
  pack_id: string;
  sovereign_id: string;
  from_sequence: number;
  through_sequence: number;
  start_anchor_sequence: number | null;
  end_anchor_sequence: number;
  created_at: string;
  requested_by: string | null;
  period_from: string | null;
  period_until: string | null;
}

export function reportHeader(manifest: AuditPackManifest): ReportHeader {
  return {
    pack_id: manifest.pack_id, sovereign_id: manifest.sovereign_id, from_sequence: manifest.from_sequence,
    through_sequence: manifest.through_sequence, start_anchor_sequence: manifest.start_anchor_sequence ?? null,
    end_anchor_sequence: manifest.end_anchor_sequence, created_at: iso(manifest.created_at),
    requested_by: manifest.requested_by ?? null,
    period_from: manifest.period_from ? iso(manifest.period_from) : null,
    period_until: manifest.period_until ? iso(manifest.period_until) : null,
  };
}

/**
 * `report.md`, byte for byte as the reference renders it from the manifest,
 * the entries, `checks.json` and `states.json` (its `states` and `notices`).
 */
export function renderReport(input: {
  manifest: ReportHeader;
  entries: readonly EvidenceEvent[];
  checks: Record<string, unknown>;
  states?: Record<string, unknown>;
  notices?: Record<string, unknown>;
}): string {
  const { manifest, entries, checks } = input;
  const states = input.states ?? {};
  const notices = input.notices ?? {};
  const judgements = new Map<string, Record<string, unknown>>();
  for (const e of entries) {
    if (e.entry.entry_kind === 'judgement') {
      judgements.set(`${pyStr(e.payload['subject_kind'])}\u0000${pyStr(e.payload['subject_id'])}`, e.payload);
    }
  }
  let period = '';
  if (manifest.period_from || manifest.period_until) {
    period = `- Asked for: ${reportCell(manifest.period_from || 'the start')} to ${reportCell(manifest.period_until || 'the last anchor')}`;
  }
  const lines = [
    `# Audit pack ${reportCell(manifest.pack_id)}`, '',
    `- Sovereign: ${reportCell(manifest.sovereign_id)}`,
    `- Range: store entries ${reportCell(manifest.from_sequence)} to ${reportCell(manifest.through_sequence)}, `
      + `ending at anchor ${reportCell(manifest.end_anchor_sequence)}`
      + (manifest.start_anchor_sequence ? `, starting after anchor ${reportCell(manifest.start_anchor_sequence)}` : ''),
    `- Created: ${reportCell(manifest.created_at)}` + (manifest.requested_by ? ` for ${reportCell(manifest.requested_by)}` : ''),
    ...(period ? [period] : []),
    '',
    'Verify it with `genesis-mesh audit verify <dir> --anchor <root public key> --known-anchors <anchors>`, '
      + 'from the root key and the anchors you hold. The remediation states and notices below are the '
      + "Network Authority's operational records at pack time (states.json), not signed records.", '',
    '## Checks', '',
    `Verified by the Network Authority when it wrote the pack, against its own anchors: **${truthy(checks['verified']) ? 'yes' : 'no'}**.`, '',
  ];
  const failures = Array.isArray(checks['failures']) ? checks['failures'].filter(isObject) : [];
  lines.push(...table(['Reason', 'File', 'Entry', 'Detail'], failures.map(f => [f['reason'], f['file'], f['store_sequence'], f['detail']])));
  const counts = isObject(checks['counts']) && truthy(checks['counts']) ? checks['counts'] : {};
  lines.push('## Totals', '');
  lines.push(...table(['Records', 'Count'],
    Object.keys(counts).sort(compareCodePoints).filter(k => truthy(counts[k])).map(k => [k, counts[k]])));

  const changes: unknown[][] = [];
  const denials: unknown[][] = [];
  const remediations: unknown[][] = [];
  const reviews: unknown[][] = [];
  const breakGlass: unknown[][] = [];
  const quarantined: unknown[][] = [];
  const others: unknown[][] = [];
  const grants: unknown[][] = [];
  const grantRevocations: unknown[][] = [];
  const stateOf = (subject: unknown): unknown => {
    const key = pyStr(subject);
    const value = Object.hasOwn(states, key) ? states[key] : undefined;
    return isObject(value) ? value['state'] : undefined;
  };
  for (const e of entries) {
    const p = e.payload;
    const kind = e.entry.entry_kind;
    const seq = e.entry.store_sequence;
    if (kind === 'execution') {
      changes.push([seq, kind, p['resource_id'], p['resource_action'], p['executed_at'], 'prior_decision',
        or(stateOf(p['decision_id']), 'recorded'), p['executor_sovereign_id']]);
    } else if (kind === 'grant_execution') {
      // v1.6.0: a change made under a grant, governed by it.
      changes.push([seq, kind, p['resource_id'], p['resource_action'], p['executed_at'], 'grant', 'recorded',
        p['executor_sovereign_id']]);
    } else if (kind === 'grant') {
      grants.push([seq, p['grant_id'], p['bearer_sovereign_id'], p['capabilities'], p['valid_from'], p['valid_until'],
        p['max_uses']]);
    } else if (kind === 'grant_revocation') {
      grantRevocations.push([seq, p['grant_id'], p['reason'], p['revoked_at']]);
    } else if (kind === 'observation' || kind === 'break_glass') {
      const recordId = pyStr(or(p['observation_id'], p['break_glass_id']));
      const judgement = judgements.get(`${kind}\u0000${recordId}`);
      let state = judgement ? stateOf(judgement['judgement_id']) : undefined;
      if (state === undefined || state === null) {
        state = judgement === undefined ? 'observed'
          : (judgement['governed_by'] === 'prior_decision' || judgement['governed_by'] === 'grant')
            && judgement['verdict'] !== 'deny' ? 'matched'
            : ({ allow: 'judged_allowed', deny: 'judged_denied' } as Record<string, string>)[pyStr(judgement['verdict'])]
              ?? 'indeterminate';
      }
      changes.push([seq, kind, p['resource_id'], or(p['action'], p['resource_action']),
        or(p['changed_at'], p['changed_not_after'], p['executed_at']), judgement ? judgement['governed_by'] : null, state, p['actor']]);
      if (kind === 'break_glass') {
        breakGlass.push([seq, p['resource_id'], p['capability'], p['executed_at'], p['evaluation_failure'], p['justification']]);
      }
    } else if (kind === 'decision') {
      const decision = (truthy(p['decision']) ? p['decision'] : {}) as Record<string, unknown>;
      if (decision['authorized'] === false) denials.push([seq, 'decision', decision['decision_id'], decision['denial_reason']]);
    } else if (kind === 'judgement' && (p['verdict'] === 'deny' || p['verdict'] === 'indeterminate')) {
      const reason = or(p['reason'], '');
      denials.push([seq, 'judgement', p['judgement_id'], `${pyStr(p['verdict'])}: ${typeof reason === 'string' ? reason : pyStr(reason)}`]);
    } else if (kind === 'remediation') {
      remediations.push([seq, p['subject_kind'], p['subject_id'], p['outcome'], p['steps'], p['remediated_at'], p['executor_sovereign_id']]);
    } else if (kind === 'review') {
      reviews.push([seq, p['subject_id'], p['verdict'], p['requested_by'], p['requester_holder'], p['decided_by'],
        p['decider_holder'], p['decided_at']]);
    } else if (kind === 'quarantine') {
      quarantined.push([seq, p['record_kind'], p['resource_id'], p['rejection_code'], p['quarantined_at']]);
    } else if (kind === 'key_succession' || kind === 'archive') {
      others.push([seq, kind, or(p['succession_id'], p['archive_id']), or(p['effective_at'], p['archived_at'])]);
    }
  }
  const noticeRows = Object.keys(notices).sort(compareCodePoints).filter(k => isObject(notices[k])).map(k => {
    const v = notices[k] as Record<string, unknown>;
    return [k, v['notified_at'], v['notified_by']];
  });
  const sections: Array<[string, string[], unknown[][]]> = [
    ['Changes', ['Entry', 'Kind', 'Resource', 'Action', 'Changed at', 'Governed by', 'State', 'Actor'], changes],
    ['Denials', ['Entry', 'Record', 'ID', 'Reason'], denials],
    ['Remediations', ['Entry', 'Subject kind', 'Subject', 'Outcome', 'Steps', 'At', 'Executor'], remediations],
    ['Reviews and deciders', ['Entry', 'Subject', 'Verdict', 'Requested by', 'Requester holder', 'Decided by',
      'Decider holder', 'Decided at'], reviews],
    ['Notices', ['Subject', 'Notified at', 'By'], noticeRows],
    ['Break-glass uses', ['Entry', 'Resource', 'Capability', 'Executed at', 'Failure', 'Justification'], breakGlass],
    ['Quarantined records', ['Entry', 'Record kind', 'Resource', 'Rejection', 'At'], quarantined],
    ['Key successions and archives', ['Entry', 'Kind', 'ID', 'At'], others],
  ];
  // v1.6.0: grants and their revocations, only in a pack that holds them (a pack without them renders as in 1.5).
  if (grants.length > 0) {
    sections.push(['Grants', ['Entry', 'Grant', 'Bearer', 'Capabilities', 'Valid from', 'Valid until', 'Budget'], grants]);
  }
  if (grantRevocations.length > 0) sections.push(['Grant revocations', ['Entry', 'Grant', 'Reason', 'Revoked at'], grantRevocations]);
  for (const [title, headers, rows] of sections) lines.push(`## ${title}`, '', ...table(headers, rows));
  const text = lines.join('\n');
  let end = text.length;
  while (end > 0 && text.charCodeAt(end - 1) === 10) end -= 1; // trailing line feeds, without a regex
  return text.slice(0, end) + '\n';
}

// ── The completeness check ───────────────────────────────────────────────────

/** One change from a log outside Genesis Mesh (a cloud audit log, a ticketing export). */
export interface Change {
  /** Its position in the log, from 1. */
  index: number;
  resource_id: string;
  action: string;
  /** RFC 3339 with an offset (`parseChanges` writes it in UTC). */
  changed_at: string;
  source?: string | null;
  source_event_id?: string | null;
  actor?: string | null;
}

/** The columns of a CSV changes file. */
export const CHANGE_COLUMNS = ['source', 'source_event_id', 'resource_id', 'action', 'changed_at', 'actor'] as const;

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?([Zz]|[+-](\d{2}):(\d{2}))$/;

/**
 * An RFC 3339 `date-time` in UTC (`...Z`, six fraction digits when not
 * zero), or throws: a date without a time, a space for `T`, a missing offset,
 * a leap second or an out-of-range field is refused. Fractions beyond
 * microseconds are cut, not rounded.
 */
export function parseRfc3339(value: string): string {
  const m = RFC3339.exec(value);
  if (!m) throw new Error('not an RFC 3339 date-time');
  const [, y, mo, d, h, mi, s, fraction, zone, zh, zm] = m;
  const year = Number(y), month = Number(mo), day = Number(d);
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (year < 1 || days === undefined || day < 1 || day > days || Number(h) > 23 || Number(mi) > 59 || Number(s) > 59) {
    throw new Error('not an RFC 3339 date-time');
  }
  let offsetMinutes = 0;
  if (zone !== 'Z' && zone !== 'z') {
    if (Number(zh) > 23 || Number(zm) > 59) throw new Error('not an RFC 3339 date-time');
    offsetMinutes = (Number(zh) * 60 + Number(zm)) * (zone!.startsWith('+') ? 1 : -1);
  }
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(Number(h), Number(mi), Number(s), 0);
  const micro = Number((fraction ?? '.0').slice(1, 7).padEnd(6, '0'));
  return isoMicros((date.getTime() - offsetMinutes * 60_000) * 1000 + micro);
}

/** RFC 4180 rows of a CSV text (the reference reads it with Python's `csv`); empty lines are skipped. */
function csvRows(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let touched = false;
  const endRow = () => {
    if (touched || row.length > 0) row.push(field);
    if (row.length > 0) rows.push(row);
    row = [];
    field = '';
    touched = false;
  };
  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    if (quoted) {
      if (ch === '"' && input[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') {
      quoted = true;
      touched = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
      touched = true;
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && input[i + 1] === '\n') i++;
      endRow();
    } else {
      field += ch;
      touched = true;
    }
  }
  endRow();
  return rows;
}

/**
 * Changes from CSV (`csv: true`; a header row naming `CHANGE_COLUMNS`) or
 * JSON (a list, or `{"changes": [...]}`; each field a string or null).
 * `resource_id`, `action` and `changed_at` (RFC 3339 with an offset) are
 * required; `source` and `source_event_id` go together; an empty string is
 * absent. Throws naming the first bad row.
 */
export function parseChanges(input: string | unknown, options: { csv?: boolean } = {}): Change[] {
  let rows: unknown[];
  if (options.csv) {
    if (typeof input !== 'string') throw new Error('a CSV changes file is text');
    const [header, ...records] = csvRows(input);
    rows = header === undefined ? [] : records.map(record => {
      const row: Record<string, unknown> = {};
      header.forEach((name, i) => defineMember(row, name, i < record.length ? record[i] : null));
      return row;
    });
  } else {
    const data = typeof input === 'string' ? parseJson(input) : input;
    const listed = isObject(data) ? data['changes'] : data;
    if (!Array.isArray(listed)) throw new Error('a JSON changes file is a list of changes or {"changes": [...]}');
    rows = listed;
  }
  return rows.map((row, i) => {
    const index = i + 1;
    if (!isObject(row)) throw new Error(`change ${index} is not an object`);
    const value = (name: string): string | null => {
      const raw = Object.hasOwn(row, name) ? row[name] : null;
      if (raw === null || raw === undefined) return null;
      if (typeof raw !== 'string') throw new Error(`change ${index}: ${name} must be a string`);
      return raw.trim() || null;
    };
    const resource = value('resource_id');
    const action = value('action');
    const changed = value('changed_at');
    if (!resource || !action || !changed) throw new Error(`change ${index}: resource_id, action and changed_at are required`);
    let at: string;
    try {
      at = parseRfc3339(changed);
    } catch {
      throw new Error(`change ${index}: changed_at is not an RFC 3339 time with an offset (Z for UTC)`);
    }
    const source = value('source');
    const eventId = value('source_event_id');
    if ((source === null) !== (eventId === null)) throw new Error(`change ${index}: source and source_event_id go together`);
    return { index, source, source_event_id: eventId, resource_id: resource, action, changed_at: at, actor: value('actor') };
  });
}

export interface CompletenessPair {
  change: number;
  kind: string;
  record_id: string;
  store_sequence: number;
  matched_by: 'source_event_id' | 'resource_action_time';
}

export interface CompletenessReport {
  changes: number;
  tolerance_seconds: number;
  period: { from: string; to: string };
  pairs: CompletenessPair[];
  /** Changes dated inside the period that no record matches: the store does not record them. */
  unmatched_changes: Change[];
  /** Unmatched changes dated outside the period: not missing from it. */
  outside_period: Change[];
  /** Changes repeating a (source, source event ID) pair already seen: set aside. */
  duplicate_changes: Change[];
  /** Records no change matched (the log may not cover every source). */
  unmatched_records: Array<{ kind: string; record_id: string; store_sequence: number; resource_id: string; action: string }>;
  complete: boolean;
}

export interface CompletenessOptions {
  /** The period the records cover: [from, to], ISO 8601. */
  period: readonly [string, string];
  /** Default 300 seconds. */
  toleranceSeconds?: number;
}

interface ChangeRecord {
  kind: string;
  record_id: string;
  store_sequence: number;
  resource_id: string;
  action: string;
  earliest: number;
  latest: number;
  source: string | null;
  source_event_id: string | null;
  group: string;
}

interface Group {
  group: string;
  members: ChangeRecord[];
  /** The execution evidence, grant use or break-glass record when the group holds one, else its observation. */
  representative: ChangeRecord;
}

function distance(record: ChangeRecord, when: number): number {
  if (record.earliest <= when && when <= record.latest) return 0;
  return Math.min(Math.abs(when - record.earliest), Math.abs(when - record.latest));
}

function changeRecords(entries: readonly EvidenceEvent[], cited: readonly EvidenceEvent[]): ChangeRecord[] {
  const records: ChangeRecord[] = [];
  const matched = new Map<string, string>();
  for (const event of [...cited, ...entries]) {
    const p = event.payload;
    if (event.entry.entry_kind === 'judgement' && truthy(p['matched_evidence_id'])) {
      matched.set(pyStr(p['subject_id']), pyStr(p['matched_evidence_id']));
    }
  }
  const str = (v: unknown) => (typeof v === 'string' ? v : null);
  const time = (v: unknown) => {
    const when = typeof v === 'string' ? timestampMicros(v) : NaN;
    if (Number.isNaN(when)) throw new Error('not a time');
    return when;
  };
  for (const event of entries) {
    const p = event.payload;
    const kind = event.entry.entry_kind;
    const seq = event.entry.store_sequence;
    const add = (id: unknown, resource: unknown, action: unknown, earliest: number, latest: number,
      source: string | null = null, sourceEventId: string | null = null) => {
      if (typeof id !== 'string' || typeof resource !== 'string' || typeof action !== 'string') return;
      records.push({ kind, record_id: id, store_sequence: seq, resource_id: resource, action, earliest, latest,
        source, source_event_id: sourceEventId, group: '' });
    };
    try {
      if (kind === 'observation') {
        add(p['observation_id'], p['resource_id'], p['action'], time(or(p['changed_at'], p['changed_not_before'])),
          time(or(p['changed_at'], p['changed_not_after'])), str(p['source']), str(p['source_event_id']));
      } else if (kind === 'break_glass') {
        const when = time(p['executed_at']);
        add(p['break_glass_id'], p['resource_id'], p['resource_action'], when, when);
      } else if (kind === 'execution' && truthy(p['resource_id'])) {
        const when = time(p['executed_at']);
        add(p['evidence_id'], p['resource_id'], p['resource_action'], when, when);
      } else if (kind === 'grant_execution' && truthy(p['resource_id'])) {
        // v1.6.0: a change made under a grant.
        const when = time(p['executed_at']);
        add(p['use_id'], p['resource_id'], p['resource_action'], when, when);
      }
    } catch {
      continue;
    }
  }
  // A governed change seen by an observer is one change: the observation and what it matched.
  for (const record of records) record.group = matched.get(record.record_id) ?? record.record_id;
  return records;
}

/**
 * The matching of one (resource, action): the most pairs, then the least total
 * distance. Changes in time order (then by index) are matched to groups in
 * time order (their representative's earliest time, then store position)
 * without crossing; at each step the choices are, in this order, pairing,
 * leaving the change, leaving the group, and the first best is taken, so every
 * verifier finds the same pairs.
 */
function matchBucket(changes: readonly Change[], groups: readonly Group[], tolerance: number): Array<[Change, Group]> {
  const cs = [...changes].sort((a, b) => timestampMicros(a.changed_at) - timestampMicros(b.changed_at) || a.index - b.index);
  const gs = [...groups].sort((a, b) => a.representative.earliest - b.representative.earliest
    || a.representative.store_sequence - b.representative.store_sequence);
  const n = cs.length;
  const m = gs.length;
  const best: Array<Array<[number, number]>> = Array.from({ length: n + 1 }, () => Array.from({ length: m + 1 }, () => [0, 0]));
  const choice: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  const better = (a: [number, number], b: [number, number]) => a[0] > b[0] || (a[0] === b[0] && a[1] > b[1]);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      const options: Array<[[number, number], number]> = [];
      const d = distance(gs[j]!.representative, timestampMicros(cs[i]!.changed_at));
      if (d <= tolerance) {
        const [pairs, cost] = best[i + 1]![j + 1]!;
        options.push([[pairs + 1, cost - d], 0]);
      }
      options.push([best[i + 1]![j]!, 1], [best[i]![j + 1]!, 2]);
      let top = options[0]!;
      for (const option of options.slice(1)) if (better(option[0], top[0])) top = option;
      best[i]![j] = top[0];
      choice[i]![j] = top[1];
    }
  }
  const out: Array<[Change, Group]> = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (choice[i]![j] === 0) {
      out.push([cs[i]!, gs[j]!]);
      i++;
      j++;
    } else if (choice[i]![j] === 1) i++;
    else j++;
  }
  return out;
}

/** A change as the reference reports it: its time in UTC. */
function reported(change: Change): Change {
  return {
    index: change.index, source: change.source ?? null, source_event_id: change.source_event_id ?? null,
    resource_id: change.resource_id, action: change.action, changed_at: iso(change.changed_at), actor: change.actor ?? null,
  };
}

/**
 * Match changes from an outside log against a pack's records: changes
 * repeating a (source, source event ID) pair are set aside
 * (`duplicate_changes`); a change with a source event ID matches the record
 * naming that very event when it agrees on resource and action; the rest are
 * matched per (resource, action) for the most pairs, then the least total
 * distance within the tolerance (an observation and the execution evidence it
 * was matched to are one change, represented by the execution evidence). An
 * unmatched change dated inside the period (with the tolerance either side)
 * is in `unmatched_changes`; one outside it in `outside_period`.
 */
export function checkCompleteness(
  changes: readonly Change[],
  entries: readonly EvidenceEvent[],
  cited: readonly EvidenceEvent[],
  options: CompletenessOptions,
): CompletenessReport {
  const tolerance = (options.toleranceSeconds ?? 300) * 1_000_000;
  const records = changeRecords(entries, cited);
  const groups = new Map<string, Group>();
  for (const record of records) {
    const group = groups.get(record.group);
    if (group === undefined) groups.set(record.group, { group: record.group, members: [record], representative: record });
    else group.members.push(record);
  }
  for (const group of groups.values()) {
    group.representative = group.members.reduce((best, r) => {
      const rank = (x: ChangeRecord) => [x.kind === 'observation' ? 1 : 0, x.store_sequence] as const;
      const [a, b] = [rank(r), rank(best)];
      return a[0] < b[0] || (a[0] === b[0] && a[1] < b[1]) ? r : best;
    });
  }
  const used = new Set<string>();
  const pairs: CompletenessPair[] = [];
  const seen = new Set<string>();
  const duplicates: Change[] = [];
  const unique: Change[] = [];
  for (const change of changes) {
    if (change.source != null && change.source_event_id != null) {
      const key = `${change.source}\u0000${change.source_event_id}`;
      if (seen.has(key)) {
        duplicates.push(change);
        continue;
      }
      seen.add(key);
    }
    unique.push(change);
  }
  const byEvent = new Map<string, ChangeRecord>();
  for (const r of records) {
    const key = `${r.source}\u0000${r.source_event_id}`;
    if (r.source !== null && r.source_event_id !== null && !byEvent.has(key)) byEvent.set(key, r);
  }
  const left: Change[] = [];
  for (const change of unique) {
    const named = change.source != null && change.source_event_id != null
      ? byEvent.get(`${change.source}\u0000${change.source_event_id}`) : undefined;
    if (named !== undefined && !used.has(named.group) && named.resource_id === change.resource_id && named.action === change.action) {
      used.add(named.group);
      pairs.push({ change: change.index, kind: named.kind, record_id: named.record_id, store_sequence: named.store_sequence,
        matched_by: 'source_event_id' });
    } else {
      left.push(change);
    }
  }
  const buckets = new Map<string, { changes: Change[]; groups: Group[] }>();
  for (const change of left) {
    const key = `${change.resource_id}\u0000${change.action}`;
    const bucket = buckets.get(key) ?? { changes: [], groups: [] };
    bucket.changes.push(change);
    buckets.set(key, bucket);
  }
  for (const group of groups.values()) {
    if (used.has(group.group)) continue;
    buckets.get(`${group.representative.resource_id}\u0000${group.representative.action}`)?.groups.push(group);
  }
  const matchedChanges = new Set<number>();
  for (const key of [...buckets.keys()].sort(compareCodePoints)) {
    const bucket = buckets.get(key)!;
    for (const [change, group] of matchBucket(bucket.changes, bucket.groups, tolerance)) {
      used.add(group.group);
      matchedChanges.add(change.index);
      const rep = group.representative;
      pairs.push({ change: change.index, kind: rep.kind, record_id: rep.record_id, store_sequence: rep.store_sequence,
        matched_by: 'resource_action_time' });
    }
  }
  const unmatched = left.filter(c => !matchedChanges.has(c.index));
  const [from, to] = options.period;
  const start = timestampMicros(from);
  const end = timestampMicros(to);
  const inside = unmatched.filter(c => {
    const when = timestampMicros(c.changed_at);
    return start - tolerance <= when && when <= end + tolerance;
  });
  const outside = unmatched.filter(c => !inside.includes(c));
  const byIndex = (a: Change, b: Change) => a.index - b.index;
  const unmatchedRecords = [...groups.values()].filter(g => !used.has(g.group)).map(g => g.representative)
    .sort((a, b) => a.store_sequence - b.store_sequence);
  return {
    changes: changes.length,
    tolerance_seconds: Math.trunc(tolerance / 1_000_000),
    period: { from: iso(from), to: iso(to) },
    pairs: pairs.sort((a, b) => a.change - b.change),
    unmatched_changes: inside.sort(byIndex).map(reported),
    outside_period: outside.sort(byIndex).map(reported),
    duplicate_changes: duplicates.map(reported),
    unmatched_records: unmatchedRecords.map(r => ({
      kind: r.kind, record_id: r.record_id, store_sequence: r.store_sequence, resource_id: r.resource_id, action: r.action,
    })),
    complete: inside.length === 0,
  };
}
