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
import { entryDigest, policyDigest, policySetDigest, revocationFeedCanonical } from './canonical.js';
import { naSignatureAt, verifyKeyHistory, type NAKey, type NAKeyHistory, type NAKeys } from './key-history.js';
import { outOfBandCanonical } from './out-of-band.js';
import { nonCanonicalFields, unknownFields } from './strict.js';
import type {
  AnchorSummary, BoundaryDecision, BoundaryPolicy, EvidenceEvent, EvidenceStoreVerification, MembershipAttestation,
  PolicyBinding, RetentionCheckpoint, Signature, SovereignRevocationFeed,
} from './types.js';
import {
  isObject, timestampMicros, validAnchor, validArchive, validAttestationRecord, validDecision, validFeed, validJudgement,
  validManifest, validPolicyRecord, validRegistry, validTreaty,
} from './validation.js';
import {
  parseExportLines, verifyAttestationSignature, verifyBoundaryDecision, verifyEvidenceEvents,
  verifyPolicySignature, verifyTreatySignature, type ExecutorKeyInfo, type RecognitionTreaty,
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

/** Every file of a pack (format version 1) but the manifest, which lists them. */
export const PACK_FILES: readonly string[] = [
  ANCHORS_FILE, CHECKS_FILE, CITED_FILE, ENTRIES_FILE, EXECUTOR_KEYS_FILE, GENESIS_FILE, KEY_HISTORY_FILE,
  POLICIES_FILE, REPORT_FILE, ATTESTATIONS_FILE, FEEDS_FILE, TREATIES_FILE,
];

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

export interface PackVerification {
  verified: boolean;
  failures: PackFinding[];
  /** `no_held_anchors` and other findings that do not fail the pack. */
  warnings: PackFinding[];
  /** The counts of the entries' verification. */
  counts: Record<string, number>;
  /** The range the entries hold. */
  range: { from_sequence: number; through_sequence: number; entries: number; first_recorded_at: string; last_recorded_at: string } | null;
  /** How the entries tie to the anchors held; null without them. */
  anchors: AnchorSummary | null;
  /** The NA's keys, as the key history verified from the root key gives them. */
  keys: NAKey[];
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
  /** Executor and observer keys supplied out of band, for a store without registry records. */
  executorKeys?: Record<string, ExecutorKeyInfo> | readonly ExecutorKeyInfo[];
  /** Changes from a log outside Genesis Mesh: runs the completeness check (`change_unmatched`). */
  changes?: readonly Change[] | null;
  /** The completeness check's time tolerance (default 300 seconds). */
  toleranceSeconds?: number;
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

/** Two anchors are the same when their wire forms are (timestamps compared as instants). */
function sameAnchor(a: StoreAnchor, b: StoreAnchor): boolean {
  const wire = (x: StoreAnchor) => canonicalJsonUnescaped({ ...withoutNulls(x), anchored_at: timestampMicros(x.anchored_at) });
  return wire(a) === wire(b);
}

function normalizeFiles(files: Record<string, Uint8Array | string>): Map<string, Uint8Array> {
  return new Map(Object.entries(files).map(([path, body]) => [path, typeof body === 'string' ? Buffer.from(body, 'utf-8') : body]));
}

function checkManifest(files: ReadonlyMap<string, Uint8Array>, fail: PackFail): Record<string, unknown> | null {
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
    const body = files.get(path);
    const item = listed.get(path)!;
    if (body === undefined) fail(path, null, 'manifest_file_missing');
    else if (!digestMatches(body, item)) fail(path, null, 'manifest_digest_mismatch');
  }
  for (const path of [...files.keys()].sort(compareCodePoints)) {
    if (path !== MANIFEST_FILE && !listed.has(path)) fail(path, null, 'manifest_unlisted_file');
  }
  return manifest as unknown as Record<string, unknown>;
}

function digestMatches(body: Uint8Array, item: PackFile): boolean {
  return createHash('sha256').update(body).digest('hex') === item.sha256 && body.length === item.bytes;
}

type PackFail = (file: string | null, storeSequence: number | null, reason: string, detail?: string) => void;

/** The signed form of a manifest as the reference reads it (its format filled when absent). */
function manifestSigned(manifest: Record<string, unknown>, keys: readonly string[]): boolean {
  const sig = manifest['signature'] as Signature | null | undefined;
  const model = { format: PACK_FORMAT, format_version: PACK_FORMAT_VERSION, ...manifest };
  copyPythonFloats(manifest, model);
  return typeof sig?.sig === 'string' && verifyCanonical(outOfBandCanonical(model), sig.sig, keys);
}

/** Executor and observer keys from the registry records the NA signed (by the key valid then). */
function registryKeys(all: readonly EvidenceEvent[], history: NAKeyHistory): Record<string, ExecutorKeyInfo> {
  const keys: Record<string, ExecutorKeyInfo> = {};
  for (const event of [...all].sort((a, b) => a.entry.store_sequence - b.entry.store_sequence)) {
    if (event.entry.entry_kind !== 'registry') continue;
    const record = event.payload;
    if (!validRegistry(record) || unknownFields('RegistryRecord', record).length > 0) continue;
    const sig = record['signature'] as Signature | null | undefined;
    const signed = naSignatureAt(k => typeof sig?.sig === 'string' && verifyCanonical(outOfBandCanonical(record), sig.sig, k),
      history, event.entry.recorded_at);
    if (signed !== 'ok') continue;
    const r = record as Record<string, string | undefined>;
    if (r['event'] === 'executor_key_registered' && r['key_id'] && r['public_key'] && r['executor_sovereign_id']) {
      defineMember(keys as Record<string, unknown>, r['key_id'], {
        key_id: r['key_id'], public_key: r['public_key'], executor_sovereign_id: r['executor_sovereign_id'],
        role: (r['key_role'] as ExecutorKeyInfo['role']) || 'executor', resource_prefix: r['resource_prefix'] ?? null,
      });
    }
  }
  return keys;
}

/**
 * Verify an audit pack offline, in the reference's order, each failure named
 * by a reason code:
 *
 * 1. the manifest (`manifest_missing`, `manifest_invalid`,
 *    `manifest_file_missing`, `manifest_digest_mismatch`,
 *    `manifest_unlisted_file`, `manifest_invalid_signature`): a pack whose
 *    manifest fails is not checked further;
 * 2. the key history, from the root key down (`genesis_*`, `succession_*`,
 *    `key_history_invalid`);
 * 3. the anchors (the anchor reasons, `pack_end_anchor_mismatch`,
 *    `pack_end_anchor_not_held`, `pack_start_not_tied`,
 *    `pack_start_anchor_not_held`, `anchor_mismatch`, `anchor_entry_missing`,
 *    `export_not_linked_to_anchors`; without held anchors the warning
 *    `no_held_anchors`);
 * 4. the entries (`entries_invalid`, `pack_range_mismatch`,
 *    `cited_out_of_range`, then every export reason, among them
 *    `na_key_not_valid_at_time`, `succession_not_in_history` and
 *    `cited_record_missing`);
 * 5. what the records rest on (`cited_trust_invalid`,
 *    `policy_invalid_signature`, `treaty_invalid_signature`,
 *    `attestation_invalid_signature`, `feed_invalid_signature`,
 *    `cited_policy_missing`, `cited_policy_mismatch`,
 *    `cited_attestation_missing`, `cited_attestation_mismatch`);
 * 6. with `changes`, completeness (`change_unmatched`).
 *
 * Decisions are judged as of their own time: one that expired since it was
 * made and used is not a failure.
 */
export function verifyAuditPack(
  files: Record<string, Uint8Array | string>,
  options: VerifyAuditPackOptions,
): PackVerification {
  const result: PackVerification = {
    verified: true, failures: [], warnings: [], counts: {}, range: null, anchors: null, keys: [], completeness: null,
  };
  const fail: PackFail = (file, storeSequence, reason, detail = '') => {
    result.verified = false;
    result.failures.push({ file, store_sequence: storeSequence, reason, detail });
  };
  const warn: PackFail = (file, storeSequence, reason, detail = '') => {
    result.warnings.push({ file, store_sequence: storeSequence, reason, detail });
  };
  const pack = normalizeFiles(files);
  const manifest = checkManifest(pack, fail) as unknown as AuditPackManifest | null;

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
    const signed = naSignatureAt(keys => manifestSigned(manifest as unknown as Record<string, unknown>, keys), history,
      manifest.created_at);
    if (signed !== 'ok') fail(MANIFEST_FILE, null, signed === 'invalid_signature' ? 'manifest_invalid_signature' : signed);
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
  const startAnchor = startSequence ? bySequence.get(startSequence) : undefined;
  if (startSequence && (startAnchor === undefined || startAnchor.store_sequence !== first - 1
    || startAnchor.entry_digest !== head.entry.prev_entry_digest)) {
    fail(ANCHORS_FILE, first, 'pack_start_not_tied', 'the start anchor does not name the entry before the range');
  }

  // The start checkpoint: a retention checkpoint (in the range or cited) that removed the entries before it.
  const startCheckpoint: RetentionCheckpoint | null = startingCheckpointOf([...entries, ...cited], head);
  if (first === 1 && head.entry.prev_entry_digest !== null) {
    fail(ENTRIES_FILE, 1, 'store_chain_break', 'entry 1 names a previous entry');
  }

  if (options.heldAnchors === null) {
    warn(null, null, 'no_held_anchors',
      'verified without anchors held out of band: the pack\'s integrity, not that nothing was removed');
  } else {
    const held = [...options.heldAnchors];
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
    if (startAnchor !== undefined && !heldBySequence.has(startAnchor.anchor_sequence) && startCheckpoint === null
      && first !== 1) {
      fail(ANCHORS_FILE, first, 'pack_start_anchor_not_held',
        `anchor ${startAnchor.anchor_sequence} is not among the anchors held`);
    }
    const inside = held.filter(a => a.store_sequence <= last);
    const tied: EvidenceStoreVerification = { verified: true, checked_entries: 0, decisions: 0, executions: 0, failures: [] };
    checkEventsAgainstAnchors(entries, inside, tied, { fromAnchor: true });
    for (const failure of tied.failures) fail(ENTRIES_FILE, failure.store_sequence, failure.reason, failure.detail);
    result.anchors = tied.anchors ?? null;
  }

  // 4. Executor keys: from registry records the NA signed, and keys supplied out of band.
  const supplied = options.executorKeys ?? {};
  const keys = {
    ...registryKeys([...cited, ...entries], history),
    ...(Array.isArray(supplied) ? Object.fromEntries((supplied as readonly ExecutorKeyInfo[]).map(k => [k.key_id, k])) : supplied),
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

  // 6. Completeness.
  if (options.changes !== undefined && options.changes !== null) {
    const endTime = end !== undefined ? end.anchored_at : tail.entry.recorded_at;
    result.completeness = checkCompleteness(options.changes, entries, cited, {
      period: [head.entry.recorded_at, endTime], toleranceSeconds: options.toleranceSeconds,
    });
    for (const item of result.completeness.unmatched_changes) {
      fail('changes', null, 'change_unmatched', `${item.source || '-'} ${item.source_event_id || '-'} ${item.resource_id} `
        + `${item.action} ${item.changed_at}`);
    }
  }
  return result;
}

/** The last retention checkpoint among `all` that removed the entries before `head`, or null. */
function startingCheckpointOf(all: readonly EvidenceEvent[], head: EvidenceEvent): RetentionCheckpoint | null {
  return startingCheckpoint([...all].reverse(), head);
}

/** Policies, attestations, treaties and feeds the records rest on (outside the store). */
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
  } catch (err) {
    fail(POLICIES_FILE, null, 'cited_trust_invalid', message(err));
    return;
  }
  const byVersion = new Map<string, BoundaryPolicy>();
  for (const policy of policies) {
    const signed = naSignatureAt(keys => verifyPolicySignature(policy, keys), history, policy.issued_at);
    if (signed !== 'ok') {
      fail(POLICIES_FILE, null, signed === 'invalid_signature' ? 'policy_invalid_signature' : signed,
        `${policy.policy_id} v${policy.version}`);
    }
    byVersion.set(`${policy.policy_id}\u0000${policy.version}`, policy);
  }
  const own = history.sovereign_id;
  const issuerKeys = new Map<string, string[]>();
  for (const treaty of treaties) {
    const signed = naSignatureAt(keys => verifyTreatySignature(treaty, keys), history, treaty.issued_at);
    if (signed !== 'ok') {
      fail(TREATIES_FILE, null, signed === 'invalid_signature' ? 'treaty_invalid_signature' : signed, treaty.treaty_id);
      continue;
    }
    issuerKeys.set(treaty.subject_sovereign_id, [...(issuerKeys.get(treaty.subject_sovereign_id) ?? []), ...treaty.subject_public_keys]);
  }
  const byAttestation = new Map<string, MembershipAttestation>();
  for (const attestation of attestations) {
    const signed = attestation.issuer_sovereign_id === own
      ? naSignatureAt(keys => attestationSigned(attestation, keys), history, attestation.issued_at)
      : (attestationSigned(attestation, issuerKeys.get(attestation.issuer_sovereign_id) ?? []) ? 'ok' : 'invalid_signature');
    if (signed !== 'ok') {
      fail(ATTESTATIONS_FILE, null, signed === 'invalid_signature' ? 'attestation_invalid_signature' : signed,
        attestation.attestation_id);
    }
    byAttestation.set(attestation.attestation_id, attestation);
  }
  for (const feed of feeds) {
    const keys = issuerKeys.get(feed.issuer_sovereign_id) ?? [];
    if (!feedSigned(feed, keys)) fail(FEEDS_FILE, null, 'feed_invalid_signature', feed.feed_id);
  }

  const fromSequence = entries.length > 0 ? entries[0]!.entry.store_sequence : 0;
  for (const event of [...cited, ...entries]) {
    const kind = event.entry.entry_kind;
    const seq = event.entry.store_sequence;
    const where = seq < fromSequence ? CITED_FILE : ENTRIES_FILE;
    let binding: PolicyBinding | null | undefined = null;
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
    }
    if (binding === null || binding === undefined) continue;
    if (policySetDigest(binding.policies) !== binding.policy_set_digest) {
      fail(where, seq, 'cited_policy_mismatch', 'policy_set_digest');
    }
    for (const applied of binding.policies) {
      const held = byVersion.get(`${applied.policy_id}\u0000${applied.version}`);
      if (held === undefined) fail(where, seq, 'cited_policy_missing', `${applied.policy_id} v${applied.version}`);
      else if (policyDigest(held) !== applied.policy_digest) {
        fail(where, seq, 'cited_policy_mismatch', `${applied.policy_id} v${applied.version}`);
      }
    }
  }
}

function attestationSigned(attestation: MembershipAttestation, keys: readonly string[]): boolean {
  return keys.length > 0 && verifyAttestationSignature(attestation, keys);
}

function feedSigned(feed: SovereignRevocationFeed, keys: readonly string[]): boolean {
  return (Array.isArray(feed.signatures) ? feed.signatures : [])
    .some(s => typeof s?.sig === 'string' && verifyCanonical(revocationFeedCanonical(feed), s.sig, keys));
}

// ── The completeness check ───────────────────────────────────────────────────

/** One change from a log outside Genesis Mesh (a cloud audit log, a ticketing export). */
export interface Change {
  /** Its position in the log, from 1. */
  index: number;
  resource_id: string;
  action: string;
  /** ISO 8601 with an offset. */
  changed_at: string;
  source?: string | null;
  source_event_id?: string | null;
  actor?: string | null;
}

/**
 * Changes from JSON: a list, or `{"changes": [...]}`, each with
 * `resource_id`, `action` and `changed_at` (ISO 8601 with an offset), and
 * `source` with `source_event_id` together. Throws naming the first bad row.
 */
export function parseChanges(input: string | unknown): Change[] {
  const data = typeof input === 'string' ? parseJson(input) : input;
  const rows = isObject(data) ? data['changes'] : data;
  if (!Array.isArray(rows)) throw new Error('a JSON changes file is a list of changes or {"changes": [...]}');
  return rows.map((row, i) => {
    const index = i + 1;
    if (!isObject(row)) throw new Error(`change ${index} is not an object`);
    const value = (name: string) => {
      const raw = row[name];
      return raw === undefined || raw === null || raw === '' ? null : String(raw).trim();
    };
    const resource = value('resource_id');
    const action = value('action');
    const changed = value('changed_at');
    if (!resource || !action || !changed) throw new Error(`change ${index}: resource_id, action and changed_at are required`);
    const offset = /(Z|[+-]\d{2}:\d{2})$/.test(changed);
    if (Number.isNaN(timestampMicros(changed))) throw new Error(`change ${index}: changed_at is not an ISO 8601 time`);
    if (!offset) throw new Error(`change ${index}: changed_at needs an offset (Z for UTC)`);
    const source = value('source');
    const eventId = value('source_event_id');
    if ((source === null) !== (eventId === null)) throw new Error(`change ${index}: source and source_event_id go together`);
    return { index, resource_id: resource, action, changed_at: changed, source, source_event_id: eventId, actor: value('actor') };
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

function distance(record: ChangeRecord, when: number): number {
  if (record.earliest <= when && when <= record.latest) return 0;
  return Math.min(Math.abs(when - record.earliest), Math.abs(when - record.latest));
}

function changeRecords(entries: readonly EvidenceEvent[], cited: readonly EvidenceEvent[]): ChangeRecord[] {
  const records: ChangeRecord[] = [];
  const matched = new Map<string, string>();
  for (const event of [...cited, ...entries]) {
    const p = event.payload;
    if (event.entry.entry_kind === 'judgement' && p['matched_evidence_id']) {
      matched.set(String(p['subject_id']), String(p['matched_evidence_id']));
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
        add(p['observation_id'], p['resource_id'], p['action'], time(p['changed_at'] || p['changed_not_before']),
          time(p['changed_at'] || p['changed_not_after']), str(p['source']), str(p['source_event_id']));
      } else if (kind === 'break_glass') {
        const when = time(p['executed_at']);
        add(p['break_glass_id'], p['resource_id'], p['resource_action'], when, when);
      } else if (kind === 'execution' && p['resource_id']) {
        const when = time(p['executed_at']);
        add(p['evidence_id'], p['resource_id'], p['resource_action'], when, when);
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
 * Match changes from an outside log against a pack's records: first by
 * source and source event ID (an observation of that very event), then by
 * resource, action and time within the tolerance (the closest record, each
 * record matched once; an observation and the execution evidence it was
 * matched to are one change). An unmatched change dated inside the period is
 * in `unmatched_changes`; one outside it in `outside_period`.
 */
export function checkCompleteness(
  changes: readonly Change[],
  entries: readonly EvidenceEvent[],
  cited: readonly EvidenceEvent[],
  options: CompletenessOptions,
): CompletenessReport {
  const tolerance = (options.toleranceSeconds ?? 300) * 1_000_000;
  const records = changeRecords(entries, cited);
  const used = new Set<string>();
  const pairs: CompletenessPair[] = [];
  const left: Change[] = [];
  const byEvent = new Map<string, ChangeRecord>();
  for (const r of records) if (r.source && r.source_event_id) byEvent.set(`${r.source}\u0000${r.source_event_id}`, r);
  for (const change of changes) {
    const record = change.source ? byEvent.get(`${change.source}\u0000${change.source_event_id ?? 'None'}`) : undefined;
    if (record !== undefined && !used.has(record.group)) {
      used.add(record.group);
      pairs.push({ change: change.index, kind: record.kind, record_id: record.record_id, store_sequence: record.store_sequence,
        matched_by: 'source_event_id' });
    } else {
      left.push(change);
    }
  }
  const unmatched: Change[] = [];
  for (const change of left) {
    const when = timestampMicros(change.changed_at);
    const candidates = records.filter(r => !used.has(r.group) && r.resource_id === change.resource_id
      && r.action === change.action && distance(r, when) <= tolerance);
    if (candidates.length === 0) {
      unmatched.push(change);
      continue;
    }
    const record = candidates.reduce((best, r) => {
      const d = distance(r, when) - distance(best, when);
      return d < 0 || (d === 0 && r.store_sequence < best.store_sequence) ? r : best;
    });
    used.add(record.group);
    pairs.push({ change: change.index, kind: record.kind, record_id: record.record_id, store_sequence: record.store_sequence,
      matched_by: 'resource_action_time' });
  }
  const [from, to] = options.period;
  const start = timestampMicros(from);
  const end = timestampMicros(to);
  const inside = unmatched.filter(c => {
    const when = timestampMicros(c.changed_at);
    return start - tolerance <= when && when <= end + tolerance;
  });
  const outside = unmatched.filter(c => !inside.includes(c));
  const lastOfGroup = new Map<string, ChangeRecord>();
  for (const r of records) if (!used.has(r.group)) lastOfGroup.set(r.group, r);
  const unmatchedRecords = [...lastOfGroup.values()].sort((a, b) => a.store_sequence - b.store_sequence);
  return {
    changes: changes.length,
    tolerance_seconds: Math.trunc(tolerance / 1_000_000),
    period: { from, to },
    pairs: pairs.sort((a, b) => a.change - b.change),
    unmatched_changes: inside,
    outside_period: outside,
    unmatched_records: unmatchedRecords.map(r => ({
      kind: r.kind, record_id: r.record_id, store_sequence: r.store_sequence, resource_id: r.resource_id, action: r.action,
    })),
    complete: inside.length === 0,
  };
}
