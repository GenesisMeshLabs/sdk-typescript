import { describe, expect, it } from '@jest/globals';
import { GenesisMeshClient, canonicalJson, verifyBytes, ConflictError, ForbiddenError, ServiceUnavailableError } from '../src/index.js';
import { mockFetch, TEST_KEY } from './helpers.js';
import { vectors } from './vectors.js';

const v = vectors();
interface Route {
  name: string;
  method: string;
  path: string;
  admin: boolean;
  response?: unknown;
  expected?: unknown;
  body?: unknown;
  call: (gm: GenesisMeshClient) => Promise<unknown>;
}
const intent = { policy_id: 'p', valid_from: v.policy.valid_from, valid_until: v.policy.valid_until };
const routes: Route[] = [
  { name: 'attestation get', method: 'GET', path: '/attestations/a%2Fb', admin: false, call: gm => gm.attestation.get('a/b') },
  { name: 'attestation list', method: 'GET', path: '/attestations?subject_id=Zo%C3%AB&status=active', admin: false, call: gm => gm.attestation.list({ subject_id: 'Zoë', status: 'active' }) },
  { name: 'attestation verify', method: 'POST', path: '/attestations/verify', admin: false, body: { attestation: v.attestation }, call: gm => gm.attestation.verify({ attestation: v.attestation }) },
  { name: 'recognition policy', method: 'GET', path: '/recognition-policy', admin: false, call: gm => gm.attestation.getPolicy() },
  { name: 'revocation feed', method: 'GET', path: '/sovereign-revocation-feed?issuer_sovereign_id=a%2Fb', admin: false, call: gm => gm.attestation.revocationFeed('a/b') },
  { name: 'evaluate attestation', method: 'POST', path: '/admin/boundary/evaluate', admin: true, body: { attestation_id: 'a', requested_capability: 'rotate' }, call: gm => gm.boundary.evaluate({ attestation_id: 'a', requested_capability: 'rotate' }) },
  { name: 'policy validate', method: 'POST', path: '/admin/boundary-policies/validate', admin: true, body: intent, call: gm => gm.policy.validate(intent) },
  { name: 'policy publish', method: 'POST', path: '/admin/boundary-policies', admin: true, body: intent, call: gm => gm.policy.publish(intent) },
  { name: 'policy list', method: 'GET', path: '/admin/boundary-policies', admin: true, response: { policies: [v.policy] }, expected: [v.policy], call: gm => gm.policy.list() },
  { name: 'policy active', method: 'GET', path: '/admin/boundary-policies/active', admin: true, call: gm => gm.policy.active() },
  { name: 'policy history', method: 'GET', path: '/admin/boundary-policies/p%2F1/history', admin: true, call: gm => gm.policy.history('p/1') },
  { name: 'policy activate/rollback', method: 'POST', path: '/admin/boundary-policies/p%2F1/activate', admin: true, body: { version: 1 }, call: gm => gm.policy.activate('p/1', 1) },
  { name: 'policy deactivate', method: 'POST', path: '/admin/boundary-policies/p%2F1/deactivate', admin: true, body: { version: 1 }, call: gm => gm.policy.deactivate('p/1', 1) },
  { name: 'policy verify', method: 'POST', path: '/boundary-policies/verify', admin: false, body: { policy: v.policy }, call: gm => gm.policy.verify({ policy: v.policy }) },
  { name: 'submit', method: 'POST', path: '/evidence/execution', admin: false, body: { evidence: v.executions[0] }, call: gm => gm.evidenceStore.submit(v.executions[0]) },
  { name: 'search', method: 'GET', path: '/admin/evidence?vendor_id=a%2Fb&after_sequence=2&limit=10', admin: true, call: gm => gm.evidenceStore.search({ vendor_id: 'a/b', after_sequence: 2, limit: 10 }) },
  { name: 'store status', method: 'GET', path: '/admin/evidence/status', admin: true, call: gm => gm.evidenceStore.status() },
  { name: 'store verify', method: 'GET', path: '/admin/evidence/verify', admin: true, call: gm => gm.evidenceStore.verify() },
  { name: 'resource history', method: 'GET', path: '/admin/evidence/resources/kv%3Avault/name%20%23', admin: true, call: gm => gm.evidenceStore.resourceHistory('kv:vault/name #') },
  { name: 'vendor history', method: 'GET', path: '/admin/evidence/vendors/a%2Fb', admin: true, call: gm => gm.evidenceStore.vendorHistory('a/b') },
  { name: 'export text', method: 'GET', path: '/admin/evidence/export?since_sequence=2&limit=10', admin: true, response: 'lines', call: gm => gm.evidenceStore.exportText({ since_sequence: 2, limit: 10 }) },
  { name: 'executor list', method: 'GET', path: '/admin/evidence/executor-keys', admin: true, response: { executor_keys: v.executor_keys }, expected: v.executor_keys, call: gm => gm.evidenceStore.listExecutorKeys() },
  { name: 'executor register', method: 'POST', path: '/admin/evidence/executor-keys', admin: true, body: v.executor_keys[0], call: gm => gm.evidenceStore.registerExecutorKey(v.executor_keys[0]) },
  { name: 'executor retire', method: 'POST', path: '/admin/evidence/executor-keys/a%2Fb/retire', admin: true, body: {}, call: gm => gm.evidenceStore.retireExecutorKey('a/b') },
  { name: 'retention', method: 'POST', path: '/admin/evidence/retention/apply', admin: true, body: { older_than_days: 30 }, call: gm => gm.evidenceStore.applyRetention(30) },
];

describe.each(routes)('$name', route => {
  it('returns the response and uses the correct URL, body and authentication', async () => {
    const body = route.response ?? { ok: true };
    const fetch = mockFetch({ status: 200, body });
    const gm = new GenesisMeshClient({ baseUrl: 'http://localhost/', signingKeyBase64: TEST_KEY.seedBase64, keyId: 'test', fetch: fetch as unknown as typeof globalThis.fetch });
    expect(await route.call(gm)).toEqual(route.expected ?? body);
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://localhost' + route.path);
    expect(init.method).toBe(route.method);
    const headers = init.headers as Record<string, string>;
    if (route.admin) {
      expect(headers['X-Admin-Key-Id']).toBe('test');
      expect(verifyBytes(Buffer.from(canonicalJson({ body: route.body ?? {}, key_id: 'test', timestamp: headers['X-Admin-Timestamp'], nonce: headers['X-Admin-Nonce'] })), headers['X-Admin-Signature'], TEST_KEY.pubBase64)).toBe(true);
    } else expect(headers['X-Admin-Signature']).toBeUndefined();
    expect(init.body === undefined ? undefined : JSON.parse(String(init.body))).toEqual(route.body);
  });
  it.each([[403, ForbiddenError], [409, ConflictError], [503, ServiceUnavailableError]] as Array<[number, typeof ForbiddenError | typeof ConflictError | typeof ServiceUnavailableError]>)('preserves typed HTTP %s errors and details', async (status, ErrorType) => {
    const fetch = mockFetch({ status, body: { error: { code: 'test_error', message: 'failed', details: { reason: 'test' }, request_id: 'request-1' } } });
    const gm = new GenesisMeshClient({ baseUrl: 'http://localhost', signingKeyBase64: TEST_KEY.seedBase64, fetch: fetch as unknown as typeof globalThis.fetch });
    const pending = route.call(gm);
    await expect(pending).rejects.toBeInstanceOf(ErrorType);
    await expect(pending).rejects.toMatchObject({ code: 'test_error', details: { reason: 'test' }, requestId: 'request-1' });
  });
});
