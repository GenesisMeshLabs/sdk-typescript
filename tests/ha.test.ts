import { describe, expect, it, jest } from '@jest/globals';
import { GenesisMeshClient, seedSigner } from '../src/index.js';
import { HttpTransport } from '../src/client.js';
import { ConflictError, NetworkError, ServiceUnavailableError, isRetryableConflict } from '../src/errors.js';
import { TEST_KEY } from './helpers.js';

const A = 'http://na-a:8443';
const B = 'http://na-b:8443';

type Behaviour = 'down' | 'reset' | number;

/** A fetch that routes by host: an instance is either down (connection refused) or answers with a status. */
function cluster(state: Record<string, Behaviour>, body: unknown = { ok: true }) {
  const calls: string[] = [];
  const fetch = jest.fn(async (url: string | URL | Request) => {
    const u = String(url);
    calls.push(u);
    const host = Object.keys(state).find(h => u.startsWith(h));
    const behaviour = host ? state[host] : 'down';
    if (behaviour === 'down') throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } });
    if (behaviour === 'reset') throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
    const status = behaviour as number;
    const payload = status === 503
      ? { error: { code: 'service_not_ready', message: 'Service is not ready', details: READY_DETAILS(false), request_id: 'r' } }
      : body;
    return { ok: status < 300, status, text: async () => JSON.stringify(payload) } as Response;
  });
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls };
}

const READY_DETAILS = (ready: boolean) => ({
  instance: 'host:1', ha_mode: 'on', rate_limiter: 'database',
  database: { backend: 'postgres', writable: ready, schema_version: 13, expected_schema_version: 13, ...(ready ? {} : { error: 'OperationalError' }) },
  signing_key: { key_id: 'na', provider: 'azure-keyvault', fingerprint: 'ab'.repeat(32) },
});

/** Like `cluster`, but `/sovereign.json` answers 200 with the NA key on a healthy (2xx) instance. */
function clusterWithMetadata(state: Record<string, Behaviour>) {
  const calls: string[] = [];
  const fetch = jest.fn(async (url: string | URL | Request) => {
    const u = String(url);
    calls.push(u);
    const host = Object.keys(state).find(h => u.startsWith(h));
    const behaviour = host ? state[host] : 'down';
    if (behaviour === 'down') throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } });
    if (behaviour === 'reset') throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
    const status = behaviour as number;
    const healthy = status < 300;
    const payload = !healthy
      ? { error: { code: 'service_not_ready', message: 'Service is not ready', details: {}, request_id: 'r' } }
      : u.endsWith('/sovereign.json') ? { network_authority: { public_key: 'NA-PUBLIC-KEY' } } : { ok: true };
    return { ok: healthy, status: healthy && u.endsWith('/sovereign.json') ? 200 : status, text: async () => JSON.stringify(payload) } as Response;
  });
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls };
}

describe('the admin audience lookup fails over (1.0.2)', () => {
  it('moves a non-idempotent request when the NA public key cannot be read from a down instance', async () => {
    const { fetch, calls } = clusterWithMetadata({ [A]: 'down', [B]: 201 });
    const client = new GenesisMeshClient({ baseUrls: [A, B], signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops', fetch });
    await expect(client.attestation.issue({ subject_id: 's', roles: ['role:client'] })).resolves.toBeDefined();
    expect(calls).toEqual([`${A}/sovereign.json`, `${B}/sovereign.json`, `${B}/admin/attestations`]);
  });

  it('moves past an instance whose metadata answers 503', async () => {
    const { fetch, calls } = clusterWithMetadata({ [A]: 503, [B]: 200 });
    const t = new HttpTransport({ baseUrls: [A, B], signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops', fetch });
    await expect(t.adminGet('/admin/evidence')).resolves.toEqual({ ok: true });
    expect(calls).toEqual([`${A}/sovereign.json`, `${B}/sovereign.json`, `${B}/admin/evidence`]);
  });
});

describe('multi-endpoint failover (v0.60)', () => {
  it('accepts baseUrls and starts with the first', () => {
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, `${B}/`] });
    expect(t.baseUrls).toEqual([A, B]);
    expect(t.baseUrl).toBe(A);
  });

  it('refuses no endpoint, both options, or a non-http URL', () => {
    expect(() => new HttpTransport({})).toThrow();
    expect(() => new HttpTransport({ audience: 'TEST', baseUrl: A, baseUrls: [B] })).toThrow();
    expect(() => new HttpTransport({ audience: 'TEST', baseUrls: ['ftp://x'] })).toThrow();
  });

  it('moves an idempotent request to the next instance when one is down', async () => {
    const { fetch, calls } = cluster({ [A]: 'down', [B]: 200 });
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B], fetch });
    await expect(t.publicGet('/healthz')).resolves.toEqual({ ok: true });
    expect(calls.map(c => c.slice(0, A.length))).toEqual([A, B]);
    expect(t.baseUrl).toBe(B); // sticky: later requests start at the healthy one
  });

  it('moves past an instance answering 503 for idempotent requests', async () => {
    const { fetch, calls } = cluster({ [A]: 503, [B]: 200 });
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B], fetch });
    await t.publicGet('/attestations');
    expect(calls).toHaveLength(2);
  });

  it('moves a non-idempotent request when the connection was refused (never sent)', async () => {
    const { fetch, calls } = cluster({ [A]: 'down', [B]: 201 });
    const client = new GenesisMeshClient({ audience: 'TEST', baseUrls: [A, B], signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops', fetch });
    await expect(client.attestation.issue({ subject_id: 's', roles: ['role:client'] })).resolves.toBeDefined();
    expect(calls.map(c => c.slice(0, A.length))).toEqual([A, B]);
  });

  it('never replays a non-idempotent request that may have been delivered, but routes the next one elsewhere', async () => {
    const { fetch, calls } = cluster({ [A]: 'reset', [B]: 201 });
    const client = new GenesisMeshClient({ audience: 'TEST', baseUrls: [A, B], signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops', fetch });
    await expect(client.attestation.issue({ subject_id: 's', roles: ['role:client'] })).rejects.toBeInstanceOf(NetworkError);
    expect(calls).toHaveLength(1);
    await expect(client.attestation.issue({ subject_id: 's', roles: ['role:client'] })).resolves.toBeDefined();
    expect(calls[1]?.startsWith(B)).toBe(true);
  });

  it('does not replay a non-idempotent request after a 503 from the instance', async () => {
    const { fetch, calls } = cluster({ [A]: 503, [B]: 201 });
    const client = new GenesisMeshClient({ audience: 'TEST', baseUrls: [A, B], signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops', fetch });
    await expect(client.attestation.issue({ subject_id: 's', roles: ['role:client'] })).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(calls).toHaveLength(1);
  });

  it('fails with NetworkError when every instance is down', async () => {
    const { fetch, calls } = cluster({ [A]: 'down', [B]: 'down' });
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B], fetch });
    await expect(t.publicGet('/healthz')).rejects.toBeInstanceOf(NetworkError);
    expect(calls).toHaveLength(2);
  });

  it('combines failover with configured retries and backoff', async () => {
    let n = 0;
    const fetch = jest.fn(async () => {
      n += 1;
      if (n <= 2) throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
      return { ok: true, status: 200, text: async () => '{"ok":true}' } as Response;
    }) as unknown as typeof globalThis.fetch;
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B], fetch, retry: { attempts: 1, baseDelayMs: 1 } });
    await expect(t.publicGet('/x')).resolves.toEqual({ ok: true });
    expect(n).toBe(3);
  });

  it('keeps single-endpoint behaviour: no extra attempt without retries', async () => {
    const { fetch, calls } = cluster({ [A]: 'down' });
    const t = new HttpTransport({ audience: 'TEST', baseUrl: A, fetch });
    await expect(t.publicGet('/healthz')).rejects.toBeInstanceOf(NetworkError);
    expect(calls).toHaveLength(1);
  });
});

describe('health client (v0.60)', () => {
  it('returns readiness with ready: true', async () => {
    const { fetch, calls } = cluster({ [A]: 200 }, { status: 'ready', db_path: 'x', ...READY_DETAILS(true) });
    const client = new GenesisMeshClient({ audience: 'TEST', baseUrl: A, fetch });
    const r = await client.health.readiness();
    expect(r.ready).toBe(true);
    expect(r.database.backend).toBe('postgres');
    expect(r.signing_key.provider).toBe('azure-keyvault');
    expect(calls[0]).toBe(`${A}/readyz`);
  });

  it('returns a not-ready NA as ready: false with the failing checks', async () => {
    const { fetch } = cluster({ [A]: 503 });
    const r = await new GenesisMeshClient({ audience: 'TEST', baseUrl: A, fetch }).health.readiness();
    expect(r).toMatchObject({ ready: false, status: 'not_ready', database: { writable: false, error: 'OperationalError' } });
  });

  it('rethrows other failures', async () => {
    const fetch = jest.fn(async () => ({
      ok: false, status: 503, text: async () => JSON.stringify({ error: { code: 'evidence_store_unavailable', message: 'x' } }),
    }) as Response) as unknown as typeof globalThis.fetch;
    await expect(new GenesisMeshClient({ audience: 'TEST', baseUrl: A, fetch }).health.readiness()).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('probes every endpoint directly', async () => {
    const { fetch } = cluster({ [A]: 'down', [B]: 200 }, { status: 'ready', ...READY_DETAILS(true) });
    const report = await new GenesisMeshClient({ audience: 'TEST', baseUrls: [A, B], fetch }).health.endpoints();
    expect(report.map(e => [e.base_url, e.reachable, e.ready])).toEqual([[A, false, false], [B, true, true]]);
  });

  it('reports a reachable but not-ready endpoint with its checks', async () => {
    const { fetch } = cluster({ [A]: 503 });
    const [a] = await new GenesisMeshClient({ audience: 'TEST', baseUrls: [A], fetch }).health.endpoints();
    expect(a).toMatchObject({ reachable: true, ready: false, readiness: { database: { writable: false } } });
  });

  it('reads liveness and health', async () => {
    const { fetch, calls } = cluster({ [A]: 200 }, { status: 'ok' });
    const client = new GenesisMeshClient({ audience: 'TEST', baseUrl: A, fetch });
    await client.health.liveness();
    await client.health.health();
    expect(calls).toEqual([`${A}/healthz`, `${A}/health`]);
  });
});

describe('isRetryableConflict', () => {
  it.each(['boundary_policy_activation_conflict', 'boundary_policy_version_conflict', 'crl_publish_contention', 'retention_in_progress'])(
    'recognises %s', code => {
      expect(isRetryableConflict(new ConflictError('x', code))).toBe(true);
    });

  it('rejects other conflicts and other errors', () => {
    expect(isRetryableConflict(new ConflictError('x', 'evidence_conflict'))).toBe(false);
    expect(isRetryableConflict(new Error('x'))).toBe(false);
    expect(isRetryableConflict(undefined)).toBe(false);
  });
});

// ── Concurrent failures ────────────────────────────────────────────────────────

describe('concurrent failures at one instance', () => {
  const ok = (body: unknown = { ok: true }) => ({ ok: true, status: 200, text: async () => JSON.stringify(body) }) as Response;
  const refused = () => Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } });

  /** A fetch where the requests to A wait until `count` of them arrived, then fail as `fail` says. */
  function together(count: number, fail: () => Promise<Response>) {
    const calls: string[] = [];
    let arrived = 0;
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const fetch = jest.fn(async (url: string | URL | Request) => {
      const u = String(url);
      calls.push(u);
      if (u.startsWith(A)) {
        if (++arrived === count) release();
        await gate;
        return fail();
      }
      return u.endsWith('/sovereign.json') ? ok({ network_authority: { public_key: 'NA-KEY' } }) : ok();
    });
    return { fetch: fetch as unknown as typeof globalThis.fetch, calls };
  }

  it('move past it once, not once per request', async () => {
    const x = together(2, async () => ({ ok: false, status: 503, text: async () => '{"error":{"code":"service_not_ready","message":"x"}}' }) as Response);
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B, C], fetch: x.fetch });
    await Promise.all([t.publicGet('/x'), t.publicGet('/y')]);
    expect(t.baseUrl).toBe(B);
    expect(x.calls.filter(u => u.startsWith(C))).toEqual([]);
  });

  it('move past it once when they failed without reaching it', async () => {
    const x = together(2, async () => { throw refused(); });
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B, C], fetch: x.fetch });
    await Promise.all([t.publicGet('/x'), t.publicGet('/y')]);
    expect(t.baseUrl).toBe(B);
    // A third request after them starts where they ended.
    await t.publicGet('/z');
    expect(x.calls.filter(u => u.startsWith(C))).toEqual([]);
  });

  it('move past it once when the NA-key lookup they waited for failed there', async () => {
    const x = together(1, async () => { throw refused(); });
    const t = new HttpTransport({ baseUrls: [A, B, C], signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops', fetch: x.fetch });
    await Promise.all([t.adminGet('/admin/x'), t.adminGet('/admin/y'), t.adminPost('/admin/z', {})]);
    expect(t.baseUrl).toBe(B);
    expect(x.calls.filter(u => u.startsWith(A))).toEqual([`${A}/sovereign.json`]);
    expect(x.calls.filter(u => u.startsWith(C))).toEqual([]);
  });
});

// ── Failover interleavings (the review of 1.9.0) ─────────────────────────────────

const C = 'http://na-c:8443';
const answer = (body: unknown = { ok: true }) => ({ ok: true, status: 200, text: async () => JSON.stringify(body) }) as Response;
const busy = () => ({ ok: false, status: 503, text: async () => '{"error":{"code":"service_not_ready","message":"x"}}' }) as Response;
const refusedConnection = () => Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } });
const resetConnection = () => Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
const tick = async (n = 50) => { for (let i = 0; i < n; i++) await Promise.resolve(); };

interface Call { url: string; resolve: (r: Response) => void; reject: (e: unknown) => void }

/** A fetch whose every call waits until the test settles it. */
function manual() {
  const calls: Call[] = [];
  const fetch = (async (url: string | URL | Request) => new Promise<Response>((resolve, reject) => {
    calls.push({ url: String(url), resolve, reject });
  })) as unknown as typeof globalThis.fetch;
  const take = (prefix: string) => {
    const i = calls.findIndex(c => c.url.startsWith(prefix));
    if (i < 0) throw new Error(`no pending call to ${prefix}: ${calls.map(c => c.url).join(', ')}`);
    return calls.splice(i, 1)[0]!;
  };
  return { fetch, calls, take };
}

describe('failover interleavings, each call settled by hand', () => {
  it('a late failure at an endpoint already left does not move the client', async () => {
    const m = manual();
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B, C], fetch: m.fetch });
    const r1 = t.publicGet('/one');
    const r2 = t.publicGet('/two');
    await tick();
    m.take(A).reject(refusedConnection()); // r2 or r1 fails first at A
    await tick();
    expect(t.baseUrl).toBe(B);
    m.take(B).resolve(answer());
    await tick();
    m.take(A).reject(resetConnection()); // the other one, late
    await tick();
    expect(t.baseUrl).toBe(B);
    m.take(B).resolve(answer());
    await Promise.all([r1, r2]);
    expect(t.baseUrl).toBe(B);
  });

  it('a late failure at A after the client moved A->B->C does not send it back to B', async () => {
    const m = manual();
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B, C], fetch: m.fetch });
    const r1 = t.publicGet('/one');
    const r2 = t.publicGet('/two');
    await tick();
    m.take(`${A}/two`).reject(refusedConnection());
    await tick();
    m.take(`${B}/two`).resolve(busy());
    await tick();
    expect(t.baseUrl).toBe(C);
    m.take(`${C}/two`).resolve(answer());
    await r2;
    m.take(`${A}/one`).reject(resetConnection());
    await tick();
    expect(t.baseUrl).toBe(C);
    m.take(`${C}/one`).resolve(answer());
    await r1;
  });

  it('a lookup started at A fails after the client moved to B: no further move', async () => {
    const m = manual();
    const t = new HttpTransport({ baseUrls: [A, B, C], signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops', fetch: m.fetch });
    const admin = t.adminGet('/admin/x');
    await tick();
    const pub = t.publicGet('/p');
    await tick();
    // public fails at A, moves to B, succeeds there
    const pubCall = m.calls.find(c => c.url === `${A}/p`)!;
    m.calls.splice(m.calls.indexOf(pubCall), 1);
    pubCall.reject(refusedConnection());
    await tick();
    expect(t.baseUrl).toBe(B);
    m.take(`${B}/p`).resolve(answer());
    await pub;
    // the lookup at A now fails
    m.take(`${A}/sovereign.json`).reject(refusedConnection());
    await tick();
    expect(t.baseUrl).toBe(B);
    m.take(`${B}/sovereign.json`).resolve(answer({ network_authority: { public_key: 'K' } }));
    await tick();
    m.take(`${B}/admin/x`).resolve(answer());
    await admin;
    expect(t.baseUrl).toBe(B);
  });

  it('a request that joins a lookup after the client moved, and the lookup fails: joins B', async () => {
    const m = manual();
    const t = new HttpTransport({ baseUrls: [A, B, C], signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops', fetch: m.fetch });
    const a1 = t.adminGet('/admin/1');
    await tick();
    const pub = t.publicGet('/p');
    await tick();
    m.take(`${A}/p`).reject(refusedConnection());
    await tick();
    m.take(`${B}/p`).resolve(answer());
    await pub;
    expect(t.baseUrl).toBe(B);
    // a2 starts while the client is at B, but joins the lookup still pending at A
    const a2 = t.adminPost('/admin/2', {});
    await tick();
    m.take(`${A}/sovereign.json`).reject(refusedConnection());
    await tick();
    expect(t.baseUrl).toBe(B);
    m.take(`${B}/sovereign.json`).resolve(answer({ network_authority: { public_key: 'K' } }));
    await tick();
    m.take(`${B}/admin/1`).resolve(answer());
    m.take(`${B}/admin/2`).resolve(answer());
    await Promise.all([a1, a2]);
    expect(t.baseUrl).toBe(B);
    expect(m.calls).toEqual([]);
  });

  it('lookup answering 503: waiters move once', async () => {
    const m = manual();
    const t = new HttpTransport({ baseUrls: [A, B, C], signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops', fetch: m.fetch });
    const all = Promise.all([t.adminGet('/admin/x'), t.adminGet('/admin/y'), t.adminPost('/admin/z', {})]);
    await tick();
    m.take(`${A}/sovereign.json`).resolve(busy());
    await tick();
    expect(t.baseUrl).toBe(B);
    m.take(`${B}/sovereign.json`).resolve(answer({ network_authority: { public_key: 'K' } }));
    await tick();
    for (const p of ['/admin/x', '/admin/y', '/admin/z']) m.take(`${B}${p}`).resolve(answer());
    await all;
    expect(t.baseUrl).toBe(B);
  });

  it('non-idempotent request reset at A while another already moved: next request starts at B', async () => {
    const m = manual();
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B], fetch: m.fetch, signingKeyBase64: TEST_KEY.seedBase64, keyId: 'ops' });
    const post = t.adminPost('/admin/p', {});
    const get = t.publicGet('/g');
    await tick();
    m.take(`${A}/g`).reject(refusedConnection());
    await tick();
    m.take(`${B}/g`).resolve(answer());
    await get;
    m.take(`${A}/admin/p`).reject(resetConnection());
    await expect(post).rejects.toBeInstanceOf(NetworkError);
    expect(t.baseUrl).toBe(B);
  });

  it('single endpoint: retries with backoff and no movement', async () => {
    let n = 0;
    const fetch = (async () => {
      n += 1;
      if (n <= 2) throw refusedConnection();
      return answer();
    }) as unknown as typeof globalThis.fetch;
    const t = new HttpTransport({ audience: 'TEST', baseUrl: A, fetch, retry: { attempts: 2, baseDelayMs: 1 } });
    await expect(t.publicGet('/x')).resolves.toEqual({ ok: true });
    expect(n).toBe(3);
    expect(t.baseUrl).toBe(A);
  });

  it('async signer: the client moves while signing, and the request goes where it is then', async () => {
    const m = manual();
    let release!: () => void;
    const gate = new Promise<void>(r => { release = r; });
    const inner = seedSigner(TEST_KEY.seedBase64, 'ops');
    const signer = { ...inner, keyId: 'ops', sign: async (d: Buffer) => { await gate; return inner.sign(d); } };
    const t = new HttpTransport({ audience: 'TEST', baseUrls: [A, B, C], fetch: m.fetch, signer: signer as never });
    const admin = t.adminGet('/admin/x');
    const pub = t.publicGet('/p');
    await tick();
    m.take(`${A}/p`).reject(refusedConnection());
    await tick();
    m.take(`${B}/p`).resolve(answer());
    await pub;
    expect(t.baseUrl).toBe(B);
    release();
    await tick();
    // sent to B (the client moved while signing), fails there: client moves past B
    m.take(`${B}/admin/x`).resolve(busy());
    await tick();
    expect(t.baseUrl).toBe(C);
    m.take(`${C}/admin/x`).resolve(answer());
    await admin;
  });
});
