import { describe, expect, it, jest } from '@jest/globals';
import { ExecutionRecorder, checkMetadataOnly, executionDigest, seedSigner, verifyExecutionSignature, SecretMaterialError } from '../src/index.js';
import { TEST_KEY } from './helpers.js';
import { vectors } from './vectors.js';

const v = vectors();
const signer = seedSigner(TEST_KEY.seedBase64, 'executor');
const recorder = new ExecutionRecorder({ executorSovereignId: 'executor', signer });
const params = { decision: v.allowed.decision, executed_capability: 'sp-secret.rotate', outcome: 'success' as const };

describe('ExecutionRecorder', () => {
  it('signs a first record without optional resource fields', async () => {
    const record = await recorder.record({ ...params, executed_at: new Date('2026-10-01T00:00:00.123Z') });
    expect(record).toMatchObject({ sequence_no: 1, prev_evidence_digest: null, executed_at: '2026-10-01T00:00:00.123000Z' });
    expect(record.resource_id).toBeUndefined();
    expect(verifyExecutionSignature(record, TEST_KEY.pubBase64)).toBe(true);
    expect(recorder.keyId).toBe('executor');
  });
  it('links both chains and accepts checkpoint heads', async () => {
    const first = await recorder.record({ ...params, resource_id: 'kv:v/s', resource_action: 'create' });
    const second = await recorder.record({ ...params, resource_id: 'kv:v/s', resource_action: 'rotate', prior_record: first, prior_resource: first });
    expect(second).toMatchObject({ sequence_no: 2, resource_sequence: 2, prev_evidence_digest: executionDigest(first), prev_resource_digest: executionDigest(first) });
    const third = await recorder.record({ ...params, resource_id: 'kv:v/s', resource_action: 'revoke', prior_resource: { resource_sequence: 2, record_digest: executionDigest(second) } });
    expect(third.resource_sequence).toBe(3);
  });
  it('requires resource ID and action together', async () => {
    await expect(recorder.record({ ...params, resource_id: 'kv:v/s' })).rejects.toThrow('go together');
    await expect(recorder.record({ ...params, resource_action: 'rotate' })).rejects.toThrow('go together');
  });
  it('propagates signer failures and rejects invalid signature lengths', async () => {
    const failure = new Error('HSM unavailable');
    const failing = new ExecutionRecorder({ executorSovereignId: 'x', signer: { keyId: 'x', sign: async () => { throw failure; } } });
    await expect(failing.record(params)).rejects.toBe(failure);
    const short = new ExecutionRecorder({ executorSovereignId: 'x', signer: { keyId: 'x', sign: async () => Buffer.alloc(2) } });
    await expect(short.record(params)).rejects.toThrow('64 bytes');
  });
  it('rejects secret metadata before signing', async () => {
    const sign = jest.fn(signer.sign);
    const guarded = new ExecutionRecorder({ executorSovereignId: 'x', signer: { keyId: 'x', sign } });
    await expect(guarded.record({ ...params, execution_parameters: { nested: [{ 'Client-Secret': 'x' }] } })).rejects.toBeInstanceOf(SecretMaterialError);
    expect(sign).not.toHaveBeenCalled();
  });
});

describe('metadata guard', () => {
  it.each([
    { password: 'x' }, { nested: { access_token: 'x' } }, { list: [{ privateKey: 'x' }] },
    { note: '-----BEGIN PRIVATE KEY-----' }, { note: 'x'.repeat(120) }, { note: 'eyJabc.def.ghi' },
  ])('rejects secret material %j', metadata => expect(checkMetadataOnly(metadata)).not.toBeNull());
  it('checks detail and byte size while allowing ordinary identifiers', () => {
    expect(checkMetadataOnly({}, '-----BEGIN PRIVATE KEY-----')).not.toBeNull();
    expect(checkMetadataOnly({ note: 'é '.repeat(6000) })).toContain('limit');
    expect(checkMetadataOnly({ secret_version: 'v1', owner: 'Zoë', expires_at: '2027-01-01' })).toBeNull();
  });
});
