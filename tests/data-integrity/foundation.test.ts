import { describe, expect, it } from 'vitest';
import * as sdk from '../../src';
import {
  IDEN3_JWZ_CIRCUIT_HEADERS,
  IDEN3_JWZ_PROOF_MEMBERS,
  IDEN3_JWZ_PROOF_REASONS,
  Iden3JwzProofRejection,
  createStrictDocumentLoader,
  formatIden3JwzDate,
  parseIden3JwzDate
} from '../../src';

const CONTEXT_URL = 'https://example.org/context/v1';
const CONTEXT = { '@context': { name: 'https://example.org/vocab#name' } };

describe('iden3-jwz-rdfc-2026 foundation', () => {
  it('holds the exact authV3-8-32 header', () => {
    expect(IDEN3_JWZ_CIRCUIT_HEADERS['authV3-8-32']).toBe(
      '{"alg":"groth16","circuitId":"authV3-8-32","crit":["circuitId"],"typ":"application/iden3-zkp-json"}'
    );
    expect(Object.keys(IDEN3_JWZ_CIRCUIT_HEADERS)).toEqual(['authV3-8-32']);
  });

  it('lists the reasons of C.6 in order', () => {
    expect(IDEN3_JWZ_PROOF_REASONS).toEqual([
      'proof_malformed',
      'proof_expired',
      'document_malformed',
      'proof_hash_mismatch',
      'proof_invalid',
      'proof_signer_mismatch',
      'state_superseded',
      'state_unavailable'
    ]);
    const rejection = new Iden3JwzProofRejection('proof_expired', 'the proof has expired');
    expect(rejection).toBeInstanceOf(Error);
    expect(rejection.reason).toBe('proof_expired');
    expect(rejection.message).toBe('the proof has expired (proof_expired)');
  });

  it('freezes the circuit headers, the proof members and the reasons', () => {
    expect(Object.isFrozen(IDEN3_JWZ_CIRCUIT_HEADERS)).toBe(true);
    expect(Object.isFrozen(IDEN3_JWZ_PROOF_MEMBERS)).toBe(true);
    expect(Object.isFrozen(IDEN3_JWZ_PROOF_REASONS)).toBe(true);
  });

  it('does not export parseStrictJsonObject from the package root', () => {
    expect(sdk).not.toHaveProperty('parseStrictJsonObject');
  });

  it('reads and writes only whole UTC seconds', () => {
    expect(parseIden3JwzDate('2026-11-08T23:00:00Z')).toBe(1794178800);
    expect(formatIden3JwzDate(1794178800)).toBe('2026-11-08T23:00:00Z');
    for (const bad of [
      '2026-11-08T23:00:00+00:00',
      '2026-11-08T23:00:00.000Z',
      '2026-11-08t23:00:00z',
      '2026-02-29T00:00:00Z',
      '2026-11-08 23:00:00Z'
    ]) {
      expect(parseIden3JwzDate(bad)).toBeNull();
    }
  });

  it('serves only the given contexts, and never the network', async () => {
    const load = createStrictDocumentLoader({ [CONTEXT_URL]: JSON.stringify(CONTEXT) });
    const loaded = await load(CONTEXT_URL);
    expect(loaded.document).toEqual(CONTEXT);
    expect(loaded.documentUrl).toBe(CONTEXT_URL);
    await expect(load('https://www.w3.org/ns/did/v1')).rejects.toThrow('not bundled');
  });

  it('gives a fresh copy for each load', async () => {
    const load = createStrictDocumentLoader({ [CONTEXT_URL]: CONTEXT });
    const first = await load(CONTEXT_URL);
    (first.document as { '@context': Record<string, string> })['@context'].name =
      'https://evil.example/name';
    expect((await load(CONTEXT_URL)).document).toEqual(CONTEXT);
  });
});
