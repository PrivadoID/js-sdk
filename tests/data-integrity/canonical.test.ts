import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { base64url } from 'rfc4648';
import {
  JsonDocumentObject,
  JsonLdCanonicalizationError,
  canonicalizeStrict,
  computeIden3JwzPayload,
  createStrictDocumentLoader
} from '../../src';
import { VECTOR_CONTEXTS } from './vectors/contexts';

const vectors = JSON.parse(readFileSync(path.join(__dirname, 'vectors/jwzsuite.json'), 'utf8'));
const genuine = vectors.documents.genuine;
const loader = createStrictDocumentLoader(VECTOR_CONTEXTS);
const LOCAL = {
  '@context': {
    a: 'https://example.org/a',
    b: 'https://example.org/b',
    s: { '@id': 'https://example.org/s', '@container': '@list' }
  },
  '@id': 'https://example.org/x',
  a: 'value'
};
const local = createStrictDocumentLoader({});

const jwzPayloadOf = (proofValue: string): string => {
  const compact = new TextDecoder().decode(base64url.parse(proofValue.slice(1), { loose: true }));
  return new TextDecoder().decode(base64url.parse(compact.split('.')[1], { loose: true }));
};
const split = (secured: JsonDocumentObject) => {
  const { proof, ...document } = secured as JsonDocumentObject & { proof: JsonDocumentObject };
  const { proofValue, ...options } = proof;
  return { document, options, proofValue: proofValue as string };
};

describe('strict canonicalization (C.3 step 3)', () => {
  it('refuses a null member', async () => {
    await expect(canonicalizeStrict({ ...LOCAL, b: null }, local)).rejects.toBeInstanceOf(
      JsonLdCanonicalizationError
    );
  });

  it('refuses an empty plain array, which canonicalization drops', async () => {
    await expect(canonicalizeStrict({ ...LOCAL, b: [] }, local)).rejects.toThrow('"b"');
  });

  it('accepts an empty array under a @list term, which is signed as rdf:nil', async () => {
    const canonicalForm = await canonicalizeStrict({ ...LOCAL, s: [] }, local);
    expect(canonicalForm).toContain('<http://www.w3.org/1999/02/22-rdf-syntax-ns#nil>');
  });

  it('refuses a term that no context defines', async () => {
    await expect(canonicalizeStrict({ ...LOCAL, unknown: 'x' }, local)).rejects.toBeInstanceOf(
      JsonLdCanonicalizationError
    );
  });

  it('refuses a relative @id', async () => {
    await expect(
      canonicalizeStrict({ ...LOCAL, '@id': 'relative/x' }, local)
    ).rejects.toBeInstanceOf(JsonLdCanonicalizationError);
  });

  it('refuses a hostile blank node clique within one second', async () => {
    const clique = {
      '@graph': Array.from({ length: 9 }, (_, i) => ({
        '@id': `_:b${i}`,
        'https://example.org/p': Array.from({ length: 9 }, (_, j) => j)
          .filter((j) => j !== i)
          .map((j) => ({ '@id': `_:b${j}` }))
      }))
    };
    const started = Date.now();
    await expect(canonicalizeStrict(clique, local)).rejects.toBeInstanceOf(
      JsonLdCanonicalizationError
    );
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe('JWZ payload (C.3)', () => {
  it('gives the JWZ payload of the genuine DID document', async () => {
    const { document, options, proofValue } = split(genuine.didDocument);
    const payload = await computeIden3JwzPayload(document, options, {
      documentLoader: loader,
      allowUnsignedEmptyArrays: true
    });
    expect(payload).toHaveLength(86);
    expect(payload).toBe(jwzPayloadOf(proofValue));
  });

  it('refuses the genuine DID document by default, because canonicalization drops its empty siblings array', async () => {
    const { document, options } = split(genuine.didDocument);
    await expect(
      computeIden3JwzPayload(document, options, { documentLoader: loader })
    ).rejects.toThrow('"siblings"');
  });

  it('gives the JWZ payload of the genuine DID configuration credential', async () => {
    const { document, options, proofValue } = split(genuine.didConfiguration.linked_dids[0]);
    expect(await computeIden3JwzPayload(document, options, { documentLoader: loader })).toBe(
      jwzPayloadOf(proofValue)
    );
  });

  it('refuses a document that holds a proof', async () => {
    const { options } = split(genuine.didDocument);
    await expect(
      computeIden3JwzPayload(genuine.didDocument, options, { documentLoader: loader })
    ).rejects.toThrow('proof');
  });
});
