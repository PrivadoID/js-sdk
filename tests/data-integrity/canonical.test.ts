import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { base64url } from 'rfc4648';
import {
  Iden3JwzPayloadOptions,
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
const LOCAL_CONTEXT_URL = 'https://example.org/local/v1';
const LOCAL_TERMS = {
  a: 'https://example.org/a',
  b: 'https://example.org/b',
  s: { '@id': 'https://example.org/s', '@container': '@list' },
  j: { '@id': 'https://example.org/j', '@type': '@json' }
};
const LOCAL = { '@context': LOCAL_CONTEXT_URL, '@id': 'https://example.org/x', a: 'value' };
const local = createStrictDocumentLoader({ [LOCAL_CONTEXT_URL]: { '@context': LOCAL_TERMS } });

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
    await expect(canonicalizeStrict({ ...LOCAL, b: [] }, local)).rejects.toThrow('empty array');
  });

  it('refuses an empty @type array, a nested empty array and an empty @set', async () => {
    for (const extra of [{ '@type': [] }, { b: [[]] }, { b: { '@set': [] } }]) {
      await expect(canonicalizeStrict({ ...LOCAL, ...extra }, local)).rejects.toThrow(
        'empty array'
      );
    }
  });

  it('accepts an empty array inside a @json literal', async () => {
    await expect(canonicalizeStrict({ ...LOCAL, j: { list: [] } }, local)).resolves.toContain(
      '#JSON>'
    );
  });

  it('refuses a document with many empty arrays within one second', async () => {
    const started = Date.now();
    await expect(
      canonicalizeStrict({ ...LOCAL, b: Array.from({ length: 20000 }, () => []) }, local)
    ).rejects.toThrow('empty array');
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it('refuses NaN and undefined array items, which become null', async () => {
    await expect(
      canonicalizeStrict({ ...LOCAL, b: NaN } as unknown as JsonDocumentObject, local)
    ).rejects.toThrow('null');
    await expect(
      canonicalizeStrict({ ...LOCAL, b: [undefined] } as unknown as JsonDocumentObject, local)
    ).rejects.toThrow('null');
  });

  it('refuses an inline context', async () => {
    await expect(
      canonicalizeStrict({ ...LOCAL, '@context': [LOCAL_TERMS] }, local)
    ).rejects.toThrow('@context');
  });

  it('refuses an @index key, which canonicalization drops', async () => {
    await expect(
      canonicalizeStrict({ ...LOCAL, b: { '@value': 'v', '@index': 'k' } }, local)
    ).rejects.toThrow('@index');
  });

  it('refuses an invalid http IRI and an invalid IPv6 host, and accepts a valid IPv6 host', async () => {
    await expect(canonicalizeStrict({ ...LOCAL, '@id': 'http://-bad-/x' }, local)).rejects.toThrow(
      'not a valid URL'
    );
    await expect(
      canonicalizeStrict({ ...LOCAL, '@id': 'http://[1::2::3]/x' }, local)
    ).rejects.toBeInstanceOf(JsonLdCanonicalizationError);
    await expect(
      canonicalizeStrict({ ...LOCAL, '@id': 'http://[::1]/x' }, local)
    ).resolves.toContain('<http://[::1]/x>');
  });

  it('refuses an IRI of 2083 code points or more, and a @json literal that is an array', async () => {
    await expect(
      canonicalizeStrict({ ...LOCAL, '@id': 'https://example.org/' + 'a'.repeat(2063) }, local)
    ).rejects.toBeInstanceOf(JsonLdCanonicalizationError);
    await expect(canonicalizeStrict({ ...LOCAL, j: ['x'] }, local)).rejects.toThrow('JSON literal');
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
    await expect(canonicalizeStrict(clique, local)).rejects.toThrow('Maximum deep iterations');
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it('refuses a list of 4000 equal items quickly', async () => {
    const started = performance.now();
    await expect(
      canonicalizeStrict({ ...LOCAL, s: Array.from({ length: 4000 }, () => 'x') }, local)
    ).rejects.toThrow('blank nodes');
    expect(performance.now() - started).toBeLessThan(100);
  });

  it('refuses a property with 20000 values quickly', async () => {
    const started = performance.now();
    await expect(
      canonicalizeStrict({ ...LOCAL, b: Array.from({ length: 20000 }, (_, i) => `v${i}`) }, local)
    ).rejects.toThrow('values');
    expect(performance.now() - started).toBeLessThan(100);
  });

  it('accepts 1000 nodes with an empty list each within one second', async () => {
    const nodes = Array.from({ length: 1000 }, (_, i) => ({
      '@id': `https://example.org/n${i}`,
      s: []
    }));
    const started = performance.now();
    await expect(canonicalizeStrict({ ...LOCAL, b: nodes }, local)).resolves.toContain(
      '<https://example.org/n999> <https://example.org/s>'
    );
    expect(performance.now() - started).toBeLessThan(1000);
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
    ).rejects.toThrow('empty array');
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

  it('refuses a document that holds a proof, and a BigInt member, with a JsonLdCanonicalizationError', async () => {
    const { document, options } = split(genuine.didDocument);
    await expect(
      computeIden3JwzPayload(genuine.didDocument, options, { documentLoader: loader })
    ).rejects.toBeInstanceOf(JsonLdCanonicalizationError);
    await expect(
      computeIden3JwzPayload({ ...document, extra: 1n } as unknown as JsonDocumentObject, options, {
        documentLoader: loader
      })
    ).rejects.toBeInstanceOf(JsonLdCanonicalizationError);
  });

  it('gives the JWZ payload of a DID document with GIST siblings and a node_aux', async () => {
    const siblings = [
      '7210171262987616307163768372431818245390547658390117213620226932618196931286',
      '0',
      '14918394740106532006282734095416718930012538405651722917215014283357233386405'
    ];
    const { document, options } = split(genuine.didDocument);
    const [stateInfo, ...methods] = document.verificationMethod as JsonDocumentObject[];
    const global = stateInfo.global as JsonDocumentObject;
    const gistDocument = {
      ...document,
      verificationMethod: [
        {
          ...stateInfo,
          global: {
            ...global,
            proof: {
              existence: false,
              node_aux: {
                key: '24846663430375341177084327381366271031641225773947711007341346118923321345',
                value:
                  '6317996369756476782464660724028085001790405126656012993591099574640713781089'
              },
              siblings,
              type: 'Iden3SparseMerkleTreeProof'
            }
          }
        },
        ...methods
      ]
    };
    const payloadOptions: Iden3JwzPayloadOptions = {
      documentLoader: loader,
      allowUnsignedEmptyArrays: true
    };
    expect(await computeIden3JwzPayload(gistDocument, options, payloadOptions)).toHaveLength(86);
    const canonicalForm = await canonicalizeStrict(gistDocument, loader, payloadOptions);
    for (const sibling of siblings) {
      expect(canonicalForm).toContain(`"${sibling}"`);
    }
  });
});
