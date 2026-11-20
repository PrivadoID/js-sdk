import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { DID } from '@iden3/js-iden3-core';
import { proving } from '@iden3/js-jwz';
import { base64url } from 'rfc4648';
import {
  IPackageManager,
  JsonDocumentObject,
  createIden3JwzProof,
  createStrictDocumentLoader,
  iden3JwzProofOptions,
  proofValueFromCompactJwz
} from '../../src';
import { VECTOR_CONTEXTS } from './vectors/contexts';

const vectors = JSON.parse(readFileSync(path.join(__dirname, 'vectors/jwzsuite.json'), 'utf8'));
const { proof: genuineProof, ...genuineDocument } = vectors.documents.genuine
  .didDocument as JsonDocumentObject & { proof: Record<string, string> };
const genuineCompact = new TextDecoder().decode(
  base64url.parse(genuineProof.proofValue.slice(1), { loose: true })
);
const signer = DID.parse(vectors.did);
const created = new Date(genuineProof.created);
const expires = new Date(genuineProof.expires);
const loader = createStrictDocumentLoader(VECTOR_CONTEXTS);

const packerReturning = (compact: string) => {
  const pack = vi.fn(async () => new TextEncoder().encode(compact));
  return { pack, manager: { pack } as unknown as IPackageManager };
};

describe('iden3-jwz-rdfc-2026 proof creation (C.4)', () => {
  it('builds the proof options of C.1', () => {
    const { proofValue, ...options } = genuineProof;
    expect(iden3JwzProofOptions(signer, new Date(created.getTime() + 999), expires)).toEqual(
      options
    );
    expect(proofValue.startsWith('u')).toBe(true);
  });

  it('refuses expires that is not later than created', () => {
    expect(() => iden3JwzProofOptions(signer, created, created)).toThrow();
  });

  it('gives the multibase proofValue of a compact JWZ', () => {
    expect(proofValueFromCompactJwz(genuineCompact)).toBe(genuineProof.proofValue);
  });

  it('proves the payload with the authV3-8-32 ZKP packer and gives the proof', async () => {
    const { pack, manager } = packerReturning(genuineCompact);
    const proof = await createIden3JwzProof(genuineDocument, {
      signer,
      created,
      expires,
      packageManager: manager,
      documentLoader: loader,
      allowUnsignedEmptyArrays: true
    });
    expect(proof).toEqual(genuineProof);
    expect(pack).toHaveBeenCalledOnce();
    const [mediaType, payloadBytes, params] = pack.mock.calls[0] as unknown as [
      string,
      Uint8Array,
      { senderDID: DID; provingMethodAlg: unknown }
    ];
    expect(mediaType).toBe('application/iden3-zkp-json');
    expect(new TextDecoder().decode(payloadBytes)).toBe(
      new TextDecoder().decode(base64url.parse(genuineCompact.split('.')[1], { loose: true }))
    );
    expect(params.senderDID.string()).toBe(vectors.did);
    expect(params.provingMethodAlg).toEqual(
      proving.provingMethodGroth16AuthV3_8_32Instance.methodAlg
    );
  });

  it('refuses a JWZ whose header is not the exact header of C.2', async () => {
    const [, payload, zkp] = genuineCompact.split('.');
    const header = base64url.stringify(
      new TextEncoder().encode(
        '{"circuitId":"authV3-8-32","alg":"groth16","crit":["circuitId"],"typ":"application/iden3-zkp-json"}'
      ),
      { pad: false }
    );
    const { manager } = packerReturning([header, payload, zkp].join('.'));
    await expect(
      createIden3JwzProof(genuineDocument, {
        signer,
        created,
        expires,
        packageManager: manager,
        documentLoader: loader,
        allowUnsignedEmptyArrays: true
      })
    ).rejects.toThrow('header');
  });
});
