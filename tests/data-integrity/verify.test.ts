import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { base64url } from 'rfc4648';
import {
  IDEN3_JWZ_PROOF_REASONS,
  JsonDocumentObject,
  VerifyIden3JwzProofOptions,
  createStrictDocumentLoader,
  verifyIden3JwzProof
} from '../../src';
import { VECTOR_CONTEXTS } from './vectors/contexts';
import { RecordedRoot, recordedGistReader, unavailableGistReader } from './vectors/recorded-gist';

type Case = {
  name: string;
  document: JsonDocumentObject;
  signer: string;
  now: number;
  states?: 'recorded' | 'unavailable' | 'none';
  gist?: RecordedRoot[];
  expect: { reason?: string; created?: string; expires?: string };
};
const file = JSON.parse(readFileSync(path.join(__dirname, 'vectors/jwzsuite.json'), 'utf8')) as {
  network: string;
  did: string;
  gist: RecordedRoot[];
  documents: Record<string, { didDocument: JsonDocumentObject }>;
  cases: Case[];
};
const verificationKeys = {
  'authV3-8-32': new TextEncoder().encode(
    readFileSync(path.join(__dirname, 'vectors/auth-v3-8-32.vk.json'), 'utf8')
  )
};
const lifetime = { minSeconds: 7 * 86400, maxSeconds: 14 * 86400 };
const documentLoader = createStrictDocumentLoader(VECTOR_CONTEXTS);
const genuineCase = file.cases[0];
const optionsFor = (
  c: Pick<Case, 'now' | 'states' | 'gist'>,
  extra: Partial<VerifyIden3JwzProofOptions> = {}
): VerifyIden3JwzProofOptions => ({
  signer: file.did,
  now: new Date(c.now * 1000),
  lifetime,
  documentLoader,
  verificationKeys,
  allowUnsignedEmptyArrays: true,
  networks: c.states === 'none' ? [] : [file.network],
  gistRootReader:
    c.states === 'unavailable'
      ? unavailableGistReader()
      : recordedGistReader(c.gist ?? file.gist, c.now),
  ...extra
});
const iso = (date: Date) => date.toISOString().replace('.000Z', 'Z');
const jwzSegmentsOf = (secured: JsonDocumentObject): string[] =>
  new TextDecoder()
    .decode(
      base64url.parse((secured.proof as Record<string, string>).proofValue.slice(1), {
        loose: true
      })
    )
    .split('.');
const withJwzSegment = (
  secured: JsonDocumentObject,
  index: number,
  segment: Uint8Array
): JsonDocumentObject => {
  const segments = jwzSegmentsOf(secured);
  segments[index] = base64url.stringify(segment, { pad: false });
  const compact = new TextEncoder().encode(segments.join('.'));
  return {
    ...secured,
    proof: {
      ...(secured.proof as Record<string, string>),
      proofValue: 'u' + base64url.stringify(compact, { pad: false })
    }
  };
};
const withZkpSegment = (secured: JsonDocumentObject, zkpText: string): JsonDocumentObject =>
  withJwzSegment(secured, 2, new TextEncoder().encode(zkpText));
const withByteOrderMark = (secured: JsonDocumentObject, index: number): JsonDocumentObject => {
  const segment = base64url.parse(jwzSegmentsOf(secured)[index], { loose: true });
  return withJwzSegment(secured, index, new Uint8Array([0xef, 0xbb, 0xbf, ...segment]));
};

describe('iden3-jwz-rdfc-2026 vectors (C.7)', () => {
  for (const c of file.cases) {
    it(c.name, async () => {
      const options = { ...optionsFor(c), signer: c.signer };
      if (c.expect.reason) {
        await expect(verifyIden3JwzProof(c.document, options)).rejects.toMatchObject({
          name: 'Iden3JwzProofRejection',
          reason: c.expect.reason
        });
        return;
      }
      const verified = await verifyIden3JwzProof(c.document, options);
      expect(iso(verified.created)).toBe(c.expect.created);
      expect(iso(verified.expires)).toBe(c.expect.expires);
    });
  }

  it('covers every reason of C.6', () => {
    expect(new Set(file.cases.flatMap((c) => (c.expect.reason ? [c.expect.reason] : [])))).toEqual(
      new Set(IDEN3_JWZ_PROOF_REASONS)
    );
  });
});

describe('iden3-jwz-rdfc-2026 verification edges', () => {
  it('rounds now down to whole seconds', async () => {
    const expires = Date.parse(genuineCase.expect.expires as string);
    await expect(
      verifyIden3JwzProof(
        genuineCase.document,
        optionsFor(genuineCase, { now: new Date(expires - 500) })
      )
    ).resolves.toBeDefined();
  });

  it('refuses a JWZ proof segment with a repeated member name', async () => {
    const proof = genuineCase.document.proof as Record<string, string>;
    const compact = new TextDecoder().decode(
      base64url.parse(proof.proofValue.slice(1), { loose: true })
    );
    const zkp = JSON.parse(
      new TextDecoder().decode(base64url.parse(compact.split('.')[2], { loose: true }))
    );
    const repeated = `{"proof":${JSON.stringify(zkp.proof)},"proof":${JSON.stringify(
      zkp.proof
    )},"pub_signals":${JSON.stringify(zkp.pub_signals)}}`;
    await expect(
      verifyIden3JwzProof(withZkpSegment(genuineCase.document, repeated), optionsFor(genuineCase))
    ).rejects.toMatchObject({ reason: 'proof_malformed' });
  });

  it('sorts a root-missing revert in errorArgs as proof_invalid, and a timeout as state_unavailable', async () => {
    const revert = {
      getGISTRootInfo: async () => {
        throw Object.assign(new Error('execution reverted'), {
          errorArgs: ['Root does not exist']
        });
      }
    };
    await expect(
      verifyIden3JwzProof(genuineCase.document, optionsFor(genuineCase, { gistRootReader: revert }))
    ).rejects.toMatchObject({ reason: 'proof_invalid' });
    const timeout = {
      getGISTRootInfo: async () => {
        throw new Error('request timeout');
      }
    };
    await expect(
      verifyIden3JwzProof(
        genuineCase.document,
        optionsFor(genuineCase, { gistRootReader: timeout })
      )
    ).rejects.toMatchObject({ reason: 'state_unavailable' });
  });

  it('sorts a revert with a bigint in errorArgs as state_unavailable', async () => {
    const revert = {
      getGISTRootInfo: async () => {
        throw Object.assign(new Error('execution reverted'), { errorArgs: [1n] });
      }
    };
    await expect(
      verifyIden3JwzProof(genuineCase.document, optionsFor(genuineCase, { gistRootReader: revert }))
    ).rejects.toMatchObject({ reason: 'state_unavailable' });
  });

  it('refuses a header segment that starts with a byte order mark', async () => {
    await expect(
      verifyIden3JwzProof(withByteOrderMark(genuineCase.document, 0), optionsFor(genuineCase))
    ).rejects.toMatchObject({ reason: 'proof_malformed' });
  });

  it('refuses a payload segment that starts with a byte order mark', async () => {
    await expect(
      verifyIden3JwzProof(withByteOrderMark(genuineCase.document, 1), optionsFor(genuineCase))
    ).rejects.toMatchObject({ reason: 'proof_hash_mismatch' });
  });

  it('refuses an invalid now and an invalid lifetime with a TypeError', async () => {
    const invalidOptions: Partial<VerifyIden3JwzProofOptions>[] = [
      { now: new Date(NaN) },
      { lifetime: { minSeconds: NaN, maxSeconds: lifetime.maxSeconds } },
      { lifetime: { minSeconds: lifetime.minSeconds, maxSeconds: NaN } },
      { lifetime: { minSeconds: lifetime.minSeconds, maxSeconds: Infinity } },
      { lifetime: { minSeconds: lifetime.maxSeconds, maxSeconds: lifetime.minSeconds } }
    ];
    for (const extra of invalidOptions) {
      await expect(
        verifyIden3JwzProof(genuineCase.document, optionsFor(genuineCase, extra))
      ).rejects.toThrow(TypeError);
    }
  });

  it('runs precheck at step 5, after the date checks', async () => {
    const refuse = () => {
      throw new Error('form');
    };
    await expect(
      verifyIden3JwzProof(genuineCase.document, optionsFor(genuineCase, { precheck: refuse }))
    ).rejects.toMatchObject({ reason: 'document_malformed' });
    const expires = Date.parse(genuineCase.expect.expires as string);
    await expect(
      verifyIden3JwzProof(
        genuineCase.document,
        optionsFor(genuineCase, { precheck: refuse, now: new Date(expires) })
      )
    ).rejects.toMatchObject({ reason: 'proof_expired' });
  });

  it('gives precheck the document without proof and the proof configuration', async () => {
    const calls: JsonDocumentObject[][] = [];
    const record = (unsecured: JsonDocumentObject, proofConfiguration: JsonDocumentObject) => {
      calls.push([unsecured, proofConfiguration]);
    };
    await verifyIden3JwzProof(genuineCase.document, optionsFor(genuineCase, { precheck: record }));
    const { proof, ...unsecured } = genuineCase.document;
    const proofOptions = Object.fromEntries(
      Object.entries(proof as JsonDocumentObject).filter(([member]) => member !== 'proofValue')
    );
    expect(calls).toEqual([[unsecured, { ...proofOptions, '@context': unsecured['@context'] }]]);
  });

  it('rejects without a verification key for the circuit', async () => {
    await expect(
      verifyIden3JwzProof(genuineCase.document, optionsFor(genuineCase, { verificationKeys: {} }))
    ).rejects.toMatchObject({ reason: 'proof_invalid' });
  });
});
