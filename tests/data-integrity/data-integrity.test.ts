import { beforeAll, describe, expect, it } from 'vitest';
import path from 'node:path';
import { DID } from '@iden3/js-iden3-core';
import {
  CircuitId,
  CredentialStatusResolverRegistry,
  CredentialStatusType,
  CredentialWallet,
  ErrStateVerificationFailed,
  FSCircuitStorage,
  IPackageManager,
  IStateStorage,
  IdentityWallet,
  JsonDocumentObject,
  ProofService,
  RHSResolver,
  RootInfo,
  base64UrlToBytes,
  byteDecoder,
  byteEncoder,
  bytesToBase64url,
  computeIden3JwzPayload,
  createIden3JwzProof,
  iden3JwzProofOptions,
  proofValueFromCompactJwz,
  verifyIden3JwzProof
} from '../../src';
import {
  MOCK_STATE_STORAGE,
  SEED_ISSUER,
  SEED_USER,
  createIdentity,
  getInMemoryDataStorage,
  getPackageMgrV3,
  registerKeyProvidersInMemoryKMS
} from '../helpers';

const MINUTE = 60 * 1000;
const LIFETIME = 14 * 24 * 60 * MINUTE;
const BYTE_ORDER_MARK = '﻿';

describe('iden3-jwz-rdfc-2026', () => {
  let did: DID;
  let otherDid: DID;
  let packageManager: IPackageManager;
  let packageManagerWith: (stateStorage: IStateStorage) => Promise<IPackageManager>;
  let document: JsonDocumentObject;
  let secured: JsonDocumentObject;
  let created: Date;
  let expires: Date;

  const proofOf = (input: JsonDocumentObject): JsonDocumentObject =>
    input.proof as JsonDocumentObject;

  const withProofValue = (proofValue: string): JsonDocumentObject => ({
    ...secured,
    proof: { ...proofOf(secured), proofValue }
  });

  const compactJwz = (): string =>
    byteDecoder.decode(base64UrlToBytes((proofOf(secured).proofValue as string).slice(1)));

  const withSegment = (index: number, change: (text: string) => string): JsonDocumentObject => {
    const segments = compactJwz().split('.');
    const text = byteDecoder.decode(base64UrlToBytes(segments[index]));
    segments[index] = bytesToBase64url(byteEncoder.encode(change(text)));
    return withProofValue(proofValueFromCompactJwz(segments.join('.')));
  };

  const replacedRootStorage = (replacedAt: Date): IStateStorage => ({
    ...MOCK_STATE_STORAGE,
    getGISTRootInfo: async (root, userId): Promise<RootInfo> => ({
      ...(await MOCK_STATE_STORAGE.getGISTRootInfo(root, userId)),
      replacedByRoot: 1n,
      replacedAtTimestamp: BigInt(Math.floor(replacedAt.getTime() / 1000))
    })
  });

  const verify = (
    input: JsonDocumentObject,
    options: {
      signer?: string;
      now?: Date;
      maxProofLifetime?: number;
      packageManager?: IPackageManager;
    } = {}
  ) =>
    verifyIden3JwzProof(input, {
      signer: did.string(),
      maxProofLifetime: LIFETIME,
      packageManager,
      ...options
    });

  beforeAll(async () => {
    const kms = registerKeyProvidersInMemoryKMS();
    const dataStorage = getInMemoryDataStorage(MOCK_STATE_STORAGE);
    const circuitStorage = new FSCircuitStorage({
      dirname: path.join(__dirname, '../proofs/testdata')
    });
    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );
    const credWallet = new CredentialWallet(dataStorage, resolvers);
    const idWallet = new IdentityWallet(kms, dataStorage, credWallet);
    const revocationOpts = {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: 'https://rhs.example.com',
      genesisPublishingDisabled: true
    };
    ({ did } = await createIdentity(idWallet, { seed: SEED_USER, revocationOpts }));
    ({ did: otherDid } = await createIdentity(idWallet, { seed: SEED_ISSUER, revocationOpts }));
    const circuits = [
      await circuitStorage.loadCircuitData(CircuitId.AuthV2),
      await circuitStorage.loadCircuitData(CircuitId.AuthV3),
      await circuitStorage.loadCircuitData(CircuitId.AuthV3_8_32)
    ];
    packageManagerWith = async (stateStorage) => {
      const proofService = new ProofService(idWallet, credWallet, circuitStorage, stateStorage);
      const prepareFunc = proofService.generateAuthInputs.bind(proofService);
      return getPackageMgrV3(
        circuits,
        [
          { circuitId: CircuitId.AuthV2, prepareFunc },
          { circuitId: CircuitId.AuthV3, prepareFunc },
          { circuitId: CircuitId.AuthV3_8_32, prepareFunc }
        ],
        proofService.verifyState.bind(proofService)
      );
    };
    packageManager = await packageManagerWith(MOCK_STATE_STORAGE);
    document = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/data-integrity/v2'],
      id: did.string(),
      controller: did.string()
    };
    created = new Date(Math.floor((Date.now() - 60 * MINUTE) / 1000) * 1000);
    expires = new Date(created.getTime() + LIFETIME);
    const proof = await createIden3JwzProof(document, {
      signer: did,
      created,
      expires,
      packageManager
    });
    secured = { ...document, proof };
  });

  it('creates a proof with the authV3-8-32 circuit and verifies it', async () => {
    expect(secured.proof).toMatchObject({
      type: 'DataIntegrityProof',
      cryptosuite: 'iden3-jwz-rdfc-2026',
      proofPurpose: 'assertionMethod',
      verificationMethod: `${did.string()}#state-info`,
      created: created.toISOString().replace('.000Z', 'Z'),
      expires: expires.toISOString().replace('.000Z', 'Z')
    });
    expect(proofOf(secured).proofValue).toMatch(/^u[A-Za-z0-9_-]+$/);
    expect(compactJwz().split('.')).toHaveLength(3);
    await expect(verify(secured)).resolves.toBeUndefined();
  });

  it('refuses a changed document', async () => {
    await expect(verify({ ...secured, controller: otherDid.string() })).rejects.toThrow('payload');
  });

  it('refuses another signer', async () => {
    await expect(verify(secured, { signer: otherDid.string() })).rejects.toThrow(
      'verificationMethod'
    );
  });

  it('refuses a proof after expires', async () => {
    await expect(verify(secured, { now: new Date(expires.getTime() + 1000) })).rejects.toThrow(
      'expired'
    );
  });

  it('refuses a proof created more than 5 minutes ahead of now', async () => {
    await expect(
      verify(secured, { now: new Date(created.getTime() - 6 * MINUTE) })
    ).rejects.toThrow('ahead');
  });

  it('refuses a header or payload segment with a byte order mark', async () => {
    await expect(verify(withSegment(0, (text) => BYTE_ORDER_MARK + text))).rejects.toThrow(
      'header segment'
    );
    await expect(verify(withSegment(1, (text) => BYTE_ORDER_MARK + text))).rejects.toThrow(
      'payload segment'
    );
  });

  it('refuses a proof whose lifetime is longer than maxProofLifetime', async () => {
    await expect(verify(secured, { maxProofLifetime: LIFETIME - 1000 })).rejects.toThrow(
      'maxProofLifetime'
    );
  });

  it('refuses a date that is not valid', async () => {
    const withDate = (name: string, value: string): JsonDocumentObject => ({
      ...secured,
      proof: { ...proofOf(secured), [name]: value }
    });
    const impossible = '2026-13-45T00:00:00Z';
    await expect(verify(withDate('created', impossible))).rejects.toThrow(
      'created must be a valid date'
    );
    await expect(verify(withDate('expires', impossible))).rejects.toThrow(
      'expires must be a valid date'
    );
  });

  it('refuses a date without Z or with a fraction', async () => {
    const withDate = (name: string, value: string): JsonDocumentObject => ({
      ...secured,
      proof: { ...proofOf(secured), [name]: value }
    });
    const [seconds] = (proofOf(secured).created as string).split('Z');
    for (const value of [seconds, `${seconds}.000Z`, seconds.slice(0, 10)]) {
      await expect(verify(withDate('created', value))).rejects.toThrow(
        'created must have the form'
      );
      await expect(verify(withDate('expires', value))).rejects.toThrow(
        'expires must have the form'
      );
    }
  });

  it('refuses a GIST root that was replaced more than 5 minutes before created', async () => {
    const accepting = await packageManagerWith(
      replacedRootStorage(new Date(created.getTime() - 4 * MINUTE))
    );
    await expect(verify(secured, { packageManager: accepting })).resolves.toBeUndefined();
    const refusing = await packageManagerWith(
      replacedRootStorage(new Date(created.getTime() - 6 * MINUTE))
    );
    await expect(verify(secured, { packageManager: refusing })).rejects.toThrow(
      ErrStateVerificationFailed
    );
  });

  it('gives an 86-character payload, and refuses a document with a proof or without @context', async () => {
    const proofOptions = iden3JwzProofOptions(did, created, expires);
    await expect(computeIden3JwzPayload(document, proofOptions)).resolves.toMatch(
      /^[A-Za-z0-9_-]{86}$/
    );
    await expect(computeIden3JwzPayload(secured, proofOptions)).rejects.toThrow('proof');
    const withoutContext = { id: did.string() };
    await expect(computeIden3JwzPayload(withoutContext, proofOptions)).rejects.toThrow('@context');
  });

  it('refuses a created or expires that is not a valid date', () => {
    const invalid = new Date(NaN);
    expect(() => iden3JwzProofOptions(did, invalid, expires)).toThrow('valid dates');
    expect(() => iden3JwzProofOptions(did, created, invalid)).toThrow('valid dates');
  });

  it('refuses expires that is not later than created', () => {
    expect(() => iden3JwzProofOptions(did, created, created)).toThrow('expires');
    expect(() => iden3JwzProofOptions(did, created, new Date(created.getTime() + 999))).toThrow(
      'expires'
    );
  });
});
