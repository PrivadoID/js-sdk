import { beforeAll, describe, expect, it } from 'vitest';
import path from 'node:path';
import { DID } from '@iden3/js-iden3-core';
import { base64url } from 'rfc4648';
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
  byteDecoder,
  byteEncoder,
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
    byteDecoder.decode(
      base64url.parse((proofOf(secured).proofValue as string).slice(1), { loose: true })
    );

  const withSegment = (index: number, change: (text: string) => string): JsonDocumentObject => {
    const segments = compactJwz().split('.');
    const text = byteDecoder.decode(base64url.parse(segments[index], { loose: true }));
    segments[index] = base64url.stringify(byteEncoder.encode(change(text)), { pad: false });
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
    options: { signer?: string; now?: Date; packageManager?: IPackageManager } = {}
  ) =>
    verifyIden3JwzProof(input, {
      signer: did.string(),
      now: created,
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
    created = new Date(Math.floor(Date.now() / 1000) * 1000);
    expires = new Date(created.getTime() + 14 * 24 * 60 * MINUTE);
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

  it('refuses a proof with a date that is not valid', async () => {
    const withDate = (name: string): JsonDocumentObject => ({
      ...secured,
      proof: { ...proofOf(secured), [name]: 'tomorrow evening' }
    });
    await expect(verify(withDate('created'))).rejects.toThrow('created must be a valid date');
    await expect(verify(withDate('expires'))).rejects.toThrow('expires must be a valid date');
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

  it('refuses expires that is not later than created', () => {
    expect(() => iden3JwzProofOptions(did, created, created)).toThrow('expires');
    expect(() => iden3JwzProofOptions(did, created, new Date(created.getTime() + 999))).toThrow(
      'expires'
    );
  });
});
