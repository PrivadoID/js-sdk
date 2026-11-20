import { beforeEach, describe, expect, it } from 'vitest';
import path from 'node:path';
import { DID } from '@iden3/js-iden3-core';
import {
  CircuitId,
  CredentialStatusResolverRegistry,
  CredentialStatusType,
  CredentialWallet,
  DocumentLoader,
  FSCircuitStorage,
  IPackageManager,
  IdentityWallet,
  ProofService,
  RHSResolver,
  createStrictDocumentLoader,
  createIden3JwzProof,
  verifyIden3JwzProof
} from '../../src';
import {
  MOCK_STATE_STORAGE,
  SEED_USER,
  createIdentity,
  getInMemoryDataStorage,
  getPackageMgrV3,
  registerKeyProvidersInMemoryKMS
} from '../helpers';
import { VECTOR_CONTEXTS } from './vectors/contexts';

describe('iden3-jwz-rdfc-2026 round trip', () => {
  let did: DID;
  let packageManager: IPackageManager;
  let circuitStorage: FSCircuitStorage;
  let documentLoader: DocumentLoader;

  beforeEach(async () => {
    const kms = registerKeyProvidersInMemoryKMS();
    const dataStorage = getInMemoryDataStorage(MOCK_STATE_STORAGE);
    circuitStorage = new FSCircuitStorage({
      dirname: path.join(__dirname, '../proofs/testdata')
    });
    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );
    const credWallet = new CredentialWallet(dataStorage, resolvers);
    const idWallet = new IdentityWallet(kms, dataStorage, credWallet);
    const proofService = new ProofService(idWallet, credWallet, circuitStorage, MOCK_STATE_STORAGE);
    ({ did } = await createIdentity(idWallet, {
      seed: SEED_USER,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: 'https://rhs.example.com',
        genesisPublishingDisabled: true
      }
    }));
    const prepareFunc = proofService.generateAuthInputs.bind(proofService);
    packageManager = await getPackageMgrV3(
      [
        await circuitStorage.loadCircuitData(CircuitId.AuthV2),
        await circuitStorage.loadCircuitData(CircuitId.AuthV3),
        await circuitStorage.loadCircuitData(CircuitId.AuthV3_8_32)
      ],
      [
        { circuitId: CircuitId.AuthV2, prepareFunc },
        { circuitId: CircuitId.AuthV3, prepareFunc },
        { circuitId: CircuitId.AuthV3_8_32, prepareFunc }
      ],
      proofService.verifyState.bind(proofService)
    );
    documentLoader = createStrictDocumentLoader(VECTOR_CONTEXTS);
  });

  it('verifies a proof that it made with the authV3-8-32 circuit', async () => {
    const document = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/data-integrity/v2'],
      id: did.string(),
      controller: did.string()
    };
    const created = new Date(Math.floor(Date.now() / 1000) * 1000);
    const expires = new Date(created.getTime() + 14 * 86400 * 1000);
    const proof = await createIden3JwzProof(document, {
      signer: did,
      created,
      expires,
      packageManager,
      documentLoader
    });
    const latest = {
      getGISTRootInfo: async (root: bigint) => ({
        root,
        replacedByRoot: 0n,
        createdAtTimestamp: 0n,
        replacedAtTimestamp: 0n,
        createdAtBlock: 0n,
        replacedAtBlock: 0n
      })
    };
    const verified = await verifyIden3JwzProof(
      { ...document, proof },
      {
        signer: did.string(),
        now: created,
        lifetime: { minSeconds: 7 * 86400, maxSeconds: 14 * 86400 },
        documentLoader,
        networks: ['polygon:amoy'],
        gistRootReader: latest,
        verificationKeys: {
          'authV3-8-32': (
            await circuitStorage.loadCircuitData(CircuitId.AuthV3_8_32)
          ).verificationKey as Uint8Array
        }
      }
    );
    expect(verified).toEqual({ created, expires });
  });
});
