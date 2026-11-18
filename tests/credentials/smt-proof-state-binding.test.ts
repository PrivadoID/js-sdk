/**
 * Regression test for the Iden3SparseMerkleTreeProof state-binding fix.
 *
 * Before the fix, verifyIden3SparseMerkleTreeProof only checked that
 * proof.issuerData.state.value is published on-chain (via validateDIDDocumentAuth)
 * and that the claim is included in proof.issuerData.state.claimsTreeRoot. It never
 * checked that state.value actually decomposes into the tree roots carried in the
 * proof, i.e. state.value === poseidon(claimsTreeRoot, revocationTreeRoot, rootOfRoots).
 *
 * That gap is the same class of bug as the BJJ-signature forgery: an attacker can take
 * a real, on-chain-published state.value of a target issuer and pair it with their own
 * claimsTreeRoot (a tree they built containing a forged claim). validateDIDDocumentAuth
 * passes (the value is genuinely published), the mtp check passes (the claim is in the
 * attacker's tree), and the credential is accepted.
 *
 * The fix re-adds the value<->roots binding. This test builds a genuine SMT proof
 * (which must verify), then swaps state.value for a different "published" value while
 * keeping the original roots, and asserts verification now fails on the binding check.
 */
import {
  CredentialStorage,
  Identity,
  IdentityStorage,
  IdentityWallet,
  Profile,
  byteEncoder
} from '../../src';
import { BjjProvider, KMS, KmsKeyType } from '../../src/kms';
import { InMemoryPrivateKeyStore } from '../../src/kms/store';
import { IDataStorage, IStateStorage } from '../../src/storage/interfaces';
import { InMemoryDataSource, InMemoryMerkleTreeStorage } from '../../src/storage/memory';
import {
  CredentialRequest,
  CredentialWallet,
  CredentialStatusResolverRegistry,
  RHSResolver
} from '../../src/credentials';
import { RootInfo, StateProof } from '../../src/storage/entities/state';
import {
  CredentialStatusType,
  ProofType,
  W3CCredential,
  Iden3SparseMerkleTreeProof,
  W3CProofVerificationOptions
} from '../../src/verifiable';
import { Hash } from '@iden3/js-merkletree';
import { Blockchain, DidMethod, NetworkId } from '@iden3/js-iden3-core';
import { JsonRpcProvider } from 'ethers';
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import nock from 'nock';
import { SEED_USER, RPC_URL } from '../helpers';
import { schemaLoaderForTests } from '../mocks/schema';

const RHS_BASE = 'https://rhs.example';
const RHS_ID = RHS_BASE;

const createIdentity = (wallet: IdentityWallet, seed: Uint8Array) =>
  wallet.createIdentity({
    method: DidMethod.Iden3,
    blockchain: Blockchain.Polygon,
    networkId: NetworkId.Amoy,
    seed,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: RHS_ID
    }
  });

const RESOLVER_BASE = 'http://my-universal-resolver';
const RESOLVER_URL = `${RESOLVER_BASE}/1.0/identifiers`;

// A second, distinct hash that the mocked resolver also reports as "published". It stands
// in for any real on-chain-published state.value the attacker reuses. It is NOT equal to
// poseidon(claimsTreeRoot, revocationTreeRoot, rootOfRoots) of the genuine proof.
const OTHER_PUBLISHED_STATE = Hash.fromBigInt(
  12345678901234567890123456789012345678901234567890n
);

const mockStateStorage: IStateStorage = {
  getLatestStateById: async () => {
    throw new Error('not implemented');
  },
  getStateInfoByIdAndState: async () => {
    throw new Error('not implemented');
  },
  publishState: async () => '0x',
  publishStateGeneric: async () => '0x',
  getGISTProof: (): Promise<StateProof> =>
    Promise.resolve({
      root: 0n,
      existence: false,
      siblings: [],
      index: 0n,
      value: 0n,
      auxExistence: false,
      auxIndex: 0n,
      auxValue: 0n
    }),
  getGISTRootInfo: (): Promise<RootInfo> =>
    Promise.resolve({
      root: 0n,
      replacedByRoot: 0n,
      createdAtTimestamp: 0n,
      replacedAtTimestamp: 0n,
      createdAtBlock: 0n,
      replacedAtBlock: 0n
    }),
  getRpcProvider: (): JsonRpcProvider => new JsonRpcProvider(RPC_URL)
};

// The universal resolver is config (trusted endpoint). We mock it to report any queried
// state of the issuer DID as published on-chain, so validateDIDDocumentAuth always passes
// and verification proceeds to the value<->roots binding check that the fix added.
function mockResolverPublished(issuerDID: string) {
  nock(RESOLVER_BASE)
    .get(() => true)
    .query(true)
    .reply(200, {
      didDocument: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: issuerDID,
        verificationMethod: [
          {
            id: `${issuerDID}#stateInfo`,
            type: 'Iden3StateInfo2023',
            controller: issuerDID,
            published: true
          }
        ]
      }
    })
    .persist();
}

describe('Iden3SparseMerkleTreeProof state value must match its tree roots', () => {
  let idWallet: IdentityWallet;
  let credWallet: CredentialWallet;
  let dataStorage: IDataStorage;
  let merklizeOpts: W3CProofVerificationOptions['merklizeOptions'];

  beforeEach(() => {
    const memoryKeyStore = new InMemoryPrivateKeyStore();
    const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, memoryKeyStore);
    const kms = new KMS();
    kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

    dataStorage = {
      credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
      identity: new IdentityStorage(
        new InMemoryDataSource<Identity>(),
        new InMemoryDataSource<Profile>()
      ),
      mt: new InMemoryMerkleTreeStorage(40),
      states: mockStateStorage
    };

    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );
    credWallet = new CredentialWallet(dataStorage, resolvers);
    idWallet = new IdentityWallet(kms, dataStorage, credWallet);
    merklizeOpts = { documentLoader: schemaLoaderForTests() };
  });

  afterEach(() => nock.cleanAll());

  // Issues a credential and attaches a genuine Iden3SparseMerkleTreeProof to it, all
  // in-memory (no chain/RHS). Returns the credential and its SMT proof.
  async function issueWithSmtProof(): Promise<{
    credential: W3CCredential;
    smtProof: Iden3SparseMerkleTreeProof;
    issuerDID: string;
  }> {
    // Identity creation publishes revocation info to the RHS endpoint; mock it.
    nock(RHS_BASE)
      .post(() => true)
      .reply(200, {})
      .persist();

    const { did: userDID } = await createIdentity(idWallet, SEED_USER);
    const seedIssuer = byteEncoder.encode('seedseedseedseedseedseedseed1new');
    const { did: issuerDID, credential: issuerAuthCredential } = await createIdentity(
      idWallet,
      seedIssuer
    );
    await credWallet.save(issuerAuthCredential);

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        nonce: 1000,
        id: 'https://rhs.example/node'
      }
    };

    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);
    await credWallet.save(issuerCred);

    const res = await idWallet.addCredentialsToMerkleTree([issuerCred], issuerDID);
    const [credWithMtp] = await idWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      'mock-tx-id'
    );

    const smtProof = (credWithMtp.proof as unknown[]).find(
      (p) => (p as { type: ProofType }).type === ProofType.Iden3SparseMerkleTreeProof
    ) as Iden3SparseMerkleTreeProof;

    return { credential: credWithMtp, smtProof, issuerDID: issuerDID.string() };
  }

  it('accepts a genuine SMT proof', async () => {
    const { credential, issuerDID } = await issueWithSmtProof();
    mockResolverPublished(issuerDID);

    const isValid = await credential.verifyProof(ProofType.Iden3SparseMerkleTreeProof, RESOLVER_URL, {
      merklizeOptions: merklizeOpts
    });
    expect(isValid).to.be.true;
  });

  it('rejects an SMT proof whose state.value does not match its tree roots', async () => {
    const { credential, smtProof, issuerDID } = await issueWithSmtProof();
    mockResolverPublished(issuerDID);

    // Attacker keeps the genuine claims/revocation/roots (so the mtp inclusion check would
    // still pass) but swaps state.value for a different, separately-published state value.
    // The on-chain check passes (resolver says published), but value != poseidon(roots).
    smtProof.issuerData.state.value = OTHER_PUBLISHED_STATE;

    await expect(
      credential.verifyProof(ProofType.Iden3SparseMerkleTreeProof, RESOLVER_URL, {
        merklizeOptions: merklizeOpts
      })
    ).rejects.toThrow('issuer state value does not match its claims/revocation/roots tree roots');
  });
});
