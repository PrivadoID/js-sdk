/**
 * Offline environment for identities with multiple auth claims: wallets ("devices"), an in-memory
 * State contract, an in-memory issuer revocation endpoint and authV3 JWZ request / response helpers.
 *
 * Uses the authV3, stateTransition and credentialAtomicQueryV3-16-16-64 circuits from
 * tests/proofs/testdata (downloaded in CI).
 */
import path from 'path';
import { expect } from 'vitest';
import { Blockchain, DID, DidMethod, NetworkId } from '@iden3/js-iden3-core';
import { getRandomBytes } from '@iden3/js-crypto';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { Signer } from 'ethers';
import { Token, proving } from '@iden3/js-jwz';
import {
  AcceptProfile,
  AuthHandler,
  AuthorizationRequestMessage,
  AuthorizationResponseMessage,
  CircuitId,
  CredentialStatus,
  CredentialStatusResolveOptions,
  CredentialStatusResolver,
  CredentialStatusResolverRegistry,
  CredentialStatusType,
  CredentialStorage,
  CredentialWallet,
  DataPrepareHandlerFunc,
  FSCircuitStorage,
  IDataStorage,
  IPackageManager,
  Identity,
  IdentityStorage,
  IdentityWallet,
  InMemoryDataSource,
  InMemoryMerkleTreeStorage,
  KMS,
  NativeProver,
  PackageManager,
  PlainPacker,
  Profile,
  ProofService,
  RevocationStatus,
  VerificationHandlerFunc,
  W3CCredential,
  ZKPPacker,
  ZeroKnowledgeProofRequest,
  buildAccept,
  byteEncoder,
  cacheLoader,
  createAuthorizationRequestWithMessage
} from '../../../src';
import { registerKeyProvidersInMemoryKMS } from '../../helpers';
import { AcceptAuthCircuits, MediaType, ProtocolVersion } from '../../../src/iden3comm/constants';
import { InMemoryStateStorage } from './in-memory-state';

export const CIRCUITS_DIR = path.join(__dirname, '../../proofs/testdata');

export const REVOCATION_URL = 'https://issuer.example.local/v1/revocation';

export const SMT_REVOCATION = {
  type: CredentialStatusType.SparseMerkleTreeProof,
  id: REVOCATION_URL
};

// requests ask holders to authenticate with authV3
const AUTH_V3_PROFILE: AcceptProfile = {
  protocolVersion: ProtocolVersion.V1,
  env: MediaType.ZKPMessage,
  circuits: [AcceptAuthCircuits.AuthV3]
};

/**
 * Plays the role of the issuer node revocation endpoint: answers non-revocation proofs from
 * the issuer's own trees at its latest (published) state.
 */
export class InMemoryIssuerRevocationResolver implements CredentialStatusResolver {
  private readonly _issuers = new Map<string, IdentityWallet>();

  registerIssuer(did: DID, wallet: IdentityWallet) {
    this._issuers.set(did.string(), wallet);
  }

  async resolve(
    status: CredentialStatus,
    opts?: CredentialStatusResolveOptions
  ): Promise<RevocationStatus> {
    const issuer = opts?.issuerDID;
    const wallet = issuer && this._issuers.get(issuer.string());
    if (!issuer || !wallet) {
      throw new Error(`unknown issuer ${issuer?.string()}`);
    }
    const { proof, treeState } = await wallet.generateNonRevocationMtpWithNonce(
      issuer,
      BigInt(status.revocationNonce ?? 0)
    );
    return {
      mtp: proof,
      issuer: {
        state: treeState.state.hex(),
        claimsTreeRoot: treeState.claimsRoot.hex(),
        revocationTreeRoot: treeState.revocationRoot.hex(),
        rootOfRoots: treeState.rootOfRoots.hex()
      }
    };
  }
}

export type Device = {
  kms: KMS;
  storage: IDataStorage;
  credWallet: CredentialWallet;
  idWallet: IdentityWallet;
  proofService: ProofService;
  packageMgr: IPackageManager;
  authHandler: AuthHandler;
};

export type IdentityType = 'bjj' | 'eth';

export type MultiAuthEnv = Awaited<ReturnType<typeof createMultiAuthEnv>>;

export const createMultiAuthEnv = async (opts?: { documentLoader?: DocumentLoader }) => {
  const merklizeOpts = { documentLoader: opts?.documentLoader ?? cacheLoader() };
  const circuitStorage = new FSCircuitStorage({ dirname: CIRCUITS_DIR });
  const prover = new NativeProver(circuitStorage);
  const chain = await new InMemoryStateStorage(prover).init();
  const revocation = new InMemoryIssuerRevocationResolver();
  const ethSigner = {} as Signer; // the in-memory State contract doesn't need a tx signer

  // merkle trees + identity state of a multi-auth identity, replicated to every auth key holder
  const sharedTreesStorage = {
    mt: new InMemoryMerkleTreeStorage(40),
    identity: new IdentityStorage(
      new InMemoryDataSource<Identity>(),
      new InMemoryDataSource<Profile>()
    )
  };

  /** JWZ packer that proves and verifies with authV3 only. */
  const authV3PackageMgr = async (proofService: ProofService): Promise<IPackageManager> => {
    const { provingKey, wasm, verificationKey } = await circuitStorage.loadCircuitData(
      CircuitId.AuthV3
    );
    if (!provingKey || !wasm || !verificationKey) {
      throw new Error(`authV3 circuit files are missing in ${CIRCUITS_DIR}`);
    }
    const alg = proving.provingMethodGroth16AuthV3Instance.methodAlg.toString();
    const packer = new ZKPPacker(
      new Map([
        [
          alg,
          {
            dataPreparer: new DataPrepareHandlerFunc(
              proofService.generateAuthInputs.bind(proofService)
            ),
            provingKey,
            wasm
          }
        ]
      ]),
      new Map([
        [
          alg,
          {
            key: verificationKey,
            verificationFn: new VerificationHandlerFunc(proofService.verifyState.bind(proofService))
          }
        ]
      ])
    );
    const mgr = new PackageManager();
    mgr.registerPackers([packer, new PlainPacker()]);
    return mgr;
  };

  /**
   * A wallet with its own KMS. `sharedTrees` devices share the trees and identity state
   * (what every auth key holder syncs); their credential storage and keys stay their own.
   */
  const newDevice = async (deviceOpts?: { kms?: KMS; sharedTrees?: boolean }): Promise<Device> => {
    const kms = deviceOpts?.kms ?? registerKeyProvidersInMemoryKMS();
    const storage: IDataStorage = {
      credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
      identity: deviceOpts?.sharedTrees
        ? sharedTreesStorage.identity
        : new IdentityStorage(
            new InMemoryDataSource<Identity>(),
            new InMemoryDataSource<Profile>()
          ),
      mt: deviceOpts?.sharedTrees ? sharedTreesStorage.mt : new InMemoryMerkleTreeStorage(40),
      states: chain
    };
    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(CredentialStatusType.SparseMerkleTreeProof, revocation);
    const credWallet = new CredentialWallet(storage, resolvers);
    const idWallet = new IdentityWallet(kms, storage, credWallet);
    const proofService = new ProofService(idWallet, credWallet, circuitStorage, chain, {
      ...merklizeOpts,
      prover
    });
    const packageMgr = await authV3PackageMgr(proofService);
    const authHandler = new AuthHandler(packageMgr, proofService);
    return { kms, storage, credWallet, idWallet, proofService, packageMgr, authHandler };
  };

  /**
   * BJJ-based identity (genesis state from the auth claim) or Ethereum-based identity (DID from
   * a secp256k1 key; the first BJJ auth claim is added and published on creation).
   */
  const createDID = async (device: Device, type: IdentityType = 'bjj') => {
    const opts = {
      method: DidMethod.Iden3,
      blockchain: Blockchain.Polygon,
      networkId: NetworkId.Amoy,
      seed: getRandomBytes(32),
      revocationOpts: SMT_REVOCATION
    };
    const { did } =
      type === 'eth'
        ? await device.idWallet.createEthereumBasedIdentity({ ...opts, ethSigner })
        : await device.idWallet.createIdentity(opts);
    return did;
  };

  const latestTreeState = async (device: Device, did: DID) => {
    const trees = await device.idWallet.getDIDTreeModel(did);
    return {
      state: trees.state,
      claimsRoot: await trees.claimsTree.root(),
      revocationRoot: await trees.revocationTree.root(),
      rootOfRoots: await trees.rootsTree.root()
    };
  };

  const isGenesis = async (device: Device, did: DID) =>
    !!(await device.storage.identity.getIdentity(did.string())).isStateGenesis;

  /** Issuer revokes a credential (VC or auth key) and publishes its new state. */
  const revokeAndPublish = async (issuer: Device, did: DID, credential: W3CCredential) => {
    const oldTreeState = await latestTreeState(issuer, did);
    const genesis = await isGenesis(issuer, did);
    await issuer.idWallet.revokeCredential(did, credential);
    await issuer.idWallet.transitState(did, oldTreeState, genesis, ethSigner, prover);
  };

  const newRequest = (sender: DID, message: string, scope: ZeroKnowledgeProofRequest[] = []) =>
    createAuthorizationRequestWithMessage(
      'multi-auth',
      message,
      sender.string(),
      'https://verifier.example.local/callback',
      { scope, accept: buildAccept([AUTH_V3_PROFILE]) }
    );

  /** Holder answers the request with `as` as the sender DID. */
  const respond = async (holder: Device, as: DID, request: AuthorizationRequestMessage) => {
    const { token } = await holder.authHandler.handleAuthorizationRequest(
      as,
      byteEncoder.encode(JSON.stringify(request))
    );
    return token;
  };

  /** Verifier unpacks the JWZ (verifies authV3 + GIST) and every scope proof. */
  const verify = async (verifier: Device, token: string, request: AuthorizationRequestMessage) => {
    expect((await Token.parse(token)).circuitId).toBe(CircuitId.AuthV3);
    const { unpackedMessage } = await verifier.packageMgr.unpack(byteEncoder.encode(token));
    const response = unpackedMessage as AuthorizationResponseMessage;
    await verifier.authHandler.handleAuthorizationResponse(response, request);
    return response;
  };

  return {
    merklizeOpts,
    prover,
    chain,
    revocation,
    ethSigner,
    newDevice,
    createDID,
    latestTreeState,
    isGenesis,
    revokeAndPublish,
    newRequest,
    respond,
    verify
  };
};
