import { IKeyProvider, KMS, KmsKeyId, KmsKeyType } from '../kms';
import {
  Blockchain,
  buildDIDType,
  BytesHelper,
  Claim,
  ClaimOptions,
  DID,
  DidMethod,
  getUnixTimestamp,
  Id,
  NetworkId,
  SchemaHash
} from '@iden3/js-iden3-core';
import {
  poseidon,
  PublicKey,
  sha256,
  Signature,
  Hex,
  getRandomBytes,
  Poseidon
} from '@iden3/js-crypto';
import { Hash, hashElems, ZERO_HASH } from '@iden3/js-merkletree';
import { generateProfileDID, subjectPositionIndex } from './common';
import * as uuid from 'uuid';
import { JSONSchema, JsonSchemaValidator, cacheLoader } from '../schema-processor';
import { IDataStorage, MerkleTreeType, Profile, UserStateTransitionInfo } from '../storage';
import {
  VerifiableConstants,
  BJJSignatureProof2021,
  MerklizedRootPosition,
  SubjectPosition,
  W3CCredential,
  MerkleTreeProofWithTreeState,
  Iden3SparseMerkleTreeProof,
  ProofType,
  CredentialStatusType,
  ProofQuery,
  CoreClaimCreationOptions
} from '../verifiable';
import {
  CredentialRequest,
  getKMSIdByAuthCredential,
  getNodesRepresentation,
  ICredentialWallet,
  ProofNode,
  PublishMode,
  pushHashesToRHS,
  TreesModel
} from '../credentials';
import { CircuitId, StateTransitionInputs, TreeState } from '../circuits';
import { buildDIDFromEthPubKey, byteEncoder, isEthereumIdentity } from '../utils';
import { Options } from '@iden3/js-jsonld-merklization';
import { Signer, TransactionReceipt } from 'ethers';
import {
  CredentialStatusPublisherRegistry,
  Iden3SmtRhsCredentialStatusPublisher
} from '../credentials/status/credential-status-publisher';
import { InputGenerator, IZKProver } from '../proof';
import { ITransactionService, TransactionService } from '../blockchain';
import { DIDDocument, JsonDocumentObject } from '../iden3comm';
import {
  DIDDocumentBuilder,
  JWK2020_CONTEXT_V1,
  Jwk2020VerificationMethodBuilder
} from '../iden3comm/utils';

/**
 * DID creation options
 * seed - seed to generate BJJ key pair
 * revocationOpts -

 * @type IdentityCreationOptions
 */
export type IdentityCreationOptions = {
  method?: string;
  blockchain?: string;
  networkId?: string;
} & AuthBJJCredentialCreationOptions;

/**
 * Options for creating profile
 * @type CreateProfileOptions
 */
export type CreateProfileOptions = {
  tags?: string[];
  didDocument?: DIDDocument;
  encryptionKeyOps?: EncryptionKeyOps;
  metadata?: JsonDocumentObject;
};

/**
 * Profile encryption creation options
 */
export type EncryptionKeyOps = {
  provider?: IKeyProvider;
  alias?: string;
};

/**
 * Options for creating Auth BJJ credential
 * seed - seed to generate BJJ key pair
 * revocationOpts
 *  nonce - explicit revocation nonce to use
 *  onChain - onchain status related option
 *      txCallback - defines how the TransactionReceipt is handled
 *      publishMode  - specifies the work of transaction polling type: sync / async / callback
 *  genesisPublishingDisabled - genesis is publishing by default. Set `true` to prevent genesis publishing
 * publicKey - BJJ public key of a key held outside of this wallet's KMS (e.g. on a delegate's device).
 *  Only honored by `addBJJAuthCredential`; when set, `seed` is ignored and no key is created in the KMS
 */
export type AuthBJJCredentialCreationOptions = {
  revocationOpts: {
    id: string;
    type: CredentialStatusType;
    nonce?: number;
    genesisPublishingDisabled?: boolean;
    onChain?: {
      txCallback?: (tx: TransactionReceipt) => Promise<void>;
      publishMode?: PublishMode;
    };
  };
  seed?: Uint8Array;
  publicKey?: PublicKey;
};

/**
 * Options for creating Ethereum based identity
 */
export type EthereumBasedIdentityCreationOptions = IdentityCreationOptions & {
  ethSigner?: Signer;
  createBjjCredential?: boolean;
};

/**
 * Options for RevocationInfoOptions.
 */
export type RevocationInfoOptions = {
  revokedNonces?: number[];
  treeModel?: TreesModel;
  rhsUrl?: string;
  onChain?: {
    txCallback?: (tx: TransactionReceipt) => Promise<void>;
    publishMode?: PublishMode;
  };
};

/**
 *  Proof creation result
 *
 * @public
 * @interface   Iden3ProofCreationResult
 */
export interface Iden3ProofCreationResult {
  credentials: W3CCredential[];
  oldTreeState: TreeState;
  newTreeState: TreeState;
}
/**
 * Interface for IdentityWallet
 * @public
 */
export interface IIdentityWallet {
  /**
   * Create Identity creates Auth BJJ credential,
   * Merkle trees for claims, revocations and root of roots,
   * adds auth BJJ credential to claims tree and generates mtp of inclusion
   * based on the resulting state it provides an identifier in DID form.
   *
   * @param {IdentityCreationOptions} opts - default is did:iden3:polygon:amoy** with generated key.
   * @returns `Promise<{ did: DID; credential: W3CCredential }>` - returns did and Auth BJJ credential
   * @public
   */
  createIdentity(opts: IdentityCreationOptions): Promise<{ did: DID; credential: W3CCredential }>;

  /**
   *  Credential wallet getter
   *
   * @returns  {ICredentialWallet}
   * @memberof IIdentityWallet
   */
  get credentialWallet(): ICredentialWallet;

  /**
   * Create Identity based in Ethereum address and it provides an identifier in DID form.
   *
   * @param {IdentityCreationOptions} opts - default is did:iden3:polygon:amoy** with generated key.
   * @returns `Promise<{ did: DID; credential: W3CCredential | undefined }>` - returns did and Auth BJJ credential
   * @public
   */
  createEthereumBasedIdentity(
    opts: EthereumBasedIdentityCreationOptions
  ): Promise<{ did: DID; credential: W3CCredential | undefined }>;

  /**
   * Creates profile based on genesis identifier
   *
   * @param {DID} did - identity to derive profile from
   * @param {number |string} nonce - unique integer number to generate a profile
   * @param {string} verifier - verifier identity/alias in a string from
   * @param {string[]} tags      - optional tag that can be assigned to profile by client
   * @returns `Promise<DID>` - profile did
   */
  createProfile(did: DID, nonce: number | string, verifier: string, tags?: string[]): Promise<DID>;

  /**
   * Creates profile based on genesis identifier
   *
   * @param {DID} did - identity to derive profile from
   * @param {number |string} nonce - unique integer number to generate a profile
   * @param {string} verifier - verifier identity/alias in a string from
   * @param {CreateProfileOptions} options - optional parameters for profile creation
   * @returns `Promise<DID>` - profile did
   */
  createProfile(
    did: DID,
    nonce: number | string,
    verifier: string,
    options?: CreateProfileOptions
  ): Promise<DID>;

  /**
   * Generates a new key
   *
   * @param {KmsKeyType} keyType - supported key type by KMS
   * @returns `Promise<KmsKeyId>` - creates a new key BJJ or ECDSA
   */
  generateKey(keyType: KmsKeyType): Promise<KmsKeyId>;

  /**
   * Issues new credential from issuer according to the claim request
   *
   * @param {DID} issuerDID - issuer identity
   * @param {CredentialRequest} req - claim request
   * @returns `Promise<W3CCredential>` - returns created W3CCredential
   */
  issueCredential(issuerDID: DID, req: CredentialRequest, opts?: Options): Promise<W3CCredential>;

  /**
   * Gets a tree model for given did that includes claims tree, revocation tree, the root of roots tree and calculated state hash
   *
   * @param {DID} did - did which trees info we need to receive
   * @returns `Promise<TreesModel>`
   * */
  getDIDTreeModel(did: DID): Promise<TreesModel>;

  /**
   * Generates proof of credential inclusion / non-inclusion to the given claims tree
   * and its root or to the current root of the Claims tree in the given Merkle tree storage.
   *
   * @param {DID} did - issuer did
   * @param {W3CCredential} credential - credential to generate mtp
   * @param {TreeState} [treeState] - tree state when to generate a proof
   * @returns `Promise<MerkleTreeProofWithTreeState>` - MerkleTreeProof and TreeState on which proof has been generated
   */
  generateCredentialMtp(
    did: DID,
    credential: W3CCredential,
    treeState?: TreeState
  ): Promise<MerkleTreeProofWithTreeState>;

  /**
   * Generates proof of core claim inclusion / non-inclusion to the given claims tree
   * and its root or to the current root of the Claims tree in the given Merkle tree storage.
   *
   * @param {DID} did - issuer did
   * @param {core.Claim} core - core claim to generate mtp
   * @param {TreeState} [treeState] - tree state when to generate a proof
   * @returns `Promise<MerkleTreeProofWithTreeState>` - MerkleTreeProof and TreeState on which proof has been generated
   */
  generateCoreClaimMtp(
    did: DID,
    coreClaim: Claim,
    treeState?: TreeState
  ): Promise<MerkleTreeProofWithTreeState>;

  /**
   * Generates proof of credential revocation nonce (with credential as a param) inclusion / non-inclusion to the given revocation tree
   * and its root or to the current root of the Revocation tree in the given Merkle tree storage.
   *
   * @param {DID} did
   * @param {W3CCredential} credential
   * @param {TreeState} [treeState]
   * @returns `Promise<MerkleTreeProofWithTreeState>` -  MerkleTreeProof and TreeState on which proof has been generated
   */
  generateNonRevocationMtp(
    did: DID,
    credential: W3CCredential,
    treeState?: TreeState
  ): Promise<MerkleTreeProofWithTreeState>;

  /**
   * Generates proof of credential revocation nonce (with revNonce as a param) inclusion / non-inclusion to the given revocation tree
   * and its root or to the current root of the Revocation tree in the given Merkle tree storage.
   *
   * @param {DID} did
   * @param {bigint} revNonce
   * @param {TreeState} [treeState]
   * @returns `Promise<MerkleTreeProofWithTreeState>` -  MerkleTreeProof and TreeState on which proof has been generated
   */
  generateNonRevocationMtpWithNonce(
    did: DID,
    revNonce: bigint,
    treeState?: TreeState
  ): Promise<MerkleTreeProofWithTreeState>;

  /**
   * Signs a payload of arbitrary size with an Auth BJJ Credential that identifies a key for signing.
   *
   * @param {Uint8Array} payload
   * @param {W3CCredential} credential - Auth BJJ Credential
   * @returns `Promise<Signature>`-  the signature object with R8 and S params
   */
  sign(payload: Uint8Array, credential: W3CCredential): Promise<Signature>;

  /**
   * Signs a big integer with an Auth BJJ Credential that identifies a key for signing.
   *
   *
   * @param {bigint} payload - big number in Field
   * @param {W3CCredential} credential - Auth BJJ credential
   * @returns `Promise<Signature>` - the signature object with R8 and S params
   */
  signChallenge(payload: bigint, credential: W3CCredential): Promise<Signature>;

  /**
   *
   *
   * @param {DID} issuerDID  - identifier of the issuer
   * @param {W3CCredential} credential - credential to revoke
   * @returns `Promise<number>` a revocation nonce of credential
   */
  revokeCredential(issuerDID: DID, credential: W3CCredential): Promise<number>;

  /**
   * Generate Iden3SparseMerkleTree proof of inclusion to issuer state of specific credentials
   *
   * @param {DID} issuerDID - issuer did
   * @param {W3CCredential[]} credentials - list of verifiable credentials to generate a proof
   * @param {string} txId - transaction hash in which state transition has been done
   * @param {number} [blockNumber] - block number in which state transition has been done
   * @param {number} [blockTimestamp] - block timestamp in which state transition has been done
   * @returns `Promise<W3CCredential[]>` credentials with an Iden3SparseMerkleTreeProof
   */
  generateIden3SparseMerkleTreeProof(
    issuerDID: DID,
    credentials: W3CCredential[],
    txId: string,
    blockNumber?: number,
    blockTimestamp?: number
  ): Promise<W3CCredential[]>;

  /**
   * Adds verifiable credentials to issuer Claims Merkle tree
   *
   * @param {W3CCredential[]} credentials - credentials to include in the claims tree
   * @param {DID} issuerDID - issuer did
   * @returns `Promise<Iden3ProofCreationResult>`- old tree state and tree state with included credentials
   */
  addCredentialsToMerkleTree(
    credentials: W3CCredential[],
    issuerDID: DID
  ): Promise<Iden3ProofCreationResult>;

  /**
   * Publishes issuer state to the reverse hash service by given URL
   *
   * @deprecated use publishRevocationInfoByCredentialStatusType instead with the same arguments in opts
   * @param {DID} issuerDID - issuer did
   * @param {string} rhsURL - reverse hash service URL
   * @param {number[]} [revokedNonces] - revoked nonces for the period from the last published
   * @returns `Promise<void>`
   */
  publishStateToRHS(
    issuerDID: DID,
    rhsURL: string,
    revokedNonces?: number[],
    opts?: object
  ): Promise<void>;

  /**
   * Publishes specific state to the reverse hash service by given URL
   * @deprecated use publishRevocationInfoByCredentialStatusType instead with the same arguments in opts
   * @param {TreesModel} treeModel - trees model to publish
   * @param {string} rhsURL - reverse hash service URL
   * @param {number[]} [revokedNonces] - revoked nonces for the period from the last published
   * @returns `Promise<void>`
   */
  publishSpecificStateToRHS(
    treeModel: TreesModel,
    rhsURL: string,
    revokedNonces?: number[],
    opts?: object
  ): Promise<void>;

  /**
   * Publishes revocation info by credential status predefined publishers
   *
   * @param {(RevocationInfoOptions)} opts
   * @returns {Promise<void>}
   * @memberof IIdentityWallet
   */
  publishRevocationInfoByCredentialStatusType(
    issuerDID: DID,
    credentialStatusType: CredentialStatusType,
    opts?: RevocationInfoOptions
  ): Promise<void>;

  /**
   * Extracts core claim from signature or merkle tree proof. If both proof persists core claim must be the same
   *
   * @public
   * @param {W3CCredential} credential - credential to extract core claim
   * @returns `{Promise<Claim>}`
   */
  getCoreClaimFromCredential(credential: W3CCredential): Promise<Claim>;

  /**
   *
   * gets profile identity by genesis identifiers
   *
   * @param {DID} did - genesis identifier from which profile has been derived
   * @returns `{Promise<Profile[]>}`
   */
  getProfilesByDID(did: DID): Promise<Profile[]>;

  /**
   *
   * gets profile nonce by it's id. if profile is genesis identifier - 0 is returned
   *
   * @param {DID} did -  profile that has been derived or genesis identity
   * @returns `{Promise<{nonce:number, genesisIdentifier: DID}>}`
   */
  getGenesisDIDMetadata(did: DID): Promise<{ nonce: number | string; genesisDID: DID }>;

  /**
   *
   * find all credentials that belong to any profile or genesis identity for the given did
   *
   * @param {DID} did -  profile that has been derived or genesis identity
   * @returns `{Promise<W3CCredential[]>}`
   */
  findOwnedCredentialsByDID(did: DID, query: ProofQuery): Promise<W3CCredential[]>;
  /**
   *
   * gets profile identity by verifier
   * @deprecated The method should not be used. It returns only one profile per verifier, which can potentially restrict business use cases
   * @param {string} verifier -  identifier of the verifier
   * @returns `{Promise<Profile>}`
   */
  getProfileByVerifier(verifier: string): Promise<Profile | undefined>;

  /**
   * gets profile by verifiers
   *
   * @param {string} verifier - verifier to which profile has been shared
   * @param {string} tags - optional, tags to filter profile entry
   * @returns `{Promise<Profile[]>}`
   */
  getProfilesByVerifier(verifier: string, tags?: string[]): Promise<Profile[]>;

  /**
   *
   * updates latest identity state in storage with given state or latest from the trees.
   *
   * @param {DID} issuerDID -  identifier of the issuer
   * @param {boolean} published - if states is published onchain
   * @param {TreeState} treeState -  contains state to upgrade
   * @returns `{Promise<void>}`
   */
  updateIdentityState(issuerDID: DID, published: boolean, treeState?: TreeState): Promise<void>;

  /**
   *
   * gets actual auth credential with proofs for provided tree state or latest from the trees.
   *
   * @param {DID} issuerDID -  identifier of the issuer
   * @param {TreeState} treeStateInfo -  optional, state for retrieval
   * @returns `{Promise<{
      authCredential: W3CCredential;
      incProof: MerkleTreeProofWithTreeState;
      nonRevProof: MerkleTreeProofWithTreeState;
    }>}`
   */
  getActualAuthCredential(
    did: DID,
    treeStateInfo?: TreeState
  ): Promise<{
    authCredential: W3CCredential;
    incProof: MerkleTreeProofWithTreeState;
    nonRevProof: MerkleTreeProofWithTreeState;
  }>;

  /**
   * Transit state for the identity with the given DID
   *
   * @param {DID} did - identifier of the user
   * @param {TreeState} oldTreeState - old state of the user
   * @param {boolean} isOldStateGenesis  - if the old state is genesis
   * @param {IStateStorage} stateStorage - storage to save the new state
   * @param {Signer} ethSigner - signer to sign the transaction
   */
  transitState(
    did: DID,
    oldTreeState: TreeState,
    isOldStateGenesis: boolean,
    ethSigner: Signer,
    prover?: IZKProver
  ): Promise<string>;

  /**
   * Add BJJ credential and transit state
   *
   * @param {DID} did - identifier of the user
   * @param {TreeState} oldTreeState - old tree state of the user
   * @param {boolean} isOldTreeState - if the old state is genesis
   * @param {Signer} ethSigner - signer to sign the transaction
   * @param {AuthBJJCredentialCreationOptions} opts - additional options
   */
  addBJJAuthCredential(
    did: DID,
    oldTreeState: TreeState,
    isOldTreeStateGenesis: boolean,
    ethSigner: Signer,
    opts?: AuthBJJCredentialCreationOptions
  ): Promise<W3CCredential>;
}

/**
 * @public
 * Wallet instance to manage the digital identity based on iden3 protocol
 * allows to: create identity/profile, sign payloads (bigint / bytes), generate keys,
 * generate Merkle tree proofs of inclusion / non-inclusion to Merkle trees, issue credentials with a BJJSignature and Iden3SparseMerkleTree Proofs,
 * revoke credentials, add credentials to Merkle trees, push states to reverse hash service
 *
 *
 * @class IdentityWallet - class
 * @implements implements IIdentityWallet interface
 */
export class IdentityWallet implements IIdentityWallet {
  private readonly _credentialStatusPublisherRegistry: CredentialStatusPublisherRegistry;
  private readonly _inputsGenerator: InputGenerator;
  private readonly _transactionService: ITransactionService;

  /**
   * Constructs a new instance of the `IdentityWallet` class
   *
   * @param {KMS} _kms - Key Management System that allows signing data with BJJ key
   * @param {IDataStorage} _storage - data storage to access credential / identity / Merkle tree data
   * @param {ICredentialWallet} _credentialWallet - credential wallet instance to quickly access credential CRUD functionality
   * @public
   */
  public constructor(
    private readonly _kms: KMS,
    private readonly _storage: IDataStorage,
    private readonly _credentialWallet: ICredentialWallet,
    private readonly _opts?: {
      credentialStatusPublisherRegistry?: CredentialStatusPublisherRegistry;
    }
  ) {
    this._credentialStatusPublisherRegistry = this.getCredentialStatusPublisherRegistry(_opts);
    this._inputsGenerator = new InputGenerator(this, _credentialWallet, _storage.states);
    this._transactionService = new TransactionService(_storage.states.getRpcProvider());
  }

  get credentialWallet(): ICredentialWallet {
    return this._credentialWallet;
  }

  private getCredentialStatusPublisherRegistry(
    _opts:
      | { credentialStatusPublisherRegistry?: CredentialStatusPublisherRegistry | undefined }
      | undefined
  ): CredentialStatusPublisherRegistry {
    if (!_opts?.credentialStatusPublisherRegistry) {
      const registry = new CredentialStatusPublisherRegistry();
      const emptyPublisher = { publish: () => Promise.resolve() };
      registry.register(
        CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        new Iden3SmtRhsCredentialStatusPublisher()
      );
      registry.register(CredentialStatusType.SparseMerkleTreeProof, emptyPublisher);
      registry.register(CredentialStatusType.Iden3commRevocationStatusV1, emptyPublisher);
      return registry;
    } else {
      return this._opts?.credentialStatusPublisherRegistry as CredentialStatusPublisherRegistry;
    }
  }

  private async createAuthCoreClaim(
    revNonce: number,
    seed: Uint8Array
  ): Promise<{ authClaim: Claim; pubKey: PublicKey }> {
    const keyId = await this._kms.createKeyFromSeed(KmsKeyType.BabyJubJub, seed);
    const pubKeyHex = await this._kms.publicKey(keyId);
    const pubKey = PublicKey.newFromHex(pubKeyHex);

    return this.createAuthCoreClaimFromPublicKey(revNonce, pubKey);
  }

  private createAuthCoreClaimFromPublicKey(
    revNonce: number,
    pubKey: PublicKey
  ): { authClaim: Claim; pubKey: PublicKey } {
    const schemaHash = SchemaHash.authSchemaHash;

    const authClaim = Claim.newClaim(
      schemaHash,
      ClaimOptions.withIndexDataInts(pubKey.p[0], pubKey.p[1]),
      ClaimOptions.withRevocationNonce(BigInt(0))
    );
    authClaim.setRevocationNonce(BigInt(revNonce));

    return { authClaim, pubKey };
  }

  private async createAuthBJJCredential(
    did: DID,
    pubKey: PublicKey,
    authClaim: Claim,
    currentState: Hash,
    revocationOpts: { id: string; type: CredentialStatusType }
  ): Promise<W3CCredential> {
    const authData = authClaim.getExpirationDate();
    const expiration = authData ? getUnixTimestamp(authData) : 0;

    const request: CredentialRequest = {
      credentialSchema: VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSON_URL,
      type: VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_TYPE,
      credentialSubject: {
        x: pubKey.p[0].toString(),
        y: pubKey.p[1].toString()
      },
      subjectPosition: subjectPositionIndex(authClaim.getIdPosition()),
      version: 0,
      expiration,
      revocationOpts: {
        nonce: Number(authClaim.getRevocationNonce()),
        id: revocationOpts.id.replace(/\/$/, ''),
        type: revocationOpts.type,
        issuerState: currentState.hex()
      }
    };

    // Check if has already an auth credential
    const authCredentials = await this._credentialWallet.getAllAuthBJJCredentials(did);

    let credential: W3CCredential = new W3CCredential();
    if (authCredentials.length === 0) {
      const schema = JSON.parse(VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSON);
      try {
        credential = this._credentialWallet.createCredential(did, request, schema);
      } catch (e) {
        throw new Error(`Error create w3c credential ${(e as Error).message}`);
      }
    } else {
      // credential with sigProof signed with previous auth bjj credential
      credential = await this.issueCredential(did, request);
    }
    return credential;
  }

  /**
   * {@inheritDoc IIdentityWallet.createIdentity}
   */
  async createIdentity(
    opts: IdentityCreationOptions
  ): Promise<{ did: DID; credential: W3CCredential }> {
    const tmpIdentifier = opts.seed ? uuid.v5(Hex.encode(sha256(opts.seed)), uuid.NIL) : uuid.v4();
    opts.seed = opts.seed ?? getRandomBytes(32);

    await this._storage.mt.createIdentityMerkleTrees(tmpIdentifier);

    const revNonce = opts.revocationOpts.nonce ?? 0;

    const { authClaim, pubKey } = await this.createAuthCoreClaim(revNonce, opts.seed);

    const { hi, hv } = authClaim.hiHv();
    await this._storage.mt.addToMerkleTree(tmpIdentifier, MerkleTreeType.Claims, hi, hv);

    const claimsTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
      tmpIdentifier,
      MerkleTreeType.Claims
    );

    const ctr = await claimsTree.root();

    const currentState = hashElems([ctr.bigInt(), ZERO_HASH.bigInt(), ZERO_HASH.bigInt()]);

    const didType = buildDIDType(
      opts.method || DidMethod.Iden3,
      opts.blockchain || Blockchain.Polygon,
      opts.networkId || NetworkId.Amoy
    );
    const identifier = Id.idGenesisFromIdenState(didType, currentState.bigInt());
    const did = DID.parseFromId(identifier);

    await this._storage.mt.bindMerkleTreeToNewIdentifier(tmpIdentifier, did.string());

    const oldTreeState = {
      revocationRoot: ZERO_HASH,
      claimsRoot: ctr,
      state: currentState,
      rootOfRoots: ZERO_HASH
    };

    const identity = await this._storage.identity.getIdentity(did.string());
    if (!identity) {
      await this._storage.identity.saveIdentity({
        did: did.string(),
        state: currentState,
        isStatePublished: false,
        isStateGenesis: true
      });
    }

    // check whether we have auth credential, if not - create a new one
    const credentials = await this._credentialWallet.findByQuery({
      credentialSubject: {
        x: {
          $eq: pubKey.p[0].toString()
        },
        y: {
          $eq: pubKey.p[1].toString()
        }
      },
      allowedIssuers: [did.string()]
    });

    // if credential exists with the same credential status type we return this credential
    if (
      credentials.length === 1 &&
      credentials[0].credentialStatus.type === opts.revocationOpts.type
    ) {
      return {
        did,
        credential: credentials[0]
      };
    }

    // otherwise something is already wrong with storage as it has more than 1 credential in it or credential status type of existing credential is different from what user provides - We should remove everything and create new credential.
    // in this way credential status of auth credential can be upgraded
    for (let i = 0; i < credentials.length; i++) {
      await this._credentialWallet.remove(credentials[i].id);
    }

    // otherwise  we create a new credential
    const credential = await this.createAuthBJJCredential(
      did,
      pubKey,
      authClaim,
      currentState,
      opts.revocationOpts
    );

    const index = authClaim.hIndex();
    const { proof } = await claimsTree.generateProof(index, ctr);

    const mtpProof: Iden3SparseMerkleTreeProof = new Iden3SparseMerkleTreeProof({
      mtp: proof,
      issuerData: {
        id: did,
        state: {
          rootOfRoots: oldTreeState.rootOfRoots,
          revocationTreeRoot: oldTreeState.revocationRoot,
          claimsTreeRoot: ctr,
          value: currentState
        }
      },
      coreClaim: authClaim
    });

    credential.proof = [mtpProof];

    // only if user specified that genesis state publishing is not needed we won't do this.
    if (!opts.revocationOpts.genesisPublishingDisabled) {
      await this.publishRevocationInfoByCredentialStatusType(did, opts.revocationOpts.type, {
        rhsUrl: opts.revocationOpts.id,
        onChain: opts.revocationOpts.onChain
      });
    }

    await this._credentialWallet.save(credential);

    return {
      did,
      credential
    };
  }

  /**
   * {@inheritDoc IIdentityWallet.createEthereumBasedIdentity}
   */
  async createEthereumBasedIdentity(
    opts: EthereumBasedIdentityCreationOptions
  ): Promise<{ did: DID; credential: W3CCredential | undefined }> {
    opts.seed = opts.seed ?? getRandomBytes(32);
    opts.createBjjCredential = opts.createBjjCredential ?? true;

    let credential;
    const ethSigner = opts.ethSigner;

    if (opts.createBjjCredential && !ethSigner) {
      throw new Error(VerifiableConstants.ERRORS.ID_WALLET_SIGNER_IS_REQUIRED);
    }

    const currentState = ZERO_HASH; // In Ethereum identities we don't have an initial state with the auth credential

    const didType = buildDIDType(
      opts.method || DidMethod.Iden3,
      opts.blockchain || Blockchain.Polygon,
      opts.networkId || NetworkId.Amoy
    );

    const keyIdEth = await this._kms.createKeyFromSeed(KmsKeyType.Secp256k1, opts.seed);
    const pubKeyHexEth = (await this._kms.publicKey(keyIdEth)).slice(2); // 04 + x + y (uncompressed key)
    const did = buildDIDFromEthPubKey(didType, pubKeyHexEth);

    await this._storage.mt.createIdentityMerkleTrees(did.string());

    await this._storage.identity.saveIdentity({
      did: did.string(),
      state: currentState,
      isStatePublished: false,
      isStateGenesis: true
    });

    if (opts.createBjjCredential && ethSigner) {
      // Old tree state genesis state
      const oldTreeState: TreeState = {
        revocationRoot: ZERO_HASH,
        claimsRoot: ZERO_HASH,
        state: currentState,
        rootOfRoots: ZERO_HASH
      };

      credential = await this.addBJJAuthCredential(did, oldTreeState, true, ethSigner, opts);
    }

    return {
      did,
      credential
    };
  }

  /** {@inheritDoc IIdentityWallet.getGenesisDIDMetadata} */
  async getGenesisDIDMetadata(did: DID): Promise<{ nonce: number | string; genesisDID: DID }> {
    // check if it is a genesis identity
    const identity = await this._storage.identity.getIdentity(did.string());

    if (identity) {
      return { nonce: 0, genesisDID: DID.parse(identity.did) };
    }
    const profile = await this._storage.identity.getProfileById(did.string());

    if (!profile) {
      throw new Error(VerifiableConstants.ERRORS.ID_WALLET_PROFILE_OR_IDENTITY_NOT_FOUND);
    }
    return { nonce: profile.nonce, genesisDID: DID.parse(profile.genesisIdentifier) };
  }

  /** {@inheritDoc IIdentityWallet.createProfile} */
  async createProfile(
    did: DID,
    nonce: number | string,
    verifier: string,
    tagsOrOptions?: string[] | CreateProfileOptions
  ): Promise<DID> {
    const profileDID = generateProfileDID(did, nonce);
    const isArray = Array.isArray(tagsOrOptions);
    const tags = isArray ? tagsOrOptions : tagsOrOptions?.tags;
    const metadata = !isArray ? tagsOrOptions?.metadata : undefined;

    const { didDocument, encryptionKeyOps } = (isArray ? {} : tagsOrOptions ?? {}) as {
      didDocument?: DIDDocument;
      encryptionKeyOps?: EncryptionKeyOps;
    };

    const identityProfiles = await this._storage.identity.getProfilesByGenesisIdentifier(
      did.string()
    );

    const profilesForTagAndVerifier = await this._storage.identity.getProfilesByVerifier(
      verifier,
      tags
    );
    if (profilesForTagAndVerifier.length) {
      throw new Error(VerifiableConstants.ERRORS.ID_WALLET_PROFILE_ALREADY_EXISTS_VERIFIER_TAGS);
    }

    const existingProfileWithNonce = identityProfiles.find((p) => p.nonce == nonce);
    if (existingProfileWithNonce) {
      throw new Error(VerifiableConstants.ERRORS.ID_WALLET_PROFILE_ALREADY_EXISTS);
    }

    let did_doc = didDocument;
    if (encryptionKeyOps?.provider) {
      const vmBuilder = new Jwk2020VerificationMethodBuilder(encryptionKeyOps.provider, {
        alias: encryptionKeyOps.alias
      });
      if (!did_doc) {
        did_doc = (
          await new DIDDocumentBuilder(profileDID.string()).addVerificationMethod(
            vmBuilder,
            JWK2020_CONTEXT_V1
          )
        ).build();
      } else {
        const vm = await vmBuilder.build(profileDID.string());
        const contextArr = [did_doc['@context']]
          .flat()
          .filter((c) => typeof c === 'string') as string[];
        did_doc = {
          ...did_doc,
          verificationMethod: [...(did_doc.verificationMethod ?? []), vm],
          '@context': [...new Set([...contextArr, JWK2020_CONTEXT_V1])]
        };
      }
    }

    await this._storage.identity.saveProfile({
      id: profileDID.string(),
      nonce,
      genesisIdentifier: did.string(),
      verifier,
      tags,
      did_doc,
      metadata
    });

    return profileDID;
  }

  /**
   *
   * gets profile identity by genesis identifiers
   *
   * @param {string} genesisIdentifier - genesis identifier from which profile has been derived
   * @returns `{Promise<Profile[]>}`
   */
  async getProfilesByDID(did: DID): Promise<Profile[]> {
    return this._storage.identity.getProfilesByGenesisIdentifier(did.string());
  }
  /** {@inheritDoc IIdentityWallet.generateKey} */
  async generateKey(keyType: KmsKeyType): Promise<KmsKeyId> {
    const key = await this._kms.createKeyFromSeed(keyType, getRandomBytes(32));
    return key;
  }
  /**
   * @deprecated The method should not be used. It returns only one profile per verifier, which can potentially restrict business use cases
   * {@inheritDoc IIdentityWallet.getProfileByVerifier}
   */
  async getProfileByVerifier(verifier: string): Promise<Profile | undefined> {
    return this._storage.identity.getProfileByVerifier(verifier);
  }

  /** {@inheritDoc IIdentityWallet.getProfilesByVerifier} */
  async getProfilesByVerifier(verifier: string, tags?: string[]): Promise<Profile[]> {
    return this._storage.identity.getProfilesByVerifier(verifier, tags);
  }

  /** {@inheritDoc IIdentityWallet.getDIDTreeModel} */
  async getDIDTreeModel(did: DID): Promise<TreesModel> {
    const didStr = did.string();
    const claimsTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
      didStr,
      MerkleTreeType.Claims
    );
    const revocationTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
      didStr,
      MerkleTreeType.Revocations
    );
    const rootsTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
      didStr,
      MerkleTreeType.Roots
    );
    const state = hashElems([
      (await claimsTree.root()).bigInt(),
      (await revocationTree.root()).bigInt(),
      (await rootsTree.root()).bigInt()
    ]);

    return {
      state,
      claimsTree,
      revocationTree,
      rootsTree
    };
  }

  /** {@inheritDoc IIdentityWallet.generateClaimMtp} */
  async generateCredentialMtp(
    did: DID,
    credential: W3CCredential,
    treeState?: TreeState
  ): Promise<MerkleTreeProofWithTreeState> {
    const coreClaim = await this.getCoreClaimFromCredential(credential);
    return this.generateCoreClaimMtp(did, coreClaim, treeState);
  }

  /** {@inheritDoc IIdentityWallet.generateClaimMtp} */
  async generateCoreClaimMtp(
    did: DID,
    coreClaim: Claim,
    treeState?: TreeState
  ): Promise<MerkleTreeProofWithTreeState> {
    const treesModel = await this.getDIDTreeModel(did);

    const claimsTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
      did.string(),
      MerkleTreeType.Claims
    );

    const claimsRoot = await treesModel.claimsTree.root();
    const rootOfRoots = await treesModel.rootsTree.root();
    const revocationRoot = await treesModel.revocationTree.root();
    const { proof } = await claimsTree.generateProof(
      coreClaim.hIndex(),
      treeState ? treeState.claimsRoot : claimsRoot
    );

    return {
      proof,
      treeState: treeState ?? {
        state: treesModel.state,
        claimsRoot,
        rootOfRoots,
        revocationRoot
      }
    };
  }

  /** {@inheritDoc IIdentityWallet.generateNonRevocationMtp} */
  async generateNonRevocationMtp(
    did: DID,
    credential: W3CCredential,
    treeState?: TreeState
  ): Promise<MerkleTreeProofWithTreeState> {
    const coreClaim = await this.getCoreClaimFromCredential(credential);

    const revNonce = coreClaim.getRevocationNonce();
    return this.generateNonRevocationMtpWithNonce(did, revNonce, treeState);
  }

  /** {@inheritDoc IIdentityWallet.generateNonRevocationMtpWithNonce} */
  async generateNonRevocationMtpWithNonce(
    did: DID,
    revNonce: bigint,
    treeState?: TreeState
  ): Promise<MerkleTreeProofWithTreeState> {
    const treesModel = await this.getDIDTreeModel(did);

    const revocationTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
      did.string(),
      MerkleTreeType.Revocations
    );

    const claimsRoot = await treesModel.claimsTree.root();
    const rootOfRoots = await treesModel.rootsTree.root();
    const revocationRoot = await treesModel.revocationTree.root();
    const { proof } = await revocationTree.generateProof(
      revNonce,
      treeState ? treeState.revocationRoot : revocationRoot
    );

    return {
      proof,
      treeState: treeState ?? {
        state: treesModel.state,
        claimsRoot,
        rootOfRoots,
        revocationRoot
      }
    };
  }

  /** {@inheritDoc IIdentityWallet.sign} */
  async sign(message: Uint8Array, credential: W3CCredential): Promise<Signature> {
    const keyKMSId = getKMSIdByAuthCredential(credential);
    const payload = poseidon.hashBytes(message);

    const signature = await this._kms.sign(keyKMSId, BytesHelper.intToBytes(payload));

    return Signature.newFromCompressed(signature);
  }

  /** {@inheritDoc IIdentityWallet.signChallenge} */
  async signChallenge(challenge: bigint, credential: W3CCredential): Promise<Signature> {
    const keyKMSId = getKMSIdByAuthCredential(credential);

    const signature = await this._kms.sign(keyKMSId, BytesHelper.intToBytes(challenge));

    return Signature.newFromCompressed(signature);
  }

  /** {@inheritDoc IIdentityWallet.issueCredential} */
  async issueCredential(
    issuerDID: DID,
    req: CredentialRequest,
    opts?: Options
  ): Promise<W3CCredential> {
    req.revocationOpts.id = req.revocationOpts.id.replace(/\/$/, '');

    let schema: object;

    const loader = opts?.documentLoader ?? cacheLoader(opts);
    try {
      schema = (await loader(req.credentialSchema)).document;
    } catch (e) {
      throw new Error(`can't load credential schema ${req.credentialSchema}`);
    }

    const jsonSchema = schema as JSONSchema;
    let credential: W3CCredential = new W3CCredential();

    const issuerRoots = await this.getDIDTreeModel(issuerDID);
    req.revocationOpts.issuerState = issuerRoots.state.hex();

    req.revocationOpts.nonce =
      typeof req.revocationOpts.nonce === 'number'
        ? req.revocationOpts.nonce
        : new DataView(getRandomBytes(16).buffer).getUint32(0, false);

    req.subjectPosition = req.subjectPosition ?? SubjectPosition.Index;

    try {
      credential = this._credentialWallet.createCredential(issuerDID, req, jsonSchema);

      const encodedCred = byteEncoder.encode(JSON.stringify(credential));
      const encodedSchema = byteEncoder.encode(JSON.stringify(schema));

      await new JsonSchemaValidator().validate(encodedCred, encodedSchema);
    } catch (e) {
      throw new Error(`Error create w3c credential ${(e as Error).message}`);
    }

    const { authCredential: issuerAuthBJJCredential } = await this.getActualAuthCredential(
      issuerDID
    );

    const coreClaimOpts: CoreClaimCreationOptions = {
      revNonce: req.revocationOpts.nonce,
      subjectPosition: req.subjectPosition,
      merklizedRootPosition: req.merklizedRootPosition ?? MerklizedRootPosition.None,
      updatable: false,
      version: 0,
      merklizeOpts: { ...opts, documentLoader: loader }
    };

    const coreClaim = await credential.toCoreClaim(coreClaimOpts);

    const { hi, hv } = coreClaim.hiHv();

    const coreClaimHash = poseidon.hash([hi, hv]);

    const signature = await this.signChallenge(coreClaimHash, issuerAuthBJJCredential);

    if (!issuerAuthBJJCredential.proof) {
      throw new Error(
        VerifiableConstants.ERRORS.ID_WALLET_ISSUER_AUTH_BJJ_CRED_MUST_HAVE_ANY_PROOF
      );
    }

    const mtpAuthBJJProof = issuerAuthBJJCredential.getIden3SparseMerkleTreeProof();
    if (!mtpAuthBJJProof) {
      throw new Error(
        VerifiableConstants.ERRORS.ID_WALLET_ISSUER_AUTH_BJJ_CRED_MUST_HAVE_MTP_PROOF
      );
    }

    const sigProof = new BJJSignatureProof2021({
      issuerData: {
        id: issuerDID,
        state: mtpAuthBJJProof.issuerData.state,
        authCoreClaim: mtpAuthBJJProof.coreClaim,
        mtp: mtpAuthBJJProof.mtp,
        credentialStatus: issuerAuthBJJCredential.credentialStatus
      },
      coreClaim,
      signature
    });
    credential.proof = [sigProof];

    return credential;
  }

  /** {@inheritDoc IIdentityWallet.getActualAuthCredential} */
  async getActualAuthCredential(
    did: DID,
    treeStateInfo?: TreeState
  ): Promise<{
    authCredential: W3CCredential;
    incProof: MerkleTreeProofWithTreeState;
    nonRevProof: MerkleTreeProofWithTreeState;
  }> {
    const authCredentials = await this._credentialWallet.getAllAuthBJJCredentials(did);
    for (let i = 0; i < authCredentials.length; i++) {
      // an identity may have auth keys held by other wallets (e.g. delegates of an organization),
      // only the ones this wallet can sign with are usable
      if (!(await this.hasAuthKey(authCredentials[i]))) {
        continue;
      }

      const incProof = await this.generateCredentialMtp(did, authCredentials[i], treeStateInfo);

      if (!incProof.proof.existence) {
        continue;
      }

      const nonRevProof = await this.generateNonRevocationMtp(
        did,
        authCredentials[i],
        treeStateInfo
      );

      if (!nonRevProof.proof.existence) {
        return {
          authCredential: authCredentials[i],
          incProof,
          nonRevProof
        };
      }
    }

    throw new Error(VerifiableConstants.ERRORS.NO_AUTH_CRED_FOUND);
  }

  private async hasAuthKey(credential: W3CCredential): Promise<boolean> {
    try {
      await this._kms.publicKey(getKMSIdByAuthCredential(credential));
      return true;
    } catch {
      return false;
    }
  }

  /** {@inheritDoc IIdentityWallet.revokeCredential} */
  async revokeCredential(issuerDID: DID, credential: W3CCredential): Promise<number> {
    const issuerTree = await this.getDIDTreeModel(issuerDID);

    const coreClaim = await this.getCoreClaimFromCredential(credential);

    if (!coreClaim) {
      throw new Error(VerifiableConstants.ERRORS.ID_WALLET_CORE_CLAIM_REQUIRED_IN_ANY_PROOF);
    }
    const nonce = coreClaim.getRevocationNonce();

    await issuerTree.revocationTree.add(nonce, BigInt(0));

    return Number(BigInt.asUintN(64, nonce));
  }

  /** {@inheritDoc IIdentityWallet.addCredentialsToMerkleTree} */
  async addCredentialsToMerkleTree(
    credentials: W3CCredential[],
    issuerDID: DID
  ): Promise<Iden3ProofCreationResult> {
    const oldIssuerTree = await this.getDIDTreeModel(issuerDID);
    let claimsRoot = await oldIssuerTree.claimsTree.root();
    let rootOfRoots = await oldIssuerTree.rootsTree.root();
    let revocationRoot = await oldIssuerTree.revocationTree.root();
    const oldTreeState: TreeState = {
      state: oldIssuerTree.state,
      claimsRoot,
      revocationRoot,
      rootOfRoots
    };

    for (let index = 0; index < credentials.length; index++) {
      const credential = credentials[index];

      // credential must have a bjj signature proof
      const coreClaim = credential.getCoreClaimFromProof(ProofType.BJJSignature);

      if (!coreClaim) {
        throw new Error(VerifiableConstants.ERRORS.ID_WALLET_CORE_CLAIM_REQUIRED_IN_SIG_PROOF);
      }

      await this._storage.mt.addToMerkleTree(
        issuerDID.string(),
        MerkleTreeType.Claims,
        coreClaim.hIndex(),
        coreClaim.hValue()
      );
    }

    const newIssuerTreeState = await this.getDIDTreeModel(issuerDID);
    const claimTreeRoot = await newIssuerTreeState.claimsTree.root();
    await this._storage.mt.addToMerkleTree(
      issuerDID.string(),
      MerkleTreeType.Roots,
      claimTreeRoot.bigInt(),
      BigInt(0)
    );
    const newIssuerTreeStateWithROR = await this.getDIDTreeModel(issuerDID);

    claimsRoot = await newIssuerTreeStateWithROR.claimsTree.root();
    rootOfRoots = await newIssuerTreeStateWithROR.rootsTree.root();
    revocationRoot = await newIssuerTreeStateWithROR.revocationTree.root();
    return {
      credentials,
      newTreeState: {
        state: newIssuerTreeStateWithROR.state,
        claimsRoot,
        rootOfRoots,
        revocationRoot
      },
      oldTreeState: oldTreeState
    };
  }

  /** {@inheritDoc IIdentityWallet.generateIden3SparseMerkleTreeProof} */
  // treeState -  optional, if it is not passed proof of claim inclusion will be generated on the latest state in the tree.
  async generateIden3SparseMerkleTreeProof(
    issuerDID: DID,
    credentials: W3CCredential[],
    txId: string,
    blockNumber?: number,
    blockTimestamp?: number,
    treeState?: TreeState,
    opts?: CoreClaimCreationOptions
  ): Promise<W3CCredential[]> {
    for (let index = 0; index < credentials.length; index++) {
      const credential = credentials[index];

      // TODO: return coreClaim from generateCredentialMtp and use it below
      // credential must have a bjj signature proof

      const coreClaim =
        credential.getCoreClaimFromProof(ProofType.BJJSignature) ||
        (await credential.toCoreClaim(opts));

      if (!coreClaim) {
        throw new Error(VerifiableConstants.ERRORS.ID_WALLET_CORE_CLAIM_REQUIRED_IN_SIG_PROOF);
      }
      const mtpWithProof = await this.generateCoreClaimMtp(issuerDID, coreClaim, treeState);

      const mtpProof: Iden3SparseMerkleTreeProof = new Iden3SparseMerkleTreeProof({
        mtp: mtpWithProof.proof,
        issuerData: {
          id: issuerDID,
          state: {
            claimsTreeRoot: mtpWithProof.treeState.claimsRoot,
            revocationTreeRoot: mtpWithProof.treeState.revocationRoot,
            rootOfRoots: mtpWithProof.treeState.rootOfRoots,
            value: mtpWithProof.treeState.state,
            txId,
            blockNumber,
            blockTimestamp
          }
        },
        coreClaim
      });

      if (Array.isArray(credentials[index].proof)) {
        (credentials[index].proof as unknown[]).push(mtpProof);
      } else {
        credentials[index].proof = credentials[index].proof
          ? [credentials[index].proof, mtpProof]
          : [mtpProof];
      }
    }
    return credentials;
  }

  /** {@inheritDoc IIdentityWallet.publishSpecificStateToRHS} */
  async publishSpecificStateToRHS(
    treeModel: TreesModel,
    rhsURL: string,
    revokedNonces?: number[]
  ): Promise<void> {
    await pushHashesToRHS(treeModel.state, treeModel, rhsURL, revokedNonces);
  }

  /** {@inheritDoc IIdentityWallet.publishStateToRHS} */
  async publishStateToRHS(issuerDID: DID, rhsURL: string, revokedNonces?: number[]): Promise<void> {
    const treeState = await this.getDIDTreeModel(issuerDID);
    await pushHashesToRHS(
      treeState.state,
      {
        revocationTree: treeState.revocationTree,
        claimsTree: treeState.claimsTree,
        state: treeState.state,
        rootsTree: treeState.rootsTree
      },
      rhsURL,
      revokedNonces
    );
  }

  /** {@inheritDoc IIdentityWallet.publishRevocationInfoByCredentialStatusType} */
  async publishRevocationInfoByCredentialStatusType(
    issuerDID: DID,
    credentialStatusType: CredentialStatusType,
    opts?: RevocationInfoOptions
  ): Promise<void> {
    const rhsPublishers = this._credentialStatusPublisherRegistry.get(credentialStatusType);
    if (!rhsPublishers) {
      throw new Error(
        `there is no registered publisher to save  hash is not registered for ${credentialStatusType} is not registered`
      );
    }

    let nodes: ProofNode[] = [];

    const tree = opts?.treeModel ?? (await this.getDIDTreeModel(issuerDID));
    nodes = await getNodesRepresentation(
      opts?.revokedNonces ?? [],
      {
        revocationTree: tree.revocationTree,
        claimsTree: tree.claimsTree,
        state: tree.state,
        rootsTree: tree.rootsTree
      },
      tree.state
    );

    if (!nodes.length) {
      return;
    }

    const rhsPublishersTask = rhsPublishers.map((publisher) =>
      publisher.publish({ nodes, ...opts, credentialStatusType, issuerDID })
    );

    await Promise.all(rhsPublishersTask);
  }

  public async getCoreClaimFromCredential(credential: W3CCredential): Promise<Claim> {
    const coreClaimFromSigProof = credential.getCoreClaimFromProof(ProofType.BJJSignature);

    const coreClaimFromMtpProof = credential.getCoreClaimFromProof(
      ProofType.Iden3SparseMerkleTreeProof
    );

    if (
      coreClaimFromMtpProof &&
      coreClaimFromSigProof &&
      coreClaimFromMtpProof.hex() !== coreClaimFromSigProof.hex()
    ) {
      throw new Error(VerifiableConstants.ERRORS.ID_WALLET_CORE_CLAIM_MISMATCH);
    }
    if (!coreClaimFromMtpProof && !coreClaimFromSigProof) {
      throw new Error(VerifiableConstants.ERRORS.ID_WALLET_CORE_CLAIM_IS_NOT_SET);
    }

    //eslint-disable-next-line  @typescript-eslint/no-non-null-assertion
    const coreClaim = coreClaimFromMtpProof ?? coreClaimFromSigProof!;

    return coreClaim;
  }

  async findOwnedCredentialsByDID(did: DID, query: ProofQuery): Promise<W3CCredential[]> {
    const credentials = await this._credentialWallet.findByQuery(query);
    if (!credentials.length) {
      throw new Error(VerifiableConstants.ERRORS.ID_WALLET_NO_CREDENTIAL_SATISFIED_QUERY);
    }

    const { genesisDID } = await this.getGenesisDIDMetadata(did);

    const profiles = await this.getProfilesByDID(genesisDID);

    return credentials.filter((cred) => {
      const credentialSubjectId = cred.credentialSubject['id'] as string; // credential subject
      return (
        credentialSubjectId == genesisDID.string() ||
        profiles.some((p) => {
          return p.id === credentialSubjectId;
        })
      );
    });
  }

  /** {@inheritDoc IIdentityWallet.updateIdentityState} */
  async updateIdentityState(
    issuerDID: DID,
    published: boolean,
    treeState?: TreeState
  ): Promise<void> {
    const latestTreeState = await this.getDIDTreeModel(issuerDID);

    await this._storage.identity.saveIdentity({
      did: issuerDID.string(),
      state: treeState?.state ?? latestTreeState.state,
      isStatePublished: published,
      isStateGenesis: false
    });
  }

  /** {@inheritdoc IIdentityWallet.transitState} */
  async transitState(
    did: DID,
    oldTreeState: TreeState,
    isOldStateGenesis: boolean,
    ethSigner: Signer,
    prover?: IZKProver
  ): Promise<string> {
    const newTreeModel = await this.getDIDTreeModel(did);
    const claimsRoot = await newTreeModel.claimsTree.root();
    const rootOfRoots = await newTreeModel.rootsTree.root();
    const revocationRoot = await newTreeModel.revocationTree.root();

    const newTreeState: TreeState = {
      revocationRoot,
      claimsRoot,
      state: newTreeModel.state,
      rootOfRoots
    };

    const userId = DID.idFromDID(did);

    let proof;
    const isEthIdentity = isEthereumIdentity(did); // don't generate proof for ethereum identities

    let txId;
    if (!isEthIdentity) {
      if (!prover) {
        throw new Error(VerifiableConstants.ERRORS.ID_WALLET_PROVER_IS_REQUIRED);
      }
      // generate the proof
      const authInfo = await this._inputsGenerator.prepareAuthBJJCredential(did, oldTreeState);
      const challenge = Poseidon.hash([oldTreeState.state.bigInt(), newTreeState.state.bigInt()]);

      const signature = await this.signChallenge(challenge, authInfo.credential);

      const circuitInputs = new StateTransitionInputs();
      circuitInputs.id = userId;

      circuitInputs.signature = signature;
      circuitInputs.isOldStateGenesis = isOldStateGenesis;

      const authClaimIncProofNewState = await this.generateCredentialMtp(
        did,
        authInfo.credential,
        newTreeState
      );

      circuitInputs.newTreeState = authClaimIncProofNewState.treeState;
      circuitInputs.authClaimNewStateIncProof = authClaimIncProofNewState.proof;

      circuitInputs.oldTreeState = oldTreeState;
      circuitInputs.authClaim = {
        claim: authInfo.coreClaim,
        incProof: authInfo.incProof,
        nonRevProof: authInfo.nonRevProof
      };

      const inputs = circuitInputs.inputsMarshal();

      proof = await prover.generate(inputs, CircuitId.StateTransition);

      txId = await this._storage.states.publishState(proof, ethSigner);
    } else {
      const oldUserState = oldTreeState.state;
      const newUserState = newTreeState.state;
      const userStateTransitionInfo: UserStateTransitionInfo = {
        userId,
        oldUserState,
        newUserState,
        isOldStateGenesis,
        methodId: BigInt(1),
        methodParams: '0x'
      } as UserStateTransitionInfo;
      txId = await this._storage.states.publishStateGeneric(ethSigner, userStateTransitionInfo);
    }
    await this.updateIdentityState(did, true, newTreeState);

    return txId;
  }

  private async getAuthBJJCredential(
    did: DID,
    oldTreeState: TreeState,
    {
      nonce,
      seed,
      id,
      type,
      publicKey
    }: {
      nonce: number;
      seed: Uint8Array;
      id: string;
      type: CredentialStatusType;
      publicKey?: PublicKey;
    }
  ): Promise<W3CCredential> {
    const { authClaim, pubKey } = publicKey
      ? this.createAuthCoreClaimFromPublicKey(nonce, publicKey)
      : await this.createAuthCoreClaim(nonce, seed);

    const { hi, hv } = authClaim.hiHv();
    await this._storage.mt.addToMerkleTree(did.string(), MerkleTreeType.Claims, hi, hv);

    // Calculate current state after adding credential to merkle tree
    const claimsTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
      did.string(),
      MerkleTreeType.Claims
    );
    const currentState = hashElems([
      (await claimsTree.root()).bigInt(),
      oldTreeState.revocationRoot.bigInt(),
      oldTreeState.rootOfRoots.bigInt()
    ]);

    return this.createAuthBJJCredential(did, pubKey, authClaim, currentState, {
      id,
      type
    });
  }

  /** {@inheritdoc IIdentityWallet.addBJJAuthCredential} */
  async addBJJAuthCredential(
    did: DID,
    oldTreeState: TreeState,
    isOldStateGenesis: boolean,
    ethSigner: Signer,
    opts: AuthBJJCredentialCreationOptions,
    prover?: IZKProver // it will be needed in case of non ethereum identities
  ): Promise<W3CCredential> {
    // seed and nonce are not written back to `opts`: callers may reuse the same options object
    // for several auth keys, which would then share the key or the revocation nonce
    const seed = opts.seed ?? getRandomBytes(32);
    // nonce 0 is only safe for the first auth key: a BJJ identity's genesis auth claim already
    // uses it, and a shared nonce would make revoking one key revoke the other as well
    const isFirstAuthKey =
      isOldStateGenesis &&
      (await this._credentialWallet.getAllAuthBJJCredentials(did)).length === 0;
    const nonce =
      opts.revocationOpts.nonce ??
      (isFirstAuthKey ? 0 : new DataView(getRandomBytes(12).buffer).getUint32(0));

    const credential = await this.getAuthBJJCredential(did, oldTreeState, {
      nonce,
      seed,
      id: opts.revocationOpts.id,
      type: opts.revocationOpts.type,
      publicKey: opts.publicKey
    });

    const addMtpToCredAndPublishRevState = async () => {
      const { receipt, block } = await this._transactionService.getTransactionReceiptAndBlock(txId);
      const credsWithIden3MTPProof = await this.generateIden3SparseMerkleTreeProof(
        did,
        [credential],
        txId,
        receipt?.blockNumber,
        block?.timestamp,
        undefined,
        {
          revNonce: nonce,
          subjectPosition: SubjectPosition.None,
          merklizedRootPosition: MerklizedRootPosition.None,
          updatable: false,
          version: 0,
          merklizeOpts: { documentLoader: cacheLoader() }
        }
      );

      await this._credentialWallet.saveAll(credsWithIden3MTPProof);

      await this.publishRevocationInfoByCredentialStatusType(did, opts.revocationOpts.type, {
        rhsUrl: opts.revocationOpts.id,
        onChain: opts.revocationOpts.onChain
      });

      return credsWithIden3MTPProof[0];
    };

    let txId = '';

    let attempt = 2;
    do {
      try {
        txId = await this.transitState(did, oldTreeState, isOldStateGenesis, ethSigner, prover);
        break;
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(
          `Error while transiting state, retrying state transition, attempt: ${attempt}`,
          err
        );
      }
    } while (--attempt);

    if (!txId) {
      const oldTransitStateInfoJson = JSON.stringify(
        {
          claimsRoot: oldTreeState.claimsRoot.hex(),
          revocationRoot: oldTreeState.revocationRoot.hex(),
          rootOfRoots: oldTreeState.rootOfRoots.hex(),
          state: oldTreeState.state.hex(),
          isOldStateGenesis,
          credentialId: credential.id,
          did: did.string()
        },
        null,
        2
      );
      await this._credentialWallet.save(credential);

      throw new Error(`Error publishing state, info to publish: ${oldTransitStateInfoJson}`);
    }

    return addMtpToCredAndPublishRevState();
  }
}
