import {
  BytesHelper,
  Claim,
  DID,
  MerklizedRootPosition,
  getDateFromUnixTimestamp
} from '@iden3/js-iden3-core';
import {
  AuthV2PubSignals,
  AuthV3PubSignals,
  CircuitId,
  Operators,
  Query,
  TreeState,
  ValueProof
} from '../circuits';
import { ICredentialWallet } from '../credentials';
import { IIdentityWallet } from '../identity';
import {
  createVerifiablePresentation,
  ProofQuery,
  RevocationStatus,
  VerifiableConstants,
  W3CCredential
} from '../verifiable';
import {
  PreparedCredential,
  QueryMetadata,
  parseQueryMetadata,
  parseZKPQuery,
  isAuthCircuit,
  transformQueryValueToBigInts
} from './common';
import { IZKProver, NativeProver } from './provers/prover';

import { Merklizer, Options, getDocumentLoader } from '@iden3/js-jsonld-merklization';
import { ZKProof } from '@iden3/js-jwz';
import { Signer } from 'ethers';
import {
  StateVerificationOpts,
  JSONObject,
  ZeroKnowledgeProofRequest,
  ZeroKnowledgeProofResponse,
  PROTOCOL_CONSTANTS,
  VerifiablePresentation,
  JsonDocumentObject,
  ZeroKnowledgeProofAuthResponse
} from '../iden3comm';
import { cacheLoader } from '../schema-processor';
import { ICircuitStorage, IProofStorage, IStateStorage } from '../storage';
import { byteDecoder, byteEncoder } from '../utils/encoding';
import {
  AuthProofGenerationOptions,
  GenerateInputsResult,
  InputGenerator,
  ProofGenerationOptions,
  ProofInputsParams
} from './provers/inputs-generator';
import { PubSignalsVerifier, VerifyContext } from './verifiers/pub-signals-verifier';
import { VerifyOpts } from './verifiers';

export interface QueryWithFieldName {
  query: Query;
  fieldName: string;
  rawValue?: unknown;
  isSelectiveDisclosure?: boolean;
}

/**
 *  Metadata that returns on verification
 * @type VerificationResultMetadata
 */
export type VerificationResultMetadata = {
  linkID?: bigint;
};

/**
 *  List of options to customize ProofService
 */
export type ProofServiceOptions = Options & {
  prover?: IZKProver;
  proofsCacheStorage?: IProofStorage;
};

export interface ProofVerifyOpts {
  query: ProofQuery;
  sender: string;
  opts?: VerifyOpts;
  params?: JSONObject;
}

export interface IProofService {
  /**
   * Verification of zkp proof for given circuit id
   *
   * @param {ZKProof} zkp  - proof to verify
   * @param {CircuitId} circuitId - circuit id
   * @returns `{Promise<boolean>}`
   */
  verifyProof(zkp: ZKProof, circuitName: CircuitId): Promise<boolean>;

  /**
   * Verification of zkp proof and pub signals for given circuit id
   *
   * @param {ZeroKnowledgeProofResponse} response  - zero knowledge proof response
   * @param {ProofVerifyOpts} opts - proof verification options
   * @returns `{Promise<VerificationResultMetadata>}`
   */
  verifyZKPResponse(
    proofResp: ZeroKnowledgeProofResponse,
    opts: ProofVerifyOpts
  ): Promise<VerificationResultMetadata>;

  /**
   * Generate proof from given identity and credential for protocol proof request
   *
   * @param {ZeroKnowledgeProofRequest} proofReq - protocol zkp request
   * @param {DID} identifier - did that will generate proof
   * @param {W3CCredential} credential - credential that will be used for proof generation
   * @param {ProofGenerationOptions} opts - options that will be used for proof generation
   *
   * @returns `Promise<ZeroKnowledgeProofResponse>`
   */
  generateProof(
    proofReq: ZeroKnowledgeProofRequest,
    identifier: DID,
    opts?: ProofGenerationOptions
  ): Promise<ZeroKnowledgeProofResponse>;

  /**
   * @deprecated, use generateAuthInputs with CircuitId.AuthV2 instead
   * generates auth inputs
   *
   * @param {Uint8Array} hash - challenge that will be signed
   * @param {DID} did - identity that will generate a proof
   * @param {CircuitId} circuitId - circuit id for authentication
   * @returns `Promise<Uint8Array>`
   */
  generateAuthV2Inputs(hash: Uint8Array, did: DID, circuitId: CircuitId): Promise<Uint8Array>;

  /**
   * generates Auth inputs
   *
   * @param {Uint8Array} hash - challenge that will be signed
   * @param {DID} did - identity that will generate a proof
   * @param {CircuitId} circuitId - circuit id for authentication
   * @returns `Promise<Uint8Array>`
   */
  generateAuthInputs(hash: Uint8Array, did: DID, circuitId: CircuitId): Promise<Uint8Array>;

  /**
   * @deprecated, use generateAuthProof with CircuitId.AuthV2 instead
   * generates auth v2 proof from given identity
   *
   * @param {Uint8Array} hash - challenge that will be signed
   * @param {DID} did - identity that will generate a proof
   * @returns `Promise<ZKProof>`
   */
  generateAuthV2Proof(hash: Uint8Array, did: DID): Promise<ZKProof>;

  /**
   * Generate auth proof from given identity with generic params
   *
   * @param {CircuitId} circuitId - circuitId for the proof generation
   * @param {DID} identifier - did that will generate proof
   * @param {ProofGenerationOptions} opts - options that will be used for proof generation
   *
   * @returns `Promise<ZeroKnowledgeProofResponse>`
   */
  generateAuthProof(
    circuitId: CircuitId,
    identifier: DID,
    opts?: AuthProofGenerationOptions
  ): Promise<ZeroKnowledgeProofAuthResponse>;

  /**
   * state verification function
   *
   * @param {string} circuitId - id of authentication circuit
   * @param {Array<string>} pubSignals - public signals of authentication circuit
   * @returns `Promise<boolean>`
   */
  verifyState(circuitId: string, pubSignals: Array<string>): Promise<boolean>;
  /**
   * transitState is done always to the latest state
   *
   * Generates a state transition proof and publishes state to the blockchain
   *
   * @param {DID} did - identity that will transit state
   * @param {TreeState} oldTreeState - previous tree state
   * @param {boolean} isOldStateGenesis - is a transition state is done from genesis state
   * @param {Signer} ethSigner - signer for transaction
   * @returns `{Promise<string>}` - transaction hash is returned
   */
  transitState(
    did: DID,
    oldTreeState: TreeState,
    isOldStateGenesis: boolean,
    stateStorage: IStateStorage,
    ethSigner: Signer
  ): Promise<string>;

  findCredentialByProofQuery(
    did: DID,
    query: ProofQuery,
    opts?: { skipClaimRevocationCheck: boolean }
  ): Promise<{ cred: W3CCredential; revStatus: RevocationStatus | undefined }>;
}
/**
 * Proof service is an implementation of IProofService
 * that works with a native groth16 prover
 *
 * @public
 * @class ProofService
 * @implements implements IProofService interface
 */
export class ProofService implements IProofService {
  private readonly _prover: IZKProver;
  private readonly _ldOptions: Options;
  private readonly _inputsGenerator: InputGenerator;
  private readonly _pubSignalsVerifier: PubSignalsVerifier;
  private readonly _proofsCacheStorage?: IProofStorage;
  /**
   * Creates an instance of ProofService.
   * @param {IIdentityWallet} _identityWallet - identity wallet
   * @param {ICredentialWallet} _credentialWallet - credential wallet
   * @param {ICircuitStorage} _circuitStorage - circuit storage to load proving / verification files
   * @param {IStateStorage} _stateStorage - state storage to get GIST proof / publish state
   */
  constructor(
    private readonly _identityWallet: IIdentityWallet,
    private readonly _credentialWallet: ICredentialWallet,
    _circuitStorage: ICircuitStorage,
    private readonly _stateStorage: IStateStorage,
    opts?: ProofServiceOptions
  ) {
    this._prover = opts?.prover ?? new NativeProver(_circuitStorage);
    this._ldOptions = { ...opts, documentLoader: opts?.documentLoader ?? cacheLoader(opts) };
    this._inputsGenerator = new InputGenerator(_identityWallet, _credentialWallet, _stateStorage);
    this._pubSignalsVerifier = new PubSignalsVerifier(
      opts?.documentLoader ?? cacheLoader(opts),
      _stateStorage
    );
    this._proofsCacheStorage = opts?.proofsCacheStorage;
  }

  /** {@inheritdoc IProofService.verifyProof} */
  async verifyProof(zkp: ZKProof, circuitId: CircuitId): Promise<boolean> {
    return this._prover.verify(zkp, circuitId);
  }

  /** {@inheritdoc IProofService.verify} */
  async verifyZKPResponse(
    proofResp: ZeroKnowledgeProofResponse,
    opts: ProofVerifyOpts
  ): Promise<VerificationResultMetadata> {
    const proofValid = await this._prover.verify(proofResp, proofResp.circuitId);
    if (!proofValid) {
      throw Error(
        `Proof with circuit id ${proofResp.circuitId} and request id ${proofResp.id} is not valid`
      );
    }

    const verifyContext: VerifyContext = {
      pubSignals: proofResp.pub_signals,
      query: opts.query,
      verifiablePresentation: proofResp.vp,
      sender: opts.sender,
      challenge: BigInt(proofResp.id),
      opts: opts.opts,
      params: opts.params
    };
    const pubSignals = await this._pubSignalsVerifier.verify(proofResp.circuitId, verifyContext);

    return { linkID: (pubSignals as unknown as { linkID?: bigint }).linkID };
  }

  /** {@inheritdoc IProofService.generateProof} */
  async generateProof(
    proofReq: ZeroKnowledgeProofRequest,
    identifier: DID,
    opts?: ProofGenerationOptions
  ): Promise<ZeroKnowledgeProofResponse> {
    if (!opts) {
      opts = {
        skipRevocation: false,
        challenge: 0n
      };
    }

    const { nonce: authProfileNonce, genesisDID: genesisDid } =
      await this._identityWallet.getGenesisDIDMetadata(identifier);

    const query = proofReq.query;
    if (!query) {
      if (!isAuthCircuit(proofReq.circuitId as CircuitId)) {
        throw new Error(`for non-auth circuits query must be provided`);
      }
      const authRes = await this.generateAuthProof(proofReq.circuitId as CircuitId, identifier, {
        challenge: proofReq.params?.challenge ? BigInt(proofReq.params.challenge) : undefined
      });
      return {
        id: proofReq.id,
        circuitId: proofReq.circuitId,
        pub_signals: authRes.pub_signals,
        proof: authRes.proof
      };
    }

    let credentialWithRevStatus: {
      cred: W3CCredential | undefined;
      revStatus: RevocationStatus | undefined;
    } = { cred: opts.credential, revStatus: opts.credentialRevocationStatus };

    if (!opts.credential) {
      credentialWithRevStatus = await this.findCredentialByProofQuery(identifier, query);
    }

    if (opts.credential && !opts.credentialRevocationStatus && !opts.skipRevocation) {
      const revStatus = await this._credentialWallet.getRevocationStatusFromCredential(
        opts.credential
      );
      credentialWithRevStatus = { cred: opts.credential, revStatus };
    }

    if (!credentialWithRevStatus.cred) {
      throw new Error(
        VerifiableConstants.ERRORS.PROOF_SERVICE_NO_CREDENTIAL_FOR_QUERY +
          ` ${JSON.stringify(proofReq.query)}`
      );
    }

    if (
      !opts.allowExpiredCredentials &&
      credentialWithRevStatus.cred.expirationDate &&
      new Date(credentialWithRevStatus.cred.expirationDate) < new Date()
    ) {
      throw new Error(VerifiableConstants.ERRORS.PROOF_SERVICE_CREDENTIAL_IS_EXPIRED);
    }

    if (this._proofsCacheStorage && !opts?.bypassCache) {
      const cachedProof = await this._proofsCacheStorage.getProof(
        identifier,
        credentialWithRevStatus.cred.id,
        proofReq
      );
      if (cachedProof) {
        return cachedProof;
      }
    }

    const credentialCoreClaim = await this._identityWallet.getCoreClaimFromCredential(
      credentialWithRevStatus.cred
    );

    const preparedCredential: PreparedCredential = {
      credential: credentialWithRevStatus.cred,
      credentialCoreClaim,
      revStatus: credentialWithRevStatus.revStatus
    };

    const subjectDID = DID.parse(preparedCredential.credential.credentialSubject['id'] as string);

    const { nonce: credentialSubjectProfileNonce, genesisDID: subjectGenesisDID } =
      await this._identityWallet.getGenesisDIDMetadata(subjectDID);

    if (subjectGenesisDID.string() !== genesisDid.string()) {
      throw new Error(VerifiableConstants.ERRORS.PROOF_SERVICE_PROFILE_GENESIS_DID_MISMATCH);
    }

    const propertiesMetadata = parseZKPQuery(query);
    if (!propertiesMetadata.length) {
      throw new Error(VerifiableConstants.ERRORS.PROOF_SERVICE_NO_QUERIES_IN_ZKP_REQUEST);
    }

    const mtPosition = preparedCredential.credentialCoreClaim.getMerklizedPosition();

    let mk: Merklizer | undefined;
    if (mtPosition !== MerklizedRootPosition.None) {
      mk = await preparedCredential.credential.merklize(this._ldOptions);
    }

    const context = query['context'] as string;
    const groupId = query['groupId'] as number;

    const ldContext = await this.loadLdContext(context);

    const credentialType = query['type'] as string;
    const queriesMetadata: QueryMetadata[] = [];
    const circuitQueries: Query[] = [];
    for (const propertyMetadata of propertiesMetadata) {
      let propertyCredentialType = credentialType;
      if (propertyMetadata.fieldName.startsWith('credentialStatus.')) {
        if (!preparedCredential.credential.credentialStatus) {
          throw new Error('credential does not have credentialStatus but query requires it');
        }
        propertyCredentialType = preparedCredential.credential.credentialStatus.type;
      }
      const queryMetadata = await parseQueryMetadata(
        propertyMetadata,
        byteDecoder.decode(ldContext),
        propertyCredentialType,
        {
          ...this._ldOptions,
          legacyNoopOperator: [
            CircuitId.AtomicQuerySigV2OnChain,
            CircuitId.AtomicQueryMTPV2OnChain
          ].includes(proofReq.circuitId)
        }
      );
      queriesMetadata.push(queryMetadata);
      const circuitQuery = await this.toCircuitsQuery(
        preparedCredential.credential,
        queryMetadata,
        mk
      );
      circuitQueries.push(circuitQuery);
    }

    const sdQueries = queriesMetadata.filter((q) => q.operator === Operators.SD);
    const hasCredentialStatusQuery = queriesMetadata.some((q) =>
      q.fieldName.startsWith('credentialStatus.')
    );
    let vp: VerifiablePresentation | undefined;
    if (sdQueries.length || hasCredentialStatusQuery) {
      vp = createVerifiablePresentation(
        context,
        credentialType,
        preparedCredential.credential,
        queriesMetadata
      );
    }

    return this._generateProof({
      proofReq,
      vp,
      credId: preparedCredential.credential.id,
      identifier,
      preparedCredential,
      genesisDid,
      circuitQueries,
      inputParams: {
        ...opts,
        authProfileNonce,
        credentialSubjectProfileNonce,
        linkNonce: groupId ? opts.linkNonce : 0n
      },
      bypassCache: opts?.bypassCache
    });
  }

  private async _generateProof({
    proofReq,
    vp,
    credId,
    identifier,
    preparedCredential,
    genesisDid,
    inputParams,
    circuitQueries,
    bypassCache
  }: {
    proofReq: ZeroKnowledgeProofRequest;
    vp?: VerifiablePresentation;
    credId?: string;
    identifier: DID;
    preparedCredential: PreparedCredential;
    genesisDid: DID;
    inputParams: ProofInputsParams;
    circuitQueries: Query[];
    bypassCache?: boolean;
  }): Promise<ZeroKnowledgeProofResponse> {
    const { inputs, metadata } = await this.generateInputs(
      preparedCredential,
      genesisDid,
      proofReq,
      inputParams,
      circuitQueries
    );

    const circuitId = (metadata?.targetCircuitId ?? proofReq.circuitId) as CircuitId;

    try {
      const { proof, pub_signals } = await this._prover.generate(inputs, circuitId);

      const zkpRes = {
        id: proofReq.id,
        circuitId,
        vp,
        proof,
        pub_signals
      };
      if (this._proofsCacheStorage && credId) {
        if (!bypassCache) {
          await this._proofsCacheStorage.storeProof(identifier, credId, proofReq, zkpRes);
        } else if (this._proofsCacheStorage.removeProof) {
          await this._proofsCacheStorage.removeProof(identifier, credId, proofReq);
        }
      }
      return zkpRes;
    } catch (e) {
      const errorMessage = e instanceof Error ? e.message : String(e);
      const cause = e instanceof Error ? e : new Error(errorMessage);
      throw new Error(`Proof generation failed for circuit ${circuitId}: ${errorMessage}`, {
        cause
      });
    }
  }

  /** {@inheritdoc IProofService.generateAuthProof} */
  async generateAuthProof(
    circuitId: CircuitId,
    identifier: DID,
    opts?: AuthProofGenerationOptions
  ): Promise<ZeroKnowledgeProofAuthResponse> {
    if (!isAuthCircuit(circuitId)) {
      throw new Error('CircuitId is not supported');
    }
    if (!opts) {
      opts = {
        challenge: 0n
      };
    }

    const challenge = opts.challenge
      ? BytesHelper.intToBytes(opts.challenge).reverse()
      : new Uint8Array(32);
    const authInputs = await this.generateAuthInputs(challenge, identifier, circuitId);

    const zkProof = await this._prover.generate(authInputs, circuitId);
    return {
      circuitId: circuitId,
      proof: zkProof.proof,
      pub_signals: zkProof.pub_signals
    };
  }

  /** {@inheritdoc IProofService.transitState} */
  async transitState(
    did: DID,
    oldTreeState: TreeState,
    isOldStateGenesis: boolean,
    stateStorage: IStateStorage, // for compatibility with previous versions we leave this parameter
    ethSigner: Signer
  ): Promise<string> {
    return this._identityWallet.transitState(
      did,
      oldTreeState,
      isOldStateGenesis,
      ethSigner,
      this._prover
    );
  }

  private async generateInputs(
    preparedCredential: PreparedCredential,
    identifier: DID,
    proofReq: ZeroKnowledgeProofRequest,
    params: ProofInputsParams,
    circuitQueries: Query[]
  ): Promise<GenerateInputsResult> {
    return this._inputsGenerator.generateInputs({
      preparedCredential,
      identifier,
      proofReq,
      params,
      circuitQueries
    });
  }

  private async toCircuitsQuery(
    credential: W3CCredential,
    queryMetadata: QueryMetadata,
    merklizedCredential?: Merklizer
  ): Promise<Query> {
    if (queryMetadata.merklizedSchema && !merklizedCredential) {
      throw new Error('merklized root position is set to None for merklized schema');
    }
    if (!queryMetadata.merklizedSchema && merklizedCredential) {
      throw new Error('merklized root position is not set to None for non-merklized schema');
    }
    const query = new Query();

    query.slotIndex = queryMetadata.slotIndex;
    query.operator = queryMetadata.operator;
    query.values = queryMetadata.values;

    if (
      queryMetadata.merklizedSchema &&
      merklizedCredential &&
      queryMetadata.claimPathKey !== BigInt(0)
    ) {
      const { proof, value: mtValue } = await merklizedCredential.proof(queryMetadata.path);
      query.valueProof = new ValueProof();
      query.valueProof.mtp = proof;
      query.valueProof.path = queryMetadata.claimPathKey;

      const mtEntry = (await mtValue?.mtEntry()) ?? 0n;
      query.valueProof.value = mtEntry;
      if (!queryMetadata.fieldName) {
        query.values = [mtEntry];
        return query;
      }
    }

    if (queryMetadata.operator === Operators.SD) {
      let v;
      const [first, ...rest] = queryMetadata.fieldName.split('.');
      v = credential[first as keyof W3CCredential];
      for (const part of rest) {
        v = (v as JsonDocumentObject)[part];
      }
      if (typeof v === 'undefined') {
        throw new Error(`credential doesn't contain value for field ${queryMetadata.fieldName}`);
      }
      query.values = await transformQueryValueToBigInts(v, queryMetadata.datatype);
    }

    return query;
  }

  private async loadLdContext(context: string): Promise<Uint8Array> {
    const loader = getDocumentLoader(this._ldOptions);
    let ldSchema: object;
    try {
      ldSchema = (await loader(context)).document;
    } catch (e) {
      throw new Error(`can't load ld context from url ${context}`);
    }
    return byteEncoder.encode(JSON.stringify(ldSchema));
  }

  /** {@inheritdoc IProofService.generateAuthV2Inputs} */
  async generateAuthV2Inputs(
    hash: Uint8Array,
    did: DID,
    circuitId: CircuitId
  ): Promise<Uint8Array> {
    if (circuitId !== CircuitId.AuthV2) {
      throw new Error('CircuitId is not supported');
    }

    return this.generateAuthInputsCommon(hash, did, circuitId);
  }

  /** {@inheritdoc IProofService.generateAuthInputs} */
  async generateAuthInputs(hash: Uint8Array, did: DID, circuitId: CircuitId): Promise<Uint8Array> {
    if (
      circuitId !== CircuitId.AuthV2 &&
      circuitId !== CircuitId.AuthV3 &&
      circuitId !== CircuitId.AuthV3_8_32
    ) {
      throw new Error('CircuitId is not supported');
    }

    return this.generateAuthInputsCommon(hash, did, circuitId);
  }

  private async generateAuthInputsCommon(
    hash: Uint8Array,
    did: DID,
    circuitId: CircuitId
  ): Promise<Uint8Array> {
    const challenge = BytesHelper.bytesToInt(hash.reverse());

    const inputsCxt = await this._inputsGenerator.generateInputs({
      proofReq: {
        circuitId
      } as ZeroKnowledgeProofRequest,
      identifier: did,
      params: {
        challenge
      } as ProofInputsParams,
      circuitQueries: [],
      preparedCredential: {
        credential: new W3CCredential(),
        credentialCoreClaim: new Claim()
      }
    });

    return inputsCxt.inputs;
  }

  /** {@inheritdoc IProofService.generateAuthV2Proof} */
  async generateAuthV2Proof(challenge: Uint8Array, did: DID): Promise<ZKProof> {
    const authInputs = await this.generateAuthInputs(challenge, did, CircuitId.AuthV2);

    const zkProof = await this._prover.generate(authInputs, CircuitId.AuthV2);
    return zkProof;
  }

  async verifyState(
    circuitId: string,
    pubSignals: string[],
    opts: StateVerificationOpts = {
      acceptedStateTransitionDelay: PROTOCOL_CONSTANTS.DEFAULT_AUTH_VERIFY_DELAY
    }
  ): Promise<boolean> {
    if (
      circuitId !== CircuitId.AuthV2 &&
      circuitId !== CircuitId.AuthV3 &&
      circuitId !== CircuitId.AuthV3_8_32
    ) {
      throw new Error(`CircuitId is not supported ${circuitId}`);
    }

    let gistRoot, userId;
    if (circuitId === CircuitId.AuthV2) {
      const authV2PubSignals = new AuthV2PubSignals().pubSignalsUnmarshal(
        byteEncoder.encode(JSON.stringify(pubSignals))
      );
      gistRoot = authV2PubSignals.GISTRoot.bigInt();
      userId = authV2PubSignals.userID.bigInt();
    } else {
      const authV3PubSignals = new AuthV3PubSignals().pubSignalsUnmarshal(
        byteEncoder.encode(JSON.stringify(pubSignals))
      );
      gistRoot = authV3PubSignals.GISTRoot.bigInt();
      userId = authV3PubSignals.userID.bigInt();
    }
    const globalStateInfo = await this._stateStorage.getGISTRootInfo(gistRoot, userId);

    if (globalStateInfo.root !== gistRoot) {
      throw new Error(`gist info contains invalid state`);
    }

    if (globalStateInfo.replacedByRoot !== 0n) {
      if (globalStateInfo.replacedAtTimestamp === 0n) {
        throw new Error(`state was replaced, but replaced time unknown`);
      }

      const timeDiff =
        Date.now() -
        getDateFromUnixTimestamp(Number(globalStateInfo.replacedAtTimestamp)).getTime();

      if (
        timeDiff >
        (opts?.acceptedStateTransitionDelay ?? PROTOCOL_CONSTANTS.DEFAULT_AUTH_VERIFY_DELAY)
      ) {
        throw new Error('global state is outdated');
      }
    }

    return true;
  }

  async findCredentialByProofQuery(
    did: DID,
    query: ProofQuery
  ): Promise<{ cred: W3CCredential; revStatus: RevocationStatus | undefined }> {
    const credentials = await this._identityWallet.findOwnedCredentialsByDID(did, query);

    if (!credentials.length) {
      throw new Error(
        VerifiableConstants.ERRORS.PROOF_SERVICE_NO_CREDENTIAL_FOR_IDENTITY_OR_PROFILE
      );
    }

    //  For EQ / IN / NIN / LT / GT operations selective if credential satisfies query - we can get any.
    // TODO: choose credential for selective credentials
    const credential = query.skipClaimRevocationCheck
      ? { cred: credentials[0], revStatus: undefined }
      : await this._credentialWallet.findNonRevokedCredential(credentials);

    return credential;
  }
}
