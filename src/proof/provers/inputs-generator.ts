import { DID, getUnixTimestamp } from '@iden3/js-iden3-core';
import {
  Iden3SparseMerkleTreeProof,
  ProofType,
  RevocationStatus,
  W3CCredential
} from '../../verifiable';
import { ZeroKnowledgeProofRequest } from '../../iden3comm';
import {
  AtomicQueryMTPV2Inputs,
  AtomicQueryMTPV2OnChainInputs,
  AtomicQuerySigV2Inputs,
  AtomicQuerySigV2OnChainInputs,
  AtomicQueryV3Inputs,
  AtomicQueryV3OnChainInputs,
  AuthV3Inputs,
  CircuitClaim,
  CircuitId,
  CircuitSubversion,
  LinkedMultiQueryInputs,
  MTProof,
  Operators,
  Query,
  TreeState,
  circuitValidator,
  getOperatorNameByValue
} from '../../circuits';
import {
  PreparedAuthBJJCredential,
  PreparedCredential,
  toClaimNonRevStatus,
  toGISTProof
} from '../common';
import { IIdentityWallet } from '../../identity';
import { IStateStorage } from '../../storage';
import {
  CredentialStatusResolveOptions,
  ICredentialWallet,
  getUserDIDFromCredential
} from '../../credentials';
import { isEthereumIdentity, getChallengeFromEthAddress } from '../../utils';
import { Proof } from '@iden3/js-merkletree';

export type DIDProfileMetadata = {
  authProfileNonce: number | string;
  credentialSubjectProfileNonce: number | string;
};

export type ProofGenerationOptions = {
  skipRevocation: boolean;
  challenge?: bigint;
  credential?: W3CCredential;
  credentialRevocationStatus?: RevocationStatus;
  verifierDid?: DID;
  linkNonce?: bigint;
  bypassCache?: boolean;
  allowExpiredCredentials?: boolean;
};

export type AuthProofGenerationOptions = {
  challenge?: bigint;
};

export type ProofInputsParams = ProofGenerationOptions & DIDProfileMetadata;

type InputContext = {
  preparedCredential: PreparedCredential;
  identifier: DID;
  proofReq: ZeroKnowledgeProofRequest;
  params: ProofInputsParams;
  circuitQueries: Query[];
};

export type GenerateInputsResult = {
  inputs: Uint8Array;
  metadata?: { targetCircuitId: CircuitId | string };
};

export class InputGenerator {
  constructor(
    private readonly _identityWallet: IIdentityWallet,
    private readonly _credentialWallet: ICredentialWallet,
    private readonly _stateStorage: IStateStorage
  ) {}

  async generateInputs(ctx: InputContext): Promise<GenerateInputsResult> {
    const { circuitId } = ctx.proofReq;
    const fnName = `${circuitId
      .replace(/-beta\.1/g, '')
      .replace(/-/g, '_')
      .replace(/authV[\w-]+/g, 'auth')}PrepareInputs`;

    const queriesLength = ctx.circuitQueries.length;

    if (queriesLength > circuitValidator[circuitId as CircuitId].validation.maxQueriesCount) {
      throw new Error(
        `circuit ${circuitId} supports only ${
          circuitValidator[circuitId as CircuitId].validation.maxQueriesCount
        } queries`
      );
    }

    const fn = (
      this as unknown as {
        [k: string]: (ctx: InputContext) => Promise<GenerateInputsResult>;
      }
    )[fnName];

    if (!fn) {
      throw new Error(`inputs generator for ${circuitId} not found`);
    }

    return fn(ctx);
  }

  async newCircuitClaimData(preparedCredential: PreparedCredential): Promise<CircuitClaim> {
    const smtProof: Iden3SparseMerkleTreeProof | undefined =
      preparedCredential.credential.getIden3SparseMerkleTreeProof();

    const circuitClaim = new CircuitClaim();
    circuitClaim.claim = preparedCredential.credentialCoreClaim;
    circuitClaim.issuerId = DID.idFromDID(DID.parse(preparedCredential.credential.issuer));

    if (smtProof) {
      circuitClaim.proof = smtProof.mtp;
      circuitClaim.treeState = {
        state: smtProof.issuerData.state.value,
        claimsRoot: smtProof.issuerData.state.claimsTreeRoot,
        revocationRoot: smtProof.issuerData.state.revocationTreeRoot,
        rootOfRoots: smtProof.issuerData.state.rootOfRoots
      };
    }

    const sigProof = preparedCredential.credential.getBJJSignature2021Proof();

    if (sigProof) {
      const issuerDID = sigProof.issuerData.id;
      const userDID: DID = getUserDIDFromCredential(issuerDID, preparedCredential.credential);

      const { credentialStatus, mtp, authCoreClaim } = sigProof.issuerData;

      if (!credentialStatus) {
        throw new Error(
          "can't check the validity of issuer auth claim: no credential status in proof"
        );
      }

      if (!mtp) {
        throw new Error('issuer auth credential must have a mtp proof');
      }

      if (!authCoreClaim) {
        throw new Error('issuer auth credential must have a core claim proof');
      }

      const opts: CredentialStatusResolveOptions = {
        issuerGenesisState: sigProof.issuerData.state,
        issuerDID,
        userDID
      };

      const rs = await this._credentialWallet.getRevocationStatus(credentialStatus, opts);

      const issuerAuthNonRevProof: MTProof = toClaimNonRevStatus(rs);

      circuitClaim.signatureProof = {
        signature: sigProof.signature,
        issuerAuthIncProof: {
          proof: sigProof.issuerData.mtp,
          treeState: {
            state: sigProof.issuerData.state.value,
            claimsRoot: sigProof.issuerData.state.claimsTreeRoot,
            revocationRoot: sigProof.issuerData.state.revocationTreeRoot,
            rootOfRoots: sigProof.issuerData.state.rootOfRoots
          }
        },
        issuerAuthClaim: sigProof.issuerData.authCoreClaim,
        issuerAuthNonRevProof
      };
    }

    return circuitClaim;
  }

  async prepareAuthBJJCredential(
    did: DID,
    treeStateInfo?: TreeState
  ): Promise<PreparedAuthBJJCredential> {
    const { authCredential, incProof, nonRevProof } =
      await this._identityWallet.getActualAuthCredential(did, treeStateInfo);

    const authCoreClaim = authCredential.getCoreClaimFromProof(
      ProofType.Iden3SparseMerkleTreeProof
    );

    if (!authCoreClaim) {
      throw new Error('auth core claim is not defined for auth bjj credential');
    }

    return {
      credential: authCredential,
      incProof,
      nonRevProof,
      coreClaim: authCoreClaim
    };
  }

  private credentialAtomicQueryMTPV2PrepareInputs = async ({
    preparedCredential,
    identifier,
    proofReq,
    params,
    circuitQueries
  }: InputContext): Promise<GenerateInputsResult> => {
    const circuitClaimData = await this.newCircuitClaimData(preparedCredential);
    circuitClaimData.nonRevProof = toClaimNonRevStatus(preparedCredential.revStatus);
    const circuitInputs = new AtomicQueryMTPV2Inputs();
    circuitInputs.id = DID.idFromDID(identifier);
    circuitInputs.requestID = BigInt(proofReq.id);

    const query = circuitQueries[0];
    query.operator = this.transformV2QueryOperator(query.operator);
    circuitInputs.query = query;
    circuitInputs.claim = {
      issuerID: circuitClaimData.issuerId,
      claim: circuitClaimData.claim,
      incProof: { proof: circuitClaimData.proof, treeState: circuitClaimData.treeState },
      nonRevProof: circuitClaimData.nonRevProof
    };
    circuitInputs.currentTimeStamp = getUnixTimestamp(new Date());
    circuitInputs.claimSubjectProfileNonce = BigInt(params.credentialSubjectProfileNonce);
    circuitInputs.profileNonce = BigInt(params.authProfileNonce);
    circuitInputs.skipClaimRevocationCheck = params.skipRevocation;

    this.checkOperatorSupport(proofReq.circuitId, query.operator);

    return {
      inputs: circuitInputs.inputsMarshal(),
      metadata: { targetCircuitId: proofReq.circuitId }
    };
  };

  private authPrepareInputs = async ({
    identifier,
    proofReq,
    params
  }: InputContext): Promise<GenerateInputsResult> => {
    const { nonce: authProfileNonce, genesisDID } =
      await this._identityWallet.getGenesisDIDMetadata(identifier);

    let challenge = params.challenge ?? proofReq.params?.challenge;

    if (challenge === null || challenge === undefined) {
      throw new Error('challenge must be provided for auth circuit');
    }

    challenge = BigInt(challenge);

    const authPrepared = await this.prepareAuthBJJCredential(genesisDID);

    const signature = await this._identityWallet.signChallenge(challenge, authPrepared.credential);
    const id = DID.idFromDID(genesisDID);
    const stateProof = await this._stateStorage.getGISTProof(id.bigInt());

    const gistProof = toGISTProof(stateProof);

    const authInputs = new AuthV3Inputs(); // works for both v3 and v2
    if (proofReq.circuitId === CircuitId.AuthV3_8_32) {
      authInputs.mtLevel = 8;
      authInputs.mtLevelOnChain = 32;
    }

    authInputs.genesisID = id;
    authInputs.profileNonce = BigInt(authProfileNonce);
    authInputs.authClaim = authPrepared.coreClaim;
    authInputs.authClaimIncMtp = authPrepared.incProof.proof;
    authInputs.authClaimNonRevMtp = authPrepared.nonRevProof.proof;
    authInputs.treeState = authPrepared.incProof.treeState;
    authInputs.signature = signature;
    authInputs.challenge = challenge;
    authInputs.gistProof = gistProof;
    return {
      inputs: authInputs.inputsMarshal()
    };
  };

  private credentialAtomicQueryMTPV2OnChainPrepareInputs = async ({
    preparedCredential,
    identifier,
    proofReq,
    params,
    circuitQueries
  }: InputContext): Promise<GenerateInputsResult> => {
    const circuitClaimData = await this.newCircuitClaimData(preparedCredential);

    const authInfo = await this.prepareAuthBJJCredential(identifier);

    const authClaimData = await this.newCircuitClaimData({
      credential: authInfo.credential,
      credentialCoreClaim: authInfo.coreClaim
    });

    circuitClaimData.nonRevProof = toClaimNonRevStatus(preparedCredential.revStatus);

    const circuitInputs = new AtomicQueryMTPV2OnChainInputs();
    const id = DID.idFromDID(identifier);
    circuitInputs.id = DID.idFromDID(identifier);
    circuitInputs.requestID = BigInt(proofReq.id);

    const stateProof = await this._stateStorage.getGISTProof(id.bigInt());

    const gistProof = toGISTProof(stateProof);
    circuitInputs.gistProof = gistProof;

    if (authClaimData?.treeState) {
      circuitInputs.treeState = {
        state: authClaimData?.treeState?.state,
        claimsRoot: authClaimData?.treeState?.claimsRoot,
        revocationRoot: authClaimData?.treeState?.revocationRoot,
        rootOfRoots: authClaimData?.treeState?.rootOfRoots
      };
    }

    circuitInputs.authClaim = authClaimData.claim;
    circuitInputs.authClaimIncMtp = authClaimData.proof;
    circuitInputs.authClaimNonRevMtp = authInfo.nonRevProof.proof;
    if (params.challenge === null || params.challenge === undefined) {
      throw new Error('challenge must be provided for onchain circuits');
    }
    const signature = await this._identityWallet.signChallenge(
      params.challenge,
      authInfo.credential
    );

    circuitInputs.signature = signature;
    circuitInputs.challenge = params.challenge;

    const query = circuitQueries[0];
    circuitInputs.query = query;
    circuitInputs.claim = {
      issuerID: circuitClaimData.issuerId,
      claim: circuitClaimData.claim,
      incProof: { proof: circuitClaimData.proof, treeState: circuitClaimData.treeState },
      nonRevProof: circuitClaimData.nonRevProof
    };
    circuitInputs.currentTimeStamp = getUnixTimestamp(new Date());
    circuitInputs.claimSubjectProfileNonce = BigInt(params.credentialSubjectProfileNonce);
    circuitInputs.profileNonce = BigInt(params.authProfileNonce);
    circuitInputs.skipClaimRevocationCheck = params.skipRevocation;

    this.checkOperatorSupport(proofReq.circuitId, query.operator);

    return { inputs: circuitInputs.inputsMarshal() };
  };

  private credentialAtomicQuerySigV2PrepareInputs = async ({
    preparedCredential,
    identifier,
    proofReq,
    params,
    circuitQueries
  }: InputContext): Promise<GenerateInputsResult> => {
    const circuitClaimData = await this.newCircuitClaimData(preparedCredential);

    circuitClaimData.nonRevProof = toClaimNonRevStatus(preparedCredential.revStatus);

    const circuitInputs = new AtomicQuerySigV2Inputs();
    circuitInputs.id = DID.idFromDID(identifier);
    circuitInputs.claim = {
      issuerID: circuitClaimData?.issuerId,
      signatureProof: circuitClaimData.signatureProof,
      claim: circuitClaimData.claim,
      nonRevProof: circuitClaimData.nonRevProof
    };
    circuitInputs.requestID = BigInt(proofReq.id);
    circuitInputs.claimSubjectProfileNonce = BigInt(params.credentialSubjectProfileNonce);
    circuitInputs.profileNonce = BigInt(params.authProfileNonce);
    circuitInputs.skipClaimRevocationCheck = params.skipRevocation;

    const query = circuitQueries[0];
    query.operator = this.transformV2QueryOperator(query.operator);
    circuitInputs.query = query;
    circuitInputs.currentTimeStamp = getUnixTimestamp(new Date());

    this.checkOperatorSupport(proofReq.circuitId, query.operator);

    return { inputs: circuitInputs.inputsMarshal() };
  };

  private credentialAtomicQuerySigV2OnChainPrepareInputs = async ({
    preparedCredential,
    identifier,
    proofReq,
    params,
    circuitQueries
  }: InputContext): Promise<GenerateInputsResult> => {
    const circuitClaimData = await this.newCircuitClaimData(preparedCredential);

    const authInfo = await this.prepareAuthBJJCredential(identifier);

    const authClaimData = await this.newCircuitClaimData({
      credential: authInfo.credential,
      credentialCoreClaim: authInfo.coreClaim
    });

    circuitClaimData.nonRevProof = toClaimNonRevStatus(preparedCredential.revStatus);

    const circuitInputs = new AtomicQuerySigV2OnChainInputs();
    const id = DID.idFromDID(identifier);
    circuitInputs.id = id;
    circuitInputs.claim = {
      issuerID: circuitClaimData.issuerId,
      signatureProof: circuitClaimData.signatureProof,
      claim: circuitClaimData.claim,
      nonRevProof: circuitClaimData.nonRevProof
    };
    circuitInputs.requestID = BigInt(proofReq.id);
    circuitInputs.claimSubjectProfileNonce = BigInt(params.credentialSubjectProfileNonce);
    circuitInputs.profileNonce = BigInt(params.authProfileNonce);
    circuitInputs.skipClaimRevocationCheck = params.skipRevocation;

    const query = circuitQueries[0];
    circuitInputs.query = query;
    circuitInputs.currentTimeStamp = getUnixTimestamp(new Date());

    if (authClaimData.treeState) {
      circuitInputs.treeState = {
        state: authClaimData.treeState?.state,
        claimsRoot: authClaimData.treeState?.claimsRoot,
        revocationRoot: authClaimData.treeState?.revocationRoot,
        rootOfRoots: authClaimData.treeState?.rootOfRoots
      };
    }

    const stateProof = await this._stateStorage.getGISTProof(id.bigInt());
    const gistProof = toGISTProof(stateProof);
    circuitInputs.gistProof = gistProof;

    circuitInputs.authClaim = authClaimData.claim;
    circuitInputs.authClaimIncMtp = authClaimData.proof;
    circuitInputs.authClaimNonRevMtp = authInfo.nonRevProof.proof;

    if (params.challenge === null || params.challenge === undefined) {
      throw new Error('challenge must be provided for onchain circuits');
    }

    const signature = await this._identityWallet.signChallenge(
      params.challenge,
      authInfo.credential
    );

    circuitInputs.signature = signature;
    circuitInputs.challenge = params.challenge;

    this.checkOperatorSupport(proofReq.circuitId, query.operator);

    return { inputs: circuitInputs.inputsMarshal() };
  };

  private credentialAtomicQueryV3PrepareInputs = async ({
    preparedCredential,
    identifier,
    proofReq,
    params,
    circuitQueries
  }: InputContext): Promise<GenerateInputsResult> => {
    const circuitClaimData = await this.newCircuitClaimData(preparedCredential);

    circuitClaimData.nonRevProof = toClaimNonRevStatus(preparedCredential.revStatus);

    const proofReqQuery = proofReq.query;

    if (!proofReqQuery) {
      throw new Error('proof request query is required for v3 circuits');
    }

    let proofType: ProofType;
    switch (proofReqQuery.proofType) {
      case ProofType.BJJSignature:
        proofType = ProofType.BJJSignature;
        break;
      case ProofType.Iden3SparseMerkleTreeProof:
        proofType = ProofType.Iden3SparseMerkleTreeProof;
        break;
      default:
        if (circuitClaimData.proof) {
          proofType = ProofType.Iden3SparseMerkleTreeProof;
        } else if (circuitClaimData.signatureProof) {
          proofType = ProofType.BJJSignature;
        } else {
          throw Error('claim has no MTP or signature proof');
        }
        break;
    }

    const query = circuitQueries[0];

    const proofsToCheck: { proof?: Proof; levelKey: keyof CircuitSubversion }[] = [
      { proof: circuitClaimData.nonRevProof.proof, levelKey: 'mtLevel' },
      { proof: circuitClaimData.signatureProof?.issuerAuthIncProof.proof, levelKey: 'mtLevel' },
      { proof: circuitClaimData.signatureProof?.issuerAuthNonRevProof.proof, levelKey: 'mtLevel' },
      { proof: circuitClaimData.proof, levelKey: 'mtLevel' },
      { proof: query.valueProof?.mtp, levelKey: 'mtLevelClaim' }
    ];

    const targetCircuitInfo = selectV3TargetCircuit(proofReq.circuitId, proofsToCheck);
    const { mtLevel, mtLevelClaim, targetCircuitId } = targetCircuitInfo ?? {
      targetCircuitId: proofReq.circuitId
    };

    const circuitInputs = new AtomicQueryV3Inputs({ mtLevel, mtLevelClaim });
    circuitInputs.id = DID.idFromDID(identifier);
    circuitInputs.claim = {
      issuerID: circuitClaimData?.issuerId,
      signatureProof: circuitClaimData.signatureProof,
      claim: circuitClaimData.claim,
      nonRevProof: circuitClaimData.nonRevProof,
      incProof: { proof: circuitClaimData.proof, treeState: circuitClaimData.treeState }
    };
    circuitInputs.requestID = BigInt(proofReq.id);
    circuitInputs.claimSubjectProfileNonce = BigInt(params.credentialSubjectProfileNonce);
    circuitInputs.profileNonce = BigInt(params.authProfileNonce);
    circuitInputs.skipClaimRevocationCheck = params.skipRevocation;

    // it is ok not to reset claimPathKey for noop, as it is a part of output, but auth won't be broken. (it skips check for noop)
    query.values = [Operators.SD, Operators.NOOP].includes(query.operator) ? [] : query.values;

    circuitInputs.query = query;
    circuitInputs.currentTimeStamp = getUnixTimestamp(new Date());

    circuitInputs.proofType = proofType;
    circuitInputs.linkNonce = params.linkNonce ?? 0n;
    circuitInputs.verifierID = params.verifierDid ? DID.idFromDID(params.verifierDid) : undefined;
    circuitInputs.nullifierSessionID = proofReq.params?.nullifierSessionId
      ? BigInt(proofReq.params?.nullifierSessionId?.toString())
      : 0n;

    this.checkOperatorSupport(proofReq.circuitId, query.operator);

    return {
      inputs: circuitInputs.inputsMarshal(),
      metadata: { targetCircuitId }
    };
  };

  private credentialAtomicQueryV3OnChainPrepareInputs = async ({
    preparedCredential,
    identifier,
    proofReq,
    params,
    circuitQueries
  }: InputContext): Promise<GenerateInputsResult> => {
    const id = DID.idFromDID(identifier);

    const circuitClaimData = await this.newCircuitClaimData(preparedCredential);

    circuitClaimData.nonRevProof = toClaimNonRevStatus(preparedCredential.revStatus);
    let proofType: ProofType;
    const proofReqQuery = proofReq.query;

    if (!proofReqQuery) {
      throw new Error('proof request query is required for v3 onchain circuits');
    }
    switch (proofReqQuery.proofType) {
      case ProofType.BJJSignature:
        proofType = ProofType.BJJSignature;
        break;
      case ProofType.Iden3SparseMerkleTreeProof:
        proofType = ProofType.Iden3SparseMerkleTreeProof;
        break;
      default:
        if (circuitClaimData.proof) {
          proofType = ProofType.Iden3SparseMerkleTreeProof;
        } else if (circuitClaimData.signatureProof) {
          proofType = ProofType.BJJSignature;
        } else {
          throw Error('claim has no MTP or signature proof');
        }
        break;
    }

    const query = circuitQueries[0];

    const stateProof = await this._stateStorage.getGISTProof(id.bigInt());
    const gistProof = toGISTProof(stateProof);

    const mtLevelsProofs: { proof?: Proof; levelKey: keyof CircuitSubversion }[] = [
      { proof: circuitClaimData.nonRevProof.proof, levelKey: 'mtLevel' },
      { proof: circuitClaimData.signatureProof?.issuerAuthIncProof.proof, levelKey: 'mtLevel' },
      {
        proof: circuitClaimData.signatureProof?.issuerAuthNonRevProof.proof,
        levelKey: 'mtLevel'
      },
      { proof: circuitClaimData.proof, levelKey: 'mtLevel' },
      { proof: query.valueProof?.mtp, levelKey: 'mtLevelClaim' },
      { proof: gistProof.proof, levelKey: 'mtLevelOnChain' }
    ];

    const { mtLevel, mtLevelClaim, mtLevelOnChain, targetCircuitId } = selectV3TargetCircuit(
      proofReq.circuitId,
      mtLevelsProofs,
      true
    ) ?? {
      targetCircuitId: proofReq.circuitId
    };

    const circuitInputs = new AtomicQueryV3OnChainInputs({ mtLevel, mtLevelClaim, mtLevelOnChain });
    circuitInputs.id = DID.idFromDID(identifier);
    circuitInputs.claim = {
      issuerID: circuitClaimData?.issuerId,
      signatureProof: circuitClaimData.signatureProof,
      claim: circuitClaimData.claim,
      nonRevProof: circuitClaimData.nonRevProof,
      incProof: { proof: circuitClaimData.proof, treeState: circuitClaimData.treeState }
    };
    circuitInputs.requestID = BigInt(proofReq.id);
    circuitInputs.claimSubjectProfileNonce = BigInt(params.credentialSubjectProfileNonce);
    circuitInputs.profileNonce = BigInt(params.authProfileNonce);
    circuitInputs.skipClaimRevocationCheck = params.skipRevocation;

    // no need to set valueProof empty for noop, because it is ignored in circuit, but implies correct calculation of query hash
    query.values = [Operators.SD, Operators.NOOP].includes(query.operator) ? [] : query.values;

    circuitInputs.query = query;
    circuitInputs.currentTimeStamp = getUnixTimestamp(new Date());

    circuitInputs.proofType = proofType;
    circuitInputs.linkNonce = params.linkNonce ?? 0n;
    circuitInputs.verifierID = params.verifierDid ? DID.idFromDID(params.verifierDid) : undefined;
    circuitInputs.nullifierSessionID = proofReq.params?.nullifierSessionId
      ? BigInt(proofReq.params?.nullifierSessionId?.toString())
      : 0n;

    const isEthIdentity = isEthereumIdentity(identifier);
    circuitInputs.isBJJAuthEnabled = isEthIdentity ? 0 : 1;

    const sender = proofReq.params?.sender;

    if (isEthIdentity && sender) {
      throw new Error(
        `the combination of "sender" and an Ethereum-based identity is not supported; when using an Ethereum identity as the prover, provide the challenge directly instead of a sender address''sender parameter is not supported for ethereum identities`
      );
    }

    const challenge = sender ? getChallengeFromEthAddress(sender) : BigInt(params.challenge ?? 0);

    circuitInputs.challenge = challenge;

    circuitInputs.gistProof = gistProof;
    // auth inputs
    if (circuitInputs.isBJJAuthEnabled === 1) {
      const authPrepared = await this.prepareAuthBJJCredential(identifier);

      const authClaimData = await this.newCircuitClaimData({
        credential: authPrepared.credential,
        credentialCoreClaim: authPrepared.coreClaim
      });

      const signature = await this._identityWallet.signChallenge(
        circuitInputs.challenge,
        authPrepared.credential
      );

      circuitInputs.authClaim = authClaimData.claim;
      circuitInputs.authClaimIncMtp = authClaimData.proof;
      circuitInputs.authClaimNonRevMtp = authPrepared.nonRevProof.proof;
      circuitInputs.treeState = authClaimData.treeState;
      circuitInputs.signature = signature;
    }

    this.checkOperatorSupport(proofReq.circuitId, query.operator);

    return { inputs: circuitInputs.inputsMarshal(), metadata: { targetCircuitId } };
  };

  private linkedMultiQueryPrepareInputs = async ({
    preparedCredential,
    params,
    proofReq,
    circuitQueries
  }: InputContext): Promise<GenerateInputsResult> => {
    const { circuitId } = proofReq;

    const resolveQueryCount = (
      circuitId: CircuitId
    ): { queryCount: number; targetCircuitId: string } => {
      // if circuitId is LinkedMultiQuery10-beta.1, return 10
      if (circuitId === CircuitId.LinkedMultiQuery10) {
        return { queryCount: 10, targetCircuitId: CircuitId.LinkedMultiQuery10 };
      }
      if (circuitQueries.length <= 3) {
        return {
          queryCount: 3,
          targetCircuitId: CircuitId.LinkedMultiQueryStable + '3'
        };
      }
      if (circuitQueries.length <= 5) {
        return {
          queryCount: 5,
          targetCircuitId: CircuitId.LinkedMultiQueryStable + '5'
        };
      }
      return { queryCount: 10, targetCircuitId: CircuitId.LinkedMultiQueryStable };
    };

    const { queryCount, targetCircuitId } = resolveQueryCount(circuitId);

    const circuitClaimData = await this.newCircuitClaimData(preparedCredential);

    circuitClaimData.nonRevProof = toClaimNonRevStatus(preparedCredential.revStatus);
    const circuitInputs = new LinkedMultiQueryInputs(queryCount);
    circuitInputs.linkNonce = params.linkNonce ?? 0n;

    circuitInputs.claim = circuitClaimData.claim;
    circuitInputs.query = circuitQueries;

    circuitQueries.forEach((query) => {
      this.checkOperatorSupport(proofReq.circuitId, query.operator);
    });
    circuitQueries.forEach((query) => {
      query.values = [Operators.SD, Operators.NOOP].includes(query.operator) ? [] : query.values;
    });
    return { inputs: circuitInputs.inputsMarshal(), metadata: { targetCircuitId } };
  };

  linkedMultiQuery10PrepareInputs = async (ctx: InputContext): Promise<GenerateInputsResult> =>
    this.linkedMultiQueryPrepareInputs(ctx);

  private transformV2QueryOperator(operator: number): number {
    return operator === Operators.SD || operator === Operators.NOOP ? Operators.EQ : operator;
  }

  private checkOperatorSupport(circuitId: string, operator: number) {
    const supportedOperators =
      circuitValidator[circuitId as CircuitId].validation.supportedOperations;
    if (!supportedOperators.includes(operator)) {
      throw new Error(
        `operator ${getOperatorNameByValue(operator)} is not supported by ${circuitId}`
      );
    }
  }
}

function selectV3TargetCircuit(
  circuitId: CircuitId,
  treesToCheck: { proof?: Proof; levelKey: keyof CircuitSubversion }[],
  isOnChain = false
): CircuitSubversion | undefined {
  const subversions = circuitValidator[circuitId].subVersions;
  if (!subversions) {
    return undefined;
  }

  for (const subversion of subversions) {
    const { mtLevel, mtLevelClaim, mtLevelOnChain, targetCircuitId } = subversion;
    const filedLevelsDefined = isOnChain
      ? [mtLevel, mtLevelClaim, mtLevelOnChain]
      : [mtLevel, mtLevelClaim];

    if (filedLevelsDefined.some((lvl) => typeof lvl === 'undefined')) {
      continue;
    }

    const mtLevelsValid = treesToCheck.reduce((acc, proofMap) => {
      if (!proofMap.proof) {
        return acc;
      }
      const allSiblings = proofMap.proof.allSiblings();
      const levelDepth = subversion[proofMap.levelKey];
      if (typeof levelDepth !== 'number') {
        return acc;
      }
      return acc && allSiblings.length <= levelDepth - 1;
    }, true);

    if (mtLevelsValid) {
      return { mtLevel, mtLevelClaim, mtLevelOnChain, targetCircuitId };
    }
  }
  return undefined;
}
