/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  BJJSignatureProof2021,
  Iden3SparseMerkleTreeProof,
  CredentialStatus,
  RefreshService,
  DisplayMethod
} from './proof';
import {
  Claim,
  DID,
  MerklizedRootPosition as MerklizedRootPositionCore,
  IdPosition,
  ClaimOptions,
  getChainId
} from '@iden3/js-iden3-core';
import { Proof, Hash, rootFromProof, verifyProof } from '@iden3/js-merkletree';
import { Merklizer, Options } from '@iden3/js-jsonld-merklization';
import { PublicKey, poseidon } from '@iden3/js-crypto';
import { CredentialRequest, CredentialStatusResolverRegistry } from '../credentials';
import { getUserDIDFromCredential } from '../credentials/utils';
import { byteEncoder, validateDIDDocumentAuth } from '../utils';
import {
  CredentialStatusType,
  MerklizedRootPosition,
  ProofType,
  SubjectPosition,
  VerifiableConstants
} from './constants';
import {
  calculateCoreSchemaHash,
  CoreClaimCreationOptions,
  findCredentialType,
  parseCoreClaimSlots
} from './core-utils';

import { JsonDocumentObject } from '../iden3comm';
import jsonld from 'jsonld';

/**
 * W3C Verifiable credential
 *
 * @public
 * @export
 * @class W3CCredential
 */
export class W3CCredential {
  id = '';
  '@context': string[] = [];
  type: string[] = [];
  expirationDate?: string;
  refreshService?: RefreshService;
  displayMethod?: DisplayMethod;
  issuanceDate?: string;
  credentialSubject: JsonDocumentObject = {};
  credentialStatus!: CredentialStatus;
  issuer = '';
  credentialSchema!: CredentialSchema;
  proof?: object | unknown[];

  /**
   *
   * @param issuer - DID of the issuer
   * @param request - Credential request
   * @returns - W3C Credential
   */
  static fromCredentialRequest(issuer: DID, request: CredentialRequest): W3CCredential {
    if (!request.id) {
      throw new Error('Credential id is required');
    }
    if (!request.context) {
      throw new Error('Credential context is required');
    }

    const context = [
      VerifiableConstants.JSONLD_SCHEMA.W3C_CREDENTIAL_2018,
      VerifiableConstants.JSONLD_SCHEMA.IDEN3_CREDENTIAL,
      ...request.context
    ];

    const credentialType = [
      VerifiableConstants.CREDENTIAL_TYPE.W3C_VERIFIABLE_CREDENTIAL,
      request.type
    ];

    const credentialSubject = request.credentialSubject;
    credentialSubject['type'] = request.type;

    const cr = new W3CCredential();
    cr.id = request.id;
    cr['@context'] = context;
    cr.type = credentialType;
    cr.credentialSubject = credentialSubject;
    cr.issuer = issuer.string();
    cr.credentialSchema = {
      id: request.credentialSchema,
      type: VerifiableConstants.JSON_SCHEMA_VALIDATOR
    };
    cr.credentialStatus = W3CCredential.buildCredentialStatus(request, issuer);

    request.expiration && (cr.expirationDate = new Date(request.expiration).toISOString());
    request.refreshService && (cr.refreshService = request.refreshService);
    request.displayMethod && (cr.displayMethod = request.displayMethod);
    request.issuanceDate && (cr.issuanceDate = new Date(request.issuanceDate).toISOString());

    return cr;
  }

  /**
   * Builds credential status
   * @param {CredentialRequest} request
   * @returns `CredentialStatus`
   */
  private static buildCredentialStatus(request: CredentialRequest, issuer: DID): CredentialStatus {
    const credentialStatus: CredentialStatus = {
      id: request.revocationOpts.id,
      type: request.revocationOpts.type,
      revocationNonce: request.revocationOpts.nonce
    };

    switch (request.revocationOpts.type) {
      case CredentialStatusType.SparseMerkleTreeProof:
        return {
          ...credentialStatus,
          id: `${credentialStatus.id.replace(/\/$/, '')}/${credentialStatus.revocationNonce}`
        };
      case CredentialStatusType.Iden3ReverseSparseMerkleTreeProof:
        return {
          ...credentialStatus,
          id: request.revocationOpts.issuerState
            ? `${credentialStatus.id.replace(/\/$/, '')}/node?state=${
                request.revocationOpts.issuerState
              }`
            : `${credentialStatus.id.replace(/\/$/, '')}`
        };
      case CredentialStatusType.Iden3OnchainSparseMerkleTreeProof2023: {
        const issuerId = DID.idFromDID(issuer);
        const chainId = getChainId(DID.blockchainFromId(issuerId), DID.networkIdFromId(issuerId));
        const searchParams = [
          ['revocationNonce', request.revocationOpts.nonce?.toString() || ''],
          ['contractAddress', `${chainId}:${request.revocationOpts.id}`],
          ['state', request.revocationOpts.issuerState || '']
        ]
          .filter(([, value]) => Boolean(value))
          .map(([key, value]) => `${key}=${value}`)
          .join('&');

        return {
          ...credentialStatus,
          // `[did]:[methodid]:[chain]:[network]:[id]/credentialStatus?(revocationNonce=value)&[contractAddress=[chainID]:[contractAddress]]&(state=issuerState)`
          id: `${issuer.string()}/credentialStatus?${searchParams}`
        };
      }
      default:
        return credentialStatus;
    }
  }

  toJSON() {
    return {
      ...this,
      proof: Array.isArray(this.proof)
        ? this.proof.map(this.proofToJSON)
        : this.proofToJSON(this.proof)
    };
  }

  private proofToJSON(p: any) {
    if (!p) {
      return p;
    }
    if (!p['type']) {
      throw new Error('proof must have type property');
    }
    switch (p.type) {
      case ProofType.Iden3SparseMerkleTreeProof:
      case ProofType.BJJSignature:
        return p.toJSON();
      default:
        return p;
    }
  }

  private static proofFromJSON = (p: any) => {
    if (!p) {
      return p;
    }
    if (!p['type']) {
      throw new Error('proof must have type property');
    }
    switch (p.type) {
      case ProofType.Iden3SparseMerkleTreeProof:
        return Iden3SparseMerkleTreeProof.fromJSON(p);
      case ProofType.BJJSignature:
        return BJJSignatureProof2021.fromJSON(p);
      default:
        return p;
    }
  };

  static fromJSON(obj: any): W3CCredential {
    const w = new W3CCredential();
    Object.assign(w, structuredClone(obj));
    w.proof = Array.isArray(w.proof)
      ? w.proof.map(W3CCredential.proofFromJSON)
      : W3CCredential.proofFromJSON(w.proof);

    return w;
  }
  /**
   * merklization of the verifiable credential
   *
   * @returns `Promise<Merklizer>`
   */
  async merklize(opts?: Options): Promise<Merklizer> {
    const credential = { ...this };
    delete credential.proof;
    return await Merklizer.merklizeJSONLD(JSON.stringify(credential), opts);
  }

  /**
   * gets core claim representation from credential proof
   *
   * @param {ProofType} proofType
   * @returns {*}  {(Claim | undefined)}
   */
  getCoreClaimFromProof(proofType: ProofType): Claim | undefined {
    if (Array.isArray(this.proof)) {
      for (const proof of this.proof) {
        const { claim, proofType: extractedProofType } = extractProof(proof);
        if (proofType === extractedProofType) {
          return claim;
        }
      }
    } else if (typeof this.proof === 'object') {
      const { claim, proofType: extractedProofType } = extractProof(this.proof);
      if (extractedProofType == proofType) {
        return claim;
      }
    }
    return undefined;
  }

  /**
   * gets core claim representation from W3CCredential
   *
   * @param {CoreClaimParsingOptions} [opts] - options to create core claim
   * @returns {*}  {(Promise<Claim>)}
   */
  async toCoreClaim(opts?: CoreClaimCreationOptions): Promise<Claim> {
    if (!opts) {
      opts = {
        revNonce: 0,
        version: 0,
        subjectPosition: SubjectPosition.Index,
        merklizedRootPosition: MerklizedRootPosition.None,
        updatable: false,
        merklizeOpts: {}
      };
    }

    const mz = await this.merklize(opts.merklizeOpts);

    const credentialType = findCredentialType(mz);

    const subjectId = this.credentialSubject['id'];

    const ldCtx = await jsonld.processContext(
      await jsonld.processContext(null, null, {}),
      this['@context'] as jsonld.JsonLdDocument,
      mz.options
    );

    const { slots, nonMerklized } = await parseCoreClaimSlots(
      ldCtx as unknown as { mappings: Map<string, Record<string, unknown>> },
      mz,
      credentialType
    );

    // if schema is for non merklized credential, root position must be set to none ('')
    // otherwise default position for merklized position is index.
    if (nonMerklized && opts.merklizedRootPosition !== MerklizedRootPosition.None) {
      throw new Error('merklized root position is not supported for non-merklized claims');
    }
    if (!nonMerklized && opts.merklizedRootPosition === MerklizedRootPosition.None) {
      opts.merklizedRootPosition = MerklizedRootPosition.Index;
    }

    const schemaHash = calculateCoreSchemaHash(byteEncoder.encode(credentialType));
    const claim = Claim.newClaim(
      schemaHash,
      ClaimOptions.withIndexDataBytes(slots.indexA, slots.indexB),
      ClaimOptions.withValueDataBytes(slots.valueA, slots.valueB),
      ClaimOptions.withRevocationNonce(BigInt(opts.revNonce)),
      ClaimOptions.withVersion(opts.version)
    );

    if (opts.updatable) {
      claim.setFlagUpdatable(opts.updatable);
    }
    if (this.expirationDate) {
      claim.setExpirationDate(new Date(this.expirationDate));
    }
    if (subjectId) {
      const did = DID.parse(subjectId.toString());
      const id = DID.idFromDID(did);

      switch (opts.subjectPosition) {
        case '':
        case SubjectPosition.Index:
          claim.setIndexId(id);
          break;
        case SubjectPosition.Value:
          claim.setValueId(id);
          break;
        default:
          throw new Error('unknown subject position');
      }
    }

    switch (opts.merklizedRootPosition) {
      case MerklizedRootPosition.Index: {
        const mk = await this.merklize(opts.merklizeOpts);
        claim.setIndexMerklizedRoot((await mk.root()).bigInt());
        break;
      }
      case MerklizedRootPosition.Value: {
        const mk = await this.merklize(opts.merklizeOpts);
        claim.setValueMerklizedRoot((await mk.root()).bigInt());
        break;
      }
      case MerklizedRootPosition.None:
        break;
      default:
        throw new Error('unknown merklized root position');
    }

    return claim;
  }

  /**
   * checks BJJSignatureProof2021 in W3C VC
   *
   * @returns BJJSignatureProof2021 | undefined
   */
  getBJJSignature2021Proof(): BJJSignatureProof2021 | undefined {
    const proof = this.getProofByType(ProofType.BJJSignature);
    if (proof) {
      return proof as BJJSignatureProof2021;
    }
    return undefined;
  }

  /**
   * checks Iden3SparseMerkleTreeProof in W3C VC
   *
   * @returns {*}  {(Iden3SparseMerkleTreeProof | undefined)}
   */
  getIden3SparseMerkleTreeProof(): Iden3SparseMerkleTreeProof | undefined {
    const proof = this.getProofByType(ProofType.Iden3SparseMerkleTreeProof);
    if (proof) {
      return proof as Iden3SparseMerkleTreeProof;
    }
    return undefined;
  }

  /**
   * Verify credential proof
   *
   * @returns {*}  {(boolean)}
   */
  async verifyProof(
    proofType: ProofType,
    resolverURL: string,
    opts?: W3CProofVerificationOptions
  ): Promise<boolean> {
    const proof = this.getProofByType(proofType);
    if (!proof) {
      throw new Error('proof not found');
    }

    const coreClaim = this.getCoreClaimFromProof(proofType);
    if (!coreClaim) {
      throw new Error(`can't get core claim`);
    }

    await this.verifyCoreClaimMatch(coreClaim, opts?.merklizeOptions);

    switch (proofType) {
      case ProofType.BJJSignature: {
        if (!opts?.credStatusResolverRegistry) {
          throw new Error('please provide credential status resolver registry');
        }
        const bjjProof = proof as BJJSignatureProof2021;
        const userDID = getUserDIDFromCredential(bjjProof.issuerData.id, this);
        return this.verifyBJJSignatureProof(
          bjjProof,
          coreClaim,
          resolverURL,
          userDID,
          opts.credStatusResolverRegistry
        );
      }
      case ProofType.Iden3SparseMerkleTreeProof: {
        return this.verifyIden3SparseMerkleTreeProof(
          proof as Iden3SparseMerkleTreeProof,
          coreClaim,
          resolverURL
        );
      }
      default: {
        throw new Error('invalid proof type');
      }
    }
  }

  /**
   * Verify credential proofs
   *
   * @returns {*}  {(boolean)}
   */
  async verifyProofs(resolverURL: string, opts?: W3CProofVerificationOptions): Promise<boolean> {
    const proofsValidPromises = [];
    if (Array.isArray(this.proof)) {
      for (const proof of this.proof) {
        proofsValidPromises.push(this.verifyProof(proof['type'] as ProofType, resolverURL, opts));
      }
    } else {
      proofsValidPromises.push(
        this.verifyProof(
          (this.proof as unknown as { type: ProofType })['type'] as ProofType,
          resolverURL,
          opts
        )
      );
    }
    const proofsValid = await Promise.all(proofsValidPromises);
    return proofsValid.every((v) => v);
  }

  private async verifyCoreClaimMatch(coreClaim: Claim, merklizeOpts?: Options) {
    let merklizedRootPosition = '';

    const merklizedPosition = coreClaim.getMerklizedPosition();
    switch (merklizedPosition) {
      case MerklizedRootPositionCore.None:
        merklizedRootPosition = MerklizedRootPosition.None;
        break;
      case MerklizedRootPositionCore.Index:
        merklizedRootPosition = MerklizedRootPosition.Index;
        break;
      case MerklizedRootPositionCore.Value:
        merklizedRootPosition = MerklizedRootPosition.Value;
        break;
    }

    let subjectPosition = '';
    const idPosition = coreClaim.getIdPosition();
    switch (idPosition) {
      case IdPosition.None:
        subjectPosition = SubjectPosition.None;
        break;
      case IdPosition.Index:
        subjectPosition = SubjectPosition.Index;
        break;
      case IdPosition.Value:
        subjectPosition = SubjectPosition.Value;
        break;
    }

    const coreClaimOpts: CoreClaimCreationOptions = {
      revNonce: Number(coreClaim.getRevocationNonce()),
      version: coreClaim.getVersion(),
      merklizedRootPosition,
      subjectPosition,
      updatable: coreClaim.getFlagUpdatable(),
      merklizeOpts: merklizeOpts
    };

    const credentialCoreClaim = await this.toCoreClaim(coreClaimOpts);
    if (coreClaim.hex() != credentialCoreClaim.hex()) {
      throw new Error('proof generated for another credential');
    }
  }

  private async verifyBJJSignatureProof(
    proof: BJJSignatureProof2021,
    coreClaim: Claim,
    resolverURL: string,
    userDID: DID,
    credStatusResolverRegistry: CredentialStatusResolverRegistry
  ): Promise<boolean> {
    // issuer auth claim
    const authClaim = proof.issuerData.authCoreClaim;
    const rawSlotsInt = authClaim.rawSlotsAsInts();
    const pubKey = new PublicKey([rawSlotsInt[2], rawSlotsInt[3]]);

    // core claim hash
    const { hi, hv } = coreClaim.hiHv();
    const claimHash = poseidon.hash([hi, hv]);
    const bjjValid = pubKey.verifyPoseidon(claimHash, proof.signature);

    if (!bjjValid) {
      throw new Error('signature is not valid');
    }
    await validateDIDDocumentAuth(proof.issuerData.id, resolverURL, proof.issuerData.state.value);

    const issuerState = proof.issuerData.state;
    const wantState = poseidon.hash([
      issuerState.claimsTreeRoot.bigInt(),
      issuerState.revocationTreeRoot.bigInt(),
      issuerState.rootOfRoots.bigInt()
    ]);
    if (wantState !== issuerState.value.bigInt()) {
      throw new Error(
        'signature proof: issuer state value does not match its claims/revocation/roots tree roots'
      );
    }
    const { hi: hiAuth, hv: hvAuth } = authClaim.hiHv();
    const authClaimRootFromProof = await rootFromProof(proof.issuerData.mtp, hiAuth, hvAuth);
    if (!authClaimRootFromProof.equals(issuerState.claimsTreeRoot)) {
      throw new Error(
        'signature proof: issuer auth claim is not included in the issuer claims tree root'
      );
    }

    const credStatusType = proof.issuerData.credentialStatus.type;
    const credStatusResolver = await credStatusResolverRegistry.get(credStatusType);
    if (!credStatusResolver) {
      throw new Error(`please register credential status resolver for ${credStatusType} type`);
    }
    const credStatus = await credStatusResolver.resolve(proof.issuerData.credentialStatus, {
      issuerDID: proof.issuerData.id,
      userDID: userDID
    });
    const stateValid = validateTreeState(credStatus.issuer);
    if (!stateValid) {
      throw new Error(
        'signature proof: invalid tree state of the issuer while checking credential status of singing key'
      );
    }

    const revocationNonce = BigInt(proof.issuerData.credentialStatus.revocationNonce || 0);
    if (revocationNonce !== proof.issuerData.authCoreClaim.getRevocationNonce()) {
      throw new Error(
        `revocation nonce mismatch: revocation nonce from core representation of auth credential is not the same as in its credential`
      );
    }
    const proofValid = await verifyProof(
      Hash.fromHex(credStatus.issuer.revocationTreeRoot),
      credStatus.mtp,
      revocationNonce,
      BigInt(0)
    );
    if (!proofValid) {
      throw new Error(`proof validation failed. revNonce=${revocationNonce}`);
    }
    if (credStatus.mtp.existence) {
      throw new Error('signature proof: singing key of the issuer is revoked');
    }
    return true;
  }

  private async verifyIden3SparseMerkleTreeProof(
    proof: Iden3SparseMerkleTreeProof,
    coreClaim: Claim,
    resolverURL: string
  ): Promise<boolean> {
    await validateDIDDocumentAuth(proof.issuerData.id, resolverURL, proof.issuerData.state.value);

    const issuerState = proof.issuerData.state;
    const wantState = poseidon.hash([
      issuerState.claimsTreeRoot.bigInt(),
      issuerState.revocationTreeRoot.bigInt(),
      issuerState.rootOfRoots.bigInt()
    ]);
    if (wantState !== issuerState.value.bigInt()) {
      throw new Error(
        'verifyIden3SparseMerkleTreeProof: issuer state value does not match its claims/revocation/roots tree roots'
      );
    }

    // root from proof == issuerData.state.claimsTreeRoot
    const { hi, hv } = coreClaim.hiHv();
    const rootFromProofValue = await rootFromProof(proof.mtp, hi, hv);
    if (!rootFromProofValue.equals(proof.issuerData.state.claimsTreeRoot)) {
      throw new Error(
        'verifyIden3SparseMerkleTreeProof: root from proof not equal to issuer data claims tree root'
      );
    }
    return true;
  }

  private getProofByType(proofType: ProofType): unknown | undefined {
    if (Array.isArray(this.proof)) {
      for (const proof of this.proof) {
        if ((proof as { [k: string]: ProofType })?.type === proofType) {
          return proof;
        }
      }
    } else if ((this.proof as { [k: string]: ProofType })?.type == proofType) {
      return this.proof;
    }
    return undefined;
  }
}

/**
 * extracts core claim from Proof and returns Proof Type
 *
 * @param {object} proof - proof of vc
 * @returns {*}  {{ claim: Claim; proofType: ProofType }}
 */
export function extractProof(proof: object): { claim: Claim; proofType: ProofType } {
  if (proof instanceof Iden3SparseMerkleTreeProof) {
    return {
      claim: proof.coreClaim,
      proofType: ProofType.Iden3SparseMerkleTreeProof
    };
  }
  if (proof instanceof BJJSignatureProof2021) {
    return { claim: proof.coreClaim, proofType: ProofType.BJJSignature };
  }
  if (typeof proof === 'object') {
    const p = proof as { type: ProofType; coreClaim: string | Claim };
    const defaultProofType: ProofType = p.type;
    if (!defaultProofType) {
      throw new Error('proof type is not specified');
    }

    if (!p.coreClaim) {
      throw new Error(`coreClaim field is not defined in proof type ${defaultProofType}`);
    }

    const coreClaim = p.coreClaim instanceof Claim ? p.coreClaim : new Claim().fromHex(p.coreClaim);

    return { claim: coreClaim, proofType: defaultProofType as ProofType };
  }

  throw new Error('proof format is not supported');
}

/**
 * validate tree state by recalculating poseidon hash of roots and comparing with state
 *
 * @param {Issuer} treeState - issuer struct
 * @returns {boolean}
 */
export function validateTreeState(treeState: Issuer) {
  const ctrHash = treeState.claimsTreeRoot ? Hash.fromHex(treeState.claimsTreeRoot) : new Hash();
  const rtrHash = treeState.revocationTreeRoot
    ? Hash.fromHex(treeState.revocationTreeRoot)
    : new Hash();
  const rorHash = treeState.rootOfRoots ? Hash.fromHex(treeState.rootOfRoots) : new Hash();
  const wantState = poseidon.hash([ctrHash.bigInt(), rtrHash.bigInt(), rorHash.bigInt()]);

  const stateHash = treeState.state ? Hash.fromHex(treeState.state) : new Hash();
  return wantState === stateHash.bigInt();
}

/**
 * Credential schema vc
 *
 * @public
 * @interface   CredentialSchema
 */
export interface CredentialSchema {
  id: string;
  type: string;
}

/**
 * Issuer tree information
 *
 * @public
 * @interface   Issuer
 */
export interface Issuer {
  state?: string;
  rootOfRoots?: string;
  claimsTreeRoot?: string;
  revocationTreeRoot?: string;
}

/**
 *
 * RevocationStatus status of revocation nonce. Info required to check revocation state of claim in circuits
 * @public
 * @interface   RevocationStatus
 */
export interface RevocationStatus {
  mtp: Proof;
  issuer: Issuer;
}

/**
 *
 * Proof verification options
 * @public
 * @interface   W3CProofVerificationOptions
 */
export interface W3CProofVerificationOptions {
  credStatusResolverRegistry?: CredentialStatusResolverRegistry;
  merklizeOptions?: Options;
}
