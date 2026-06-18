import { Hash, Proof } from '@iden3/js-merkletree';
import {
  ProofType,
  CredentialStatusType,
  RefreshServiceType,
  DisplayMethodType
} from './constants';
import { TreeState } from '../circuits';
import { Hex, Signature } from '@iden3/js-crypto';
import { Claim, DID } from '@iden3/js-iden3-core';
import { JsonDocumentObject, JSONObject } from '../iden3comm';

/**
 * Represents the published state of the issuer
 *
 * @public
 * @interface   State
 */
export interface State {
  txId?: string;
  blockTimestamp?: number;
  blockNumber?: number;
  rootOfRoots: Hash;
  claimsTreeRoot: Hash;
  revocationTreeRoot: Hash;
  value: Hash;
  status?: string;
}

/**
 * Iden3SparseMerkleProof is a iden3 protocol merkle tree proof
 *
 * @public
 * @class Iden3SparseMerkleTreeProof
 */
export class Iden3SparseMerkleTreeProof {
  type: ProofType;
  issuerData: {
    id: DID;
    state: State;
  };
  mtp: Proof;
  coreClaim: Claim;
  /**
   * Creates an instance of Iden3SparseMerkleTreeProof.
   * @param {object} obj
   */
  constructor(obj: {
    issuerData: {
      id: DID;
      state: State;
    };
    mtp: Proof;
    coreClaim: Claim;
  }) {
    this.coreClaim = obj.coreClaim;
    this.issuerData = obj.issuerData;
    this.type = ProofType.Iden3SparseMerkleTreeProof;
    this.mtp = obj.mtp;
  }

  /**
   *
   *
   * @returns `json object in serialized presentation`
   */
  toJSON() {
    const issuerId = this.issuerData.id;
    return {
      issuerData: {
        id: issuerId.string(),
        state: {
          ...this.issuerData.state,
          rootOfRoots: this.issuerData.state.rootOfRoots.hex(),
          claimsTreeRoot: this.issuerData.state.claimsTreeRoot.hex(),
          revocationTreeRoot: this.issuerData.state.revocationTreeRoot.hex(),
          value: this.issuerData.state.value.hex()
        }
      },
      type: this.type,
      coreClaim: this.coreClaim.hex(),
      mtp: this.mtp.toJSON()
    };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static fromJSON(obj: any) {
    let mtp: Proof;
    if (obj?.mtp?.notEmpties && obj?.mtp?.depth && obj?.mtp?.siblings) {
      // legacy

      const ne = obj?.mtp?.notEmpties;
      const notEmpties = ne instanceof Uint8Array ? ne : new Uint8Array(Object.values(ne));
      const siblingsHashes = obj?.mtp?.siblings.map((h: unknown) =>
        Hash.fromString(JSON.stringify(h))
      );
      const allSiblings = Proof.buildAllSiblings(obj?.mtp?.depth, notEmpties, siblingsHashes);
      let nodeAux = obj.mtp.nodeAux || obj.mtp.node_aux;
      if (nodeAux) {
        nodeAux = {
          key: Hash.fromString(JSON.stringify(nodeAux.key)),
          value: Hash.fromString(JSON.stringify(nodeAux.value))
        };
      }
      mtp = new Proof({ existence: obj?.mtp.existence, nodeAux: nodeAux, siblings: allSiblings });
    } else {
      mtp = Proof.fromJSON(obj.mtp);
    }

    return new Iden3SparseMerkleTreeProof({
      coreClaim: new Claim().fromHex(obj.coreClaim),
      mtp,
      issuerData: {
        id: DID.parse(obj.issuerData.id),
        state: {
          ...obj.issuerData.state,
          rootOfRoots: Hash.fromHex(obj.issuerData.state.rootOfRoots),
          claimsTreeRoot: Hash.fromHex(obj.issuerData.state.claimsTreeRoot),
          revocationTreeRoot: Hash.fromHex(obj.issuerData.state.revocationTreeRoot),
          value: Hash.fromHex(obj.issuerData.state.value)
        }
      }
    });
  }
}

/**
 *
 * BJJSignatureProof2021 is a signature of core claim by BJJ key
 * @public
 * @class BJJSignatureProof2021
 */
export class BJJSignatureProof2021 {
  type: ProofType;
  issuerData: {
    id: DID;
    state: State;
    authCoreClaim: Claim;
    mtp: Proof;
    credentialStatus: CredentialStatus;
  };
  signature: Signature;
  coreClaim: Claim;

  constructor(obj: {
    issuerData: {
      id: DID;
      state: State;
      authCoreClaim: Claim;
      mtp: Proof;
      credentialStatus: CredentialStatus;
    };
    coreClaim: Claim;
    signature: Signature;
  }) {
    this.type = ProofType.BJJSignature;
    this.issuerData = obj.issuerData;
    this.coreClaim = obj.coreClaim;
    this.signature = obj.signature;
  }

  /**
   * toJSON is a method to serialize BJJSignatureProof2021 to json
   *
   * @returns `json object in serialized presentation`
   */
  toJSON() {
    return {
      issuerData: {
        id: this.issuerData.id.string(),
        state: {
          ...this.issuerData.state,
          rootOfRoots: this.issuerData.state.rootOfRoots.hex(),
          claimsTreeRoot: this.issuerData.state.claimsTreeRoot.hex(),
          revocationTreeRoot: this.issuerData.state.revocationTreeRoot.hex(),
          value: this.issuerData.state.value.hex()
        },
        mtp: this.issuerData.mtp.toJSON(),
        authCoreClaim: this.issuerData.authCoreClaim.hex(),
        credentialStatus: this.issuerData.credentialStatus
      },
      type: this.type,
      coreClaim: this.coreClaim.hex(),
      signature: Hex.encodeString(this.signature.compress())
    };
  }

  /**
   * fromJSON is a method to deserialize BJJSignatureProof2021 from json
   * @param obj
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static fromJSON(obj: any) {
    return new BJJSignatureProof2021({
      issuerData: {
        id: DID.parse(obj.issuerData.id),
        mtp: Proof.fromJSON(obj.issuerData.mtp),
        state: {
          ...obj.issuerData.state,
          rootOfRoots: Hash.fromHex(obj.issuerData.state.rootOfRoots),
          claimsTreeRoot: Hash.fromHex(obj.issuerData.state.claimsTreeRoot),
          revocationTreeRoot: Hash.fromHex(obj.issuerData.state.revocationTreeRoot),
          value: Hash.fromHex(obj.issuerData.state.value)
        },
        credentialStatus: obj.issuerData.credentialStatus,
        authCoreClaim: new Claim().fromHex(obj.issuerData.authCoreClaim)
      },
      coreClaim: new Claim().fromHex(obj.coreClaim),
      signature: Signature.newFromCompressed(
        Uint8Array.from(Hex.decodeString(obj.signature)).slice(0, 64)
      )
    });
  }
}
/**
 *  Query represents structure for query to atomic circuit
 *
 * @public
 * @interface   ProofQuery
 */
export interface ProofQuery {
  allowedIssuers?: string[];
  credentialSubject?: JsonDocumentObject;
  schema?: string; // string url
  claimId?: string;
  credentialSubjectId?: string;
  context?: string;
  type?: string;
  skipClaimRevocationCheck?: boolean;
  proofType?: string;
  groupId?: number;
  params?: JSONObject;
  expirationDate?: JsonDocumentObject;
  issuanceDate?: JsonDocumentObject;
  credentialStatus?: JsonDocumentObject;
}

/**
 * Proof with MerkleTree info
 *
 * @public
 * @interface   MerkleTreeProofWithTreeState
 */
export interface MerkleTreeProofWithTreeState {
  proof: Proof;
  treeState: TreeState;
}

/**
 *
 * CredentialStatus contains type and revocation Url
 * @public
 * @interface   CredentialStatus
 */
export interface CredentialStatus {
  id: string;
  type: CredentialStatusType;
  revocationNonce?: number;
  statusIssuer?: { id: string; type: CredentialStatusType; revocationNonce?: number };
}

/**
 * RefreshService contains type and id
 * @public
 * @interface   RefreshService
 */
export interface RefreshService {
  id: string;
  type: RefreshServiceType | string;
}

/**
 * DisplayMethod contains type and id
 * @public
 * @interface   DisplayMethod
 */
export interface DisplayMethod {
  id: string;
  type: DisplayMethodType | string;
}
