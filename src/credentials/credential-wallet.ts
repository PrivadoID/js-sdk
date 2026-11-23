import { DID } from '@iden3/js-iden3-core';
import { IDataStorage } from '../storage/interfaces';
import {
  W3CCredential,
  ProofQuery,
  VerifiableConstants,
  CredentialStatus,
  RevocationStatus,
  CredentialStatusType,
  State,
  DisplayMethodType,
  ProofType
} from './../verifiable';

import { JSONSchema } from '../schema-processor';
import * as uuid from 'uuid';
import { CredentialStatusResolverRegistry } from './status/resolver';
import { IssuerResolver } from './status/sparse-merkle-tree';
import { AgentResolver } from './status/agent-revocation';
import { CredentialStatusResolveOptions } from './status/resolver';
import { getUserDIDFromCredential } from './utils';
import { CredentialRequest } from './models';

/**
 * Interface to work with credential wallets
 *
 * @public
 * @interface   ICredentialWallet
 */
export interface ICredentialWallet {
  /**
   * List of W3C Credential
   *
   * @returns `Promise<W3CCredential[]`
   */
  list(): Promise<W3CCredential[]>;
  /**
   * saves W3C credential (upsert)
   * @param {W3CCredential} credential - credential to save
   * @returns `Promise<void>`
   *
   */
  save(credential: W3CCredential): Promise<void>;
  /**
   * saves the batch of W3C credentials (upsert)
   * @param {W3CCredential[]} credentials - credentials to save
   * @returns `Promise<void>`
   */
  saveAll(credentials: W3CCredential[]): Promise<void>;

  /**
   *
   * removes W3C credentials from data storage
   * @param {string} id
   * @returns `Promise<void>`
   */
  remove(id: string): Promise<void>;
  /**
   * Find credential using iden3 query language
   *
   * @param {ProofQuery} query  - protocol query to find credential
   * @returns `Promise<W3CCredential[]>`
   */
  findByQuery(query: ProofQuery): Promise<W3CCredential[]>;
  /**
   * Finds the credential by its id
   *
   * @param {string} id - id of credential
   * @returns `Promise<W3CCredential | undefined>`
   */
  findById(id: string): Promise<W3CCredential | undefined>;
  /**
   * Finds credentials by JSON-LD schema and type
   *
   * @param {string} context - the URL of JSON-LD schema where type is defined
   * @returns `Promise<W3CCredential[]>`
   */
  findByContextType(context: string, type: string): Promise<W3CCredential[]>;

  /**
   * Filters given credentials with given credential subject
   *
   * @param {W3CCredential[]} credentials - credentials to filter
   * @param {DID} subject - credential subject id
   * @returns `Promise<W3CCredential[]>`
   */
  filterByCredentialSubject(credentials: W3CCredential[], subject: DID): Promise<W3CCredential[]>;
  /**
   * Finds first non-revoked Auth BJJ credential for given user
   *
   * @param {DID} did - the issuer of Auth BJJ credential
   * @returns `Promise<W3CCredential>` W3CCredential with AuthBJJCredential type
   */
  getAuthBJJCredential(did: DID): Promise<W3CCredential>;

  /**
   * Finds all Auth BJJ credentials for given user
   *
   * @param {DID} did - the issuer of Auth BJJ credential
   * @returns `Promise<W3CCredential[]>` W3CCredentials with AuthBJJCredential type
   */
  getAllAuthBJJCredentials(did: DID): Promise<W3CCredential[]>;

  /**
   * Fetches or Builds a revocation status for a given credential
   * Supported types for credentialStatus field: SparseMerkleTreeProof, Iden3ReverseSparseMerkleTreeProof
   *
   * @param {W3CCredential} cred - credential for which lib should build revocation status
   * @returns `Promise<RevocationStatus>`
   */
  getRevocationStatusFromCredential(cred: W3CCredential): Promise<RevocationStatus>;
  /**
   * Fetches Revocation status depended on type
   *
   * @param {(CredentialStatus )} credStatus - credentialStatus field of the Verifiable Credential.  Supported types for credentialStatus field: SparseMerkleTreeProof, Iden3ReverseSparseMerkleTreeProof
   * @param {CredentialStatusResolveOptions} credentialStatusResolveOptions - options to resolve credential status
   * @returns `Promise<RevocationStatus>`
   */
  getRevocationStatus(
    credStatus: CredentialStatus,
    credentialStatusResolveOptions?: CredentialStatusResolveOptions
  ): Promise<RevocationStatus>;
  /**
   * Creates a W3C verifiable Credential object
   *
   * @param {string} hostUrl - URL that will be used as a prefix for credential identifier
   * @param {DID} issuer - issuer identity
   * @param {CredentialRequest} request - specification of claim creation parameters
   * @param {JSONSchema} schema - JSON schema for W3C Verifiable Credential
   * @returns W3CCredential
   */
  createCredential(issuer: DID, request: CredentialRequest, schema: JSONSchema): W3CCredential;

  /**
   * Finds non-revoked credential from a given list by resolving their credential status
   *
   * @param {W3CCredential[]} creds
   * @returns `{Promise<{
   *     cred: W3CCredential;
   *     revStatus: RevocationStatus;
   *   }>` not revoked credential and it's revocation status
   */
  findNonRevokedCredential(creds: W3CCredential[]): Promise<{
    cred: W3CCredential;
    revStatus: RevocationStatus;
  }>;

  /**
   * getCredentialStatusResolverRegistry
   * @returns {CredentialStatusResolverRegistry | undefined} - returns credential status resolver registry or undefined
   */
  getCredentialStatusResolverRegistry(): CredentialStatusResolverRegistry | undefined;
}

/**
 *
 * Wallet instance is a wrapper of CRUD logic for W3C credentials,
 * also it allows to fetch revocation statuses.
 *
 * @public
 * @class CredentialWallet
 * @implements implements ICredentialWallet interface
 */
export class CredentialWallet implements ICredentialWallet {
  /**
   * Creates an instance of CredentialWallet.
   * @param {IDataStorage} _storage - data storage to access credential / identity / Merkle tree data
   * @param {CredentialStatusResolverRegistry} _credentialStatusResolverRegistry - list of credential status resolvers
   * if _credentialStatusResolverRegistry is not provided, default resolvers will be used
   */
  constructor(
    private readonly _storage: IDataStorage,
    private readonly _credentialStatusResolverRegistry?: CredentialStatusResolverRegistry
  ) {
    // if no credential status resolvers are provided
    // register default issuer resolver
    if (!this._credentialStatusResolverRegistry) {
      this._credentialStatusResolverRegistry = new CredentialStatusResolverRegistry();
      this._credentialStatusResolverRegistry.register(
        CredentialStatusType.SparseMerkleTreeProof,
        new IssuerResolver()
      );
      this._credentialStatusResolverRegistry.register(
        CredentialStatusType.Iden3commRevocationStatusV1,
        new AgentResolver()
      );
    }
  }

  /**
   * {@inheritDoc ICredentialWallet.getCredentialStatusResolverRegistry}
   */
  getCredentialStatusResolverRegistry(): CredentialStatusResolverRegistry | undefined {
    return this._credentialStatusResolverRegistry;
  }

  /**
   * {@inheritDoc ICredentialWallet.getAuthBJJCredential}
   */
  async getAuthBJJCredential(did: DID): Promise<W3CCredential> {
    // filter where the issuer of auth credential is given did

    const authBJJCredsOfIssuer = await this._storage.credential.findCredentialsByQuery({
      context: VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD_URL,
      type: VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_TYPE,
      allowedIssuers: [did.string()]
    });

    if (!authBJJCredsOfIssuer.length) {
      throw new Error(VerifiableConstants.ERRORS.NO_AUTH_CRED_FOUND);
    }

    for (let index = 0; index < authBJJCredsOfIssuer.length; index++) {
      const authCred = authBJJCredsOfIssuer[index];
      const revocationStatus = await this.getRevocationStatusFromCredential(authCred);

      if (!revocationStatus.mtp.existence) {
        return authCred;
      }
    }
    throw new Error('all auth bjj credentials are revoked');
  }

  /**
   * {@inheritDoc ICredentialWallet.getAllAuthBJJCredentials}
   */
  async getAllAuthBJJCredentials(did: DID): Promise<W3CCredential[]> {
    return this._storage.credential.findCredentialsByQuery({
      context: VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD_URL,
      type: VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_TYPE,
      allowedIssuers: [did.string()]
    });
  }

  /**
   * {@inheritDoc ICredentialWallet.getRevocationStatusFromCredential}
   */
  async getRevocationStatusFromCredential(cred: W3CCredential): Promise<RevocationStatus> {
    const mtpProof = cred.getIden3SparseMerkleTreeProof();
    const sigProof = cred.getBJJSignature2021Proof();

    const stateInfo: State | undefined = mtpProof
      ? mtpProof.issuerData.state
      : sigProof?.issuerData.state;
    const issuerDID = DID.parse(cred.issuer);

    const userDID = getUserDIDFromCredential(issuerDID, cred);

    const opts: CredentialStatusResolveOptions = {
      issuerGenesisState: stateInfo,
      issuerDID,
      userDID
    };

    return this.getRevocationStatus(cred.credentialStatus, opts);
  }

  /**
   * {@inheritDoc ICredentialWallet.getRevocationStatus}
   */
  async getRevocationStatus(
    credStatus: CredentialStatus,
    credentialStatusResolveOptions?: CredentialStatusResolveOptions
  ): Promise<RevocationStatus> {
    const statusResolver = this._credentialStatusResolverRegistry?.get(credStatus.type);
    if (!statusResolver) {
      throw new Error(`credential status resolver does not exist for ${credStatus.type} type`);
    }

    return statusResolver.resolve(credStatus, credentialStatusResolveOptions);
  }
  /**
   * {@inheritDoc ICredentialWallet.createCredential}
   */
  createCredential = (
    issuer: DID,
    request: CredentialRequest,
    schema: JSONSchema
  ): W3CCredential => {
    if (!schema.$metadata.uris['jsonLdContext']) {
      throw new Error('jsonLdContext is missing is the schema');
    }
    // do copy of request to avoid mutation
    const r = { ...request };
    r.context = r.context ?? [];
    if (
      r.displayMethod?.type === DisplayMethodType.Iden3BasicDisplayMethodV1 &&
      !r.context.includes(VerifiableConstants.JSONLD_SCHEMA.IDEN3_DISPLAY_METHOD)
    ) {
      r.context.push(VerifiableConstants.JSONLD_SCHEMA.IDEN3_DISPLAY_METHOD);
    }
    r.context.push(schema.$metadata.uris['jsonLdContext']);
    r.expiration = r.expiration ? r.expiration * 1000 : undefined;
    r.id = r.id ? r.id : `urn:${uuid.v4()}`;
    r.issuanceDate = r.issuanceDate ? r.issuanceDate * 1000 : Date.now();

    return W3CCredential.fromCredentialRequest(issuer, r);
  };

  /**
   * {@inheritDoc ICredentialWallet.findById}
   */
  async findById(id: string): Promise<W3CCredential | undefined> {
    return this._storage.credential.findCredentialById(id);
  }
  /**
   * {@inheritDoc ICredentialWallet.findByContextType}
   */
  async findByContextType(context: string, type: string): Promise<W3CCredential[]> {
    return this._storage.credential.findCredentialsByQuery({ context, type });
  }
  /**
   * {@inheritDoc ICredentialWallet.save}
   */
  async save(credential: W3CCredential): Promise<void> {
    return this._storage.credential.saveCredential(credential);
  }
  /**
   * {@inheritDoc ICredentialWallet.saveAll}
   */
  async saveAll(credentials: W3CCredential[]): Promise<void> {
    return this._storage.credential.saveAllCredentials(credentials);
  }
  /**
   * {@inheritDoc ICredentialWallet.remove}
   */
  async remove(id: string): Promise<void> {
    return this._storage.credential.removeCredential(id);
  }
  /**
   * {@inheritDoc ICredentialWallet.list}
   */
  async list(): Promise<W3CCredential[]> {
    return this._storage.credential.listCredentials();
  }
  /**
   * {@inheritDoc ICredentialWallet.findByQuery}
   */
  async findByQuery(query: ProofQuery): Promise<W3CCredential[]> {
    return this._storage.credential.findCredentialsByQuery(query);
  }

  /**
   * {@inheritDoc ICredentialWallet.filterByCredentialSubject}
   */
  async filterByCredentialSubject(
    credentials: W3CCredential[],
    subject: DID
  ): Promise<W3CCredential[]> {
    return credentials.filter((cred: W3CCredential) => {
      return cred.credentialSubject['id'] === subject.string();
    });
  }
  async findNonRevokedCredential(creds: W3CCredential[]): Promise<{
    cred: W3CCredential;
    revStatus: RevocationStatus;
  }> {
    for (const cred of creds) {
      const revStatus = await this.getRevocationStatusFromCredential(cred);
      if (revStatus.mtp.existence) {
        continue;
      }
      return { cred, revStatus };
    }
    throw new Error(VerifiableConstants.ERRORS.CREDENTIAL_WALLET_ALL_CREDENTIALS_ARE_REVOKED);
  }
}

/**
 * Options of {@link isRevokedByIssuerAuthClaim}
 *
 * @public
 * @property {ProofType} [proofType] - proof type the credential will be proven with, when the
 *   circuit or the query forces one (see getRequiredProofType)
 */
export type IssuerAuthClaimCheckOptions = {
  proofType?: ProofType;
};

/**
 * Resolves the revocation status of the issuer auth claim (BJJ key) that signed the credential's
 * BJJSignature2021 proof. Circuits always verify that this auth claim is not revoked, so a
 * credential signed with a revoked one can't be proven with its signature anymore, although its
 * own revocation nonce may still be valid. The status is also the issuer auth non-revocation proof
 * used when the credential is proven, so it can be reused there instead of being resolved again.
 *
 * Only resolved when the signature will be used: when `opts.proofType` is BJJSignature2021, or,
 * without a proof type, when the credential has no Iden3SparseMerkleTreeProof (js-sdk proves
 * credentials via MTP by default).
 *
 * @param {ICredentialWallet} credentialWallet - wallet used to resolve the auth claim status
 * @param {W3CCredential} credential - credential to check
 * @param {IssuerAuthClaimCheckOptions} [opts] - proof type the credential will be proven with
 * @returns `Promise<RevocationStatus | undefined>` - undefined when the signature won't be used,
 *   or when its auth claim has no credential status
 */
export const getIssuerAuthClaimRevocationStatus = async (
  credentialWallet: ICredentialWallet,
  credential: W3CCredential,
  opts?: IssuerAuthClaimCheckOptions
): Promise<RevocationStatus | undefined> => {
  const usesSignature = opts?.proofType
    ? opts.proofType === ProofType.BJJSignature
    : !credential.getIden3SparseMerkleTreeProof();
  if (!usesSignature) {
    return undefined;
  }
  const sigProof = credential.getBJJSignature2021Proof();
  if (!sigProof?.issuerData.credentialStatus) {
    return undefined;
  }
  const issuerDID = sigProof.issuerData.id;
  return credentialWallet.getRevocationStatus(sigProof.issuerData.credentialStatus, {
    issuerGenesisState: sigProof.issuerData.state,
    issuerDID,
    userDID: getUserDIDFromCredential(issuerDID, credential)
  });
};

/**
 * Checks whether a credential is revoked because the issuer revoked the auth claim (BJJ key)
 * that signed its BJJSignature2021 proof (see {@link getIssuerAuthClaimRevocationStatus}).
 *
 * @param {ICredentialWallet} credentialWallet - wallet used to resolve the auth claim status
 * @param {W3CCredential} credential - credential to check
 * @param {IssuerAuthClaimCheckOptions} [opts] - proof type the credential will be proven with
 * @returns `Promise<boolean>`
 */
export const isRevokedByIssuerAuthClaim = async (
  credentialWallet: ICredentialWallet,
  credential: W3CCredential,
  opts?: IssuerAuthClaimCheckOptions
): Promise<boolean> => {
  const revStatus = await getIssuerAuthClaimRevocationStatus(credentialWallet, credential, opts);
  return !!revStatus?.mtp.existence;
};
