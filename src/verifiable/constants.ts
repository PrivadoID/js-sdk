/** Verifiable constants */
export const VerifiableConstants = Object.freeze({
  ERRORS: {
    FiELD_IS_EMPTY: 'fieldPath is empty',
    CONTEXT_TYPE_IS_EMPTY: 'ctxType is empty',
    // ErrStateNotFound issuer state is genesis state.
    IDENTITY_DOES_NOT_EXIST: 'Identity does not exist',
    IDENTITY_DOES_NOT_EXIST_CUSTOM_ERROR: 'IdentityDoesNotExist',
    NO_AUTH_CRED_FOUND: 'no auth credentials found',
    STATE_DOES_NOT_EXIST: 'State does not exist',
    STATE_DOES_NOT_EXIST_CUSTOM_ERROR: 'StateDoesNotExist',
    ROOT_DOES_NOT_EXIST: 'Root does not exist',
    ROOT_DOES_NOT_EXIST_CUSTOM_ERROR: 'RootDoesNotExist',

    // identity wallet

    ID_WALLET_NO_CREDENTIAL_SATISFIED_QUERY: 'no credential satisfied query',
    ID_WALLET_SIGNER_IS_REQUIRED:
      'Ethereum signer is required to create Ethereum identities in order to transit state',
    ID_WALLET_PROVER_IS_REQUIRED:
      'prover is required to generate proofs for non ethereum identities',
    ID_WALLET_CORE_CLAIM_REQUIRED_IN_SIG_PROOF:
      'credential must have coreClaim representation in the signature proof',
    ID_WALLET_CORE_CLAIM_REQUIRED_IN_ANY_PROOF:
      'credential must have coreClaim representation in proofs',
    ID_WALLET_CORE_CLAIM_MISMATCH:
      'core claim representations is set in both proofs but they are not equal',
    ID_WALLET_CORE_CLAIM_IS_NOT_SET: 'core claim is not set in credential proofs',
    ID_WALLET_PROFILE_OR_IDENTITY_NOT_FOUND: 'profile or identity not found',
    ID_WALLET_PROFILE_ALREADY_EXISTS: 'profile with given nonce or verifier already exists',
    ID_WALLET_PROFILE_ALREADY_EXISTS_VERIFIER_TAGS:
      'profile with given verifier and tags already exists',
    ID_WALLET_ISSUER_AUTH_BJJ_CRED_MUST_HAVE_ANY_PROOF: 'issuer auth credential must have proof',
    ID_WALLET_ISSUER_AUTH_BJJ_CRED_MUST_HAVE_MTP_PROOF:
      'mtp is required for auth bjj key to issue new credentials',

    // proof service

    PROOF_SERVICE_NO_CREDENTIAL_FOR_IDENTITY_OR_PROFILE:
      'no credentials belong to did or its profiles',
    PROOF_SERVICE_NO_CREDENTIAL_FOR_QUERY: 'credential not found for query',
    PROOF_SERVICE_PROFILE_GENESIS_DID_MISMATCH:
      'subject and auth profiles are not derived from the same did',
    PROOF_SERVICE_NO_QUERIES_IN_ZKP_REQUEST: 'no queries in zkp request',
    PROOF_SERVICE_CREDENTIAL_IS_EXPIRED: 'credential is expired',

    // credential wallet

    CREDENTIAL_WALLET_ALL_CREDENTIALS_ARE_REVOKED: 'all claims are revoked'
  },
  CREDENTIAL_TYPE: {
    // VerifiableCredential is a W3C verifiable credential type
    W3C_VERIFIABLE_CREDENTIAL: 'VerifiableCredential',
    W3C_VERIFIABLE_PRESENTATION: 'VerifiablePresentation'
  },
  CREDENTIAL_SUBJECT_PATH: 'https://www.w3.org/2018/credentials#credentialSubject',
  CREDENTIAL_STATUS_PATH: 'https://www.w3.org/2018/credentials#credentialStatus',
  JSONLD_SCHEMA: {
    // JSONLDSchemaIden3Credential is a schema for context with Iden3Credential type
    IDEN3_CREDENTIAL: 'https://schema.iden3.io/core/jsonld/iden3proofs.jsonld',
    // JSONLDSchemaIden3DisplayMethod is a schema for context with Iden3BasicDisplayMethodV1 type
    IDEN3_DISPLAY_METHOD: 'https://schema.iden3.io/core/jsonld/displayMethod.jsonld',
    // JSONLDSchemaW3CCredential2018 is a schema for context with VerifiableCredential type
    W3C_CREDENTIAL_2018: 'https://www.w3.org/2018/credentials/v1',
    W3C_VC_DOCUMENT_2018: `{"@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","VerifiableCredential":{"@id":"https://www.w3.org/2018/credentials#VerifiableCredential","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","cred":"https://www.w3.org/2018/credentials#","sec":"https://w3id.org/security#","xsd":"http://www.w3.org/2001/XMLSchema#","credentialSchema":{"@id":"cred:credentialSchema","@type":"@id","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","cred":"https://www.w3.org/2018/credentials#","JsonSchemaValidator2018":"cred:JsonSchemaValidator2018"}},"credentialStatus":{"@id":"cred:credentialStatus","@type":"@id"},"credentialSubject":{"@id":"cred:credentialSubject","@type":"@id"},"evidence":{"@id":"cred:evidence","@type":"@id"},"expirationDate":{"@id":"cred:expirationDate","@type":"xsd:dateTime"},"holder":{"@id":"cred:holder","@type":"@id"},"issued":{"@id":"cred:issued","@type":"xsd:dateTime"},"issuer":{"@id":"cred:issuer","@type":"@id"},"issuanceDate":{"@id":"cred:issuanceDate","@type":"xsd:dateTime"},"proof":{"@id":"sec:proof","@type":"@id","@container":"@graph"},"refreshService":{"@id":"cred:refreshService","@type":"@id","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","cred":"https://www.w3.org/2018/credentials#","ManualRefreshService2018":"cred:ManualRefreshService2018"}},"termsOfUse":{"@id":"cred:termsOfUse","@type":"@id"},"validFrom":{"@id":"cred:validFrom","@type":"xsd:dateTime"},"validUntil":{"@id":"cred:validUntil","@type":"xsd:dateTime"}}},"VerifiablePresentation":{"@id":"https://www.w3.org/2018/credentials#VerifiablePresentation","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","cred":"https://www.w3.org/2018/credentials#","sec":"https://w3id.org/security#","holder":{"@id":"cred:holder","@type":"@id"},"proof":{"@id":"sec:proof","@type":"@id","@container":"@graph"},"verifiableCredential":{"@id":"cred:verifiableCredential","@type":"@id","@container":"@graph"}}},"EcdsaSecp256k1Signature2019":{"@id":"https://w3id.org/security#EcdsaSecp256k1Signature2019","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","sec":"https://w3id.org/security#","xsd":"http://www.w3.org/2001/XMLSchema#","challenge":"sec:challenge","created":{"@id":"http://purl.org/dc/terms/created","@type":"xsd:dateTime"},"domain":"sec:domain","expires":{"@id":"sec:expiration","@type":"xsd:dateTime"},"jws":"sec:jws","nonce":"sec:nonce","proofPurpose":{"@id":"sec:proofPurpose","@type":"@vocab","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","sec":"https://w3id.org/security#","assertionMethod":{"@id":"sec:assertionMethod","@type":"@id","@container":"@set"},"authentication":{"@id":"sec:authenticationMethod","@type":"@id","@container":"@set"}}},"proofValue":"sec:proofValue","verificationMethod":{"@id":"sec:verificationMethod","@type":"@id"}}},"EcdsaSecp256r1Signature2019":{"@id":"https://w3id.org/security#EcdsaSecp256r1Signature2019","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","sec":"https://w3id.org/security#","xsd":"http://www.w3.org/2001/XMLSchema#","challenge":"sec:challenge","created":{"@id":"http://purl.org/dc/terms/created","@type":"xsd:dateTime"},"domain":"sec:domain","expires":{"@id":"sec:expiration","@type":"xsd:dateTime"},"jws":"sec:jws","nonce":"sec:nonce","proofPurpose":{"@id":"sec:proofPurpose","@type":"@vocab","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","sec":"https://w3id.org/security#","assertionMethod":{"@id":"sec:assertionMethod","@type":"@id","@container":"@set"},"authentication":{"@id":"sec:authenticationMethod","@type":"@id","@container":"@set"}}},"proofValue":"sec:proofValue","verificationMethod":{"@id":"sec:verificationMethod","@type":"@id"}}},"Ed25519Signature2018":{"@id":"https://w3id.org/security#Ed25519Signature2018","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","sec":"https://w3id.org/security#","xsd":"http://www.w3.org/2001/XMLSchema#","challenge":"sec:challenge","created":{"@id":"http://purl.org/dc/terms/created","@type":"xsd:dateTime"},"domain":"sec:domain","expires":{"@id":"sec:expiration","@type":"xsd:dateTime"},"jws":"sec:jws","nonce":"sec:nonce","proofPurpose":{"@id":"sec:proofPurpose","@type":"@vocab","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","sec":"https://w3id.org/security#","assertionMethod":{"@id":"sec:assertionMethod","@type":"@id","@container":"@set"},"authentication":{"@id":"sec:authenticationMethod","@type":"@id","@container":"@set"}}},"proofValue":"sec:proofValue","verificationMethod":{"@id":"sec:verificationMethod","@type":"@id"}}},"RsaSignature2018":{"@id":"https://w3id.org/security#RsaSignature2018","@context":{"@version":1.1,"@protected":true,"challenge":"sec:challenge","created":{"@id":"http://purl.org/dc/terms/created","@type":"xsd:dateTime"},"domain":"sec:domain","expires":{"@id":"sec:expiration","@type":"xsd:dateTime"},"jws":"sec:jws","nonce":"sec:nonce","proofPurpose":{"@id":"sec:proofPurpose","@type":"@vocab","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","sec":"https://w3id.org/security#","assertionMethod":{"@id":"sec:assertionMethod","@type":"@id","@container":"@set"},"authentication":{"@id":"sec:authenticationMethod","@type":"@id","@container":"@set"}}},"proofValue":"sec:proofValue","verificationMethod":{"@id":"sec:verificationMethod","@type":"@id"}}},"proof":{"@id":"https://w3id.org/security#proof","@type":"@id","@container":"@graph"}}}`,
    IDEN3_PROOFS_DEFINITION_DOCUMENT: `{"@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","Iden3SparseMerkleTreeProof":{"@id":"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld#Iden3SparseMerkleTreeProof","@context":{"@version":1.1,"@protected":true,"@propagate":true,"id":"@id","type":"@type","sec":"https://w3id.org/security#","@vocab":"https://schema.iden3.io/core/vocab/Iden3SparseMerkleTreeProof.md#","xsd":"http://www.w3.org/2001/XMLSchema#","mtp":{"@id":"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld#SparseMerkleTreeProof","@type":"SparseMerkleTreeProof"},"coreClaim":{"@id":"coreClaim","@type":"xsd:string"},"issuerData":{"@id":"issuerData","@context":{"@version":1.1,"state":{"@id":"state","@context":{"txId":{"@id":"txId","@type":"xsd:string"},"blockTimestamp":{"@id":"blockTimestamp","@type":"xsd:integer"},"blockNumber":{"@id":"blockNumber","@type":"xsd:integer"},"rootOfRoots":{"@id":"rootOfRoots","@type":"xsd:string"},"claimsTreeRoot":{"@id":"claimsTreeRoot","@type":"xsd:string"},"revocationTreeRoot":{"@id":"revocationTreeRoot","@type":"xsd:string"},"authCoreClaim":{"@id":"authCoreClaim","@type":"xsd:string"},"value":{"@id":"value","@type":"xsd:string"}}}}}}},"SparseMerkleTreeProof":{"@id":"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld#SparseMerkleTreeProof","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","sec":"https://w3id.org/security#","smt-proof-vocab":"https://schema.iden3.io/core/vocab/SparseMerkleTreeProof.md#","xsd":"http://www.w3.org/2001/XMLSchema#","existence":{"@id":"smt-proof-vocab:existence","@type":"xsd:boolean"},"revocationNonce":{"@id":"smt-proof-vocab:revocationNonce","@type":"xsd:number"},"siblings":{"@id":"smt-proof-vocab:siblings","@container":"@list"},"nodeAux":"@nest","hIndex":{"@id":"smt-proof-vocab:hIndex","@nest":"nodeAux","@type":"xsd:string"},"hValue":{"@id":"smt-proof-vocab:hValue","@nest":"nodeAux","@type":"xsd:string"}}},"BJJSignature2021":{"@id":"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld#BJJSignature2021","@context":{"@version":1.1,"@protected":true,"id":"@id","@vocab":"https://schema.iden3.io/core/vocab/BJJSignature2021.md#","@propagate":true,"type":"@type","xsd":"http://www.w3.org/2001/XMLSchema#","coreClaim":{"@id":"coreClaim","@type":"xsd:string"},"issuerData":{"@id":"issuerData","@context":{"@version":1.1,"authCoreClaim":{"@id":"authCoreClaim","@type":"xsd:string"},"mtp":{"@id":"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld#SparseMerkleTreeProof","@type":"SparseMerkleTreeProof"},"revocationStatus":{"@id":"revocationStatus","@type":"@id"},"state":{"@id":"state","@context":{"@version":1.1,"rootOfRoots":{"@id":"rootOfRoots","@type":"xsd:string"},"claimsTreeRoot":{"@id":"claimsTreeRoot","@type":"xsd:string"},"revocationTreeRoot":{"@id":"revocationTreeRoot","@type":"xsd:string"},"value":{"@id":"value","@type":"xsd:string"}}}}},"signature":{"@id":"signature","@type":"https://w3id.org/security#multibase"},"domain":"https://w3id.org/security#domain","creator":{"@id":"creator","@type":"http://www.w3.org/2001/XMLSchema#string"},"challenge":"https://w3id.org/security#challenge","created":{"@id":"created","@type":"http://www.w3.org/2001/XMLSchema#dateTime"},"expires":{"@id":"https://w3id.org/security#expiration","@type":"http://www.w3.org/2001/XMLSchema#dateTime"},"nonce":"https://w3id.org/security#nonce","proofPurpose":{"@id":"https://w3id.org/security#proofPurpose","@type":"@vocab","@context":{"@protected":true,"id":"@id","type":"@type","assertionMethod":{"@id":"https://w3id.org/security#assertionMethod","@type":"@id","@container":"@set"},"authentication":{"@id":"https://w3id.org/security#authenticationMethod","@type":"@id","@container":"@set"},"capabilityInvocation":{"@id":"https://w3id.org/security#capabilityInvocationMethod","@type":"@id","@container":"@set"},"capabilityDelegation":{"@id":"https://w3id.org/security#capabilityDelegationMethod","@type":"@id","@container":"@set"},"keyAgreement":{"@id":"https://w3id.org/security#keyAgreementMethod","@type":"@id","@container":"@set"}}},"proofValue":{"@id":"https://w3id.org/security#proofValue","@type":"https://w3id.org/security#multibase"},"verificationMethod":{"@id":"https://w3id.org/security#verificationMethod","@type":"@id"}}},"Iden3ReverseSparseMerkleTreeProof":{"@id":"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld#Iden3ReverseSparseMerkleTreeProof","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","iden3-reverse-sparse-merkle-tree-proof-vocab":"https://schema.iden3.io/core/vocab/Iden3ReverseSparseMerkleTreeProof.md#","xsd":"http://www.w3.org/2001/XMLSchema#","revocationNonce":{"@id":"iden3-reverse-sparse-merkle-tree-proof-vocab:revocationNonce","@type":"xsd:integer"},"statusIssuer":{"@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type"},"@id":"iden3-reverse-sparse-merkle-tree-proof-vocab:statusIssuer"}}},"Iden3commRevocationStatusV1.0":{"@id":"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld#Iden3commRevocationStatusV1.0","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","iden3-comm-revocation-statusV1.0-vocab":"https://schema.iden3.io/core/vocab/Iden3commRevocationStatusV1.0.md#","xsd":"http://www.w3.org/2001/XMLSchema#","revocationNonce":{"@id":"iden3-comm-revocation-statusV1.0-vocab:revocationNonce","@type":"xsd:integer"},"statusIssuer":{"@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type"},"@id":"iden3-comm-revocation-statusV1.0-vocab:statusIssuer"}}},"Iden3OnchainSparseMerkleTreeProof2023":{"@id":"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld#Iden3OnchainSparseMerkleTreeProof2023","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","iden3-onchain-sparse-merkle-tree-proof-2023-vocab":"https://schema.iden3.io/core/vocab/Iden3OnchainSparseMerkleTreeProof2023.md#","xsd":"http://www.w3.org/2001/XMLSchema#","revocationNonce":{"@id":"iden3-onchain-sparse-merkle-tree-proof-2023-vocab:revocationNonce","@type":"xsd:integer"},"statusIssuer":{"@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type"},"@id":"iden3-onchain-sparse-merkle-tree-proof-2023-vocab:statusIssuer"}}},"JsonSchema2023":"https://www.w3.org/ns/credentials#JsonSchema2023","Iden3RefreshService2023":"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld#Iden3RefreshService2023"}}`,
    IDEN3_DISPLAY_METHOD_DEFINITION_DOCUMENT: `{"@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","displayMethod":{"@id":"https://schema.iden3.io/core/vocab/displayMethod.md#displayMethod","@type":"@id","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","Iden3BasicDisplayMethodV1":"https://schema.iden3.io/core/vocab/displayMethod.md#Iden3BasicDisplayMethodV1"}}}}`
  },
  // JsonSchema2023 JSON schema for verification of Iden3Credential
  JSON_SCHEMA_VALIDATOR: 'JsonSchema2023',
  SERVICE_TYPE: {
    // Iden3CommServiceType is service type for iden3comm protocol
    IDEN3_COMM: 'iden3-communication',
    // PushNotificationServiceType is service type for delivering push notifications to identity
    PUSH_NOTIFICATION: 'push-notification'
  },
  AUTH: {
    AUTH_BJJ_CREDENTIAL_HASH: '013fd3f623559d850fb5b02ff012d0e2',
    AUTH_BJJ_CREDENTIAL_SCHEMA_JSON_URL: 'https://schema.iden3.io/core/json/auth.json',
    AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD_URL: 'https://schema.iden3.io/core/jsonld/auth.jsonld',
    AUTH_BJJ_CREDENTIAL_TYPE: 'AuthBJJCredential',
    AUTH_BJJ_CREDENTIAL_SCHEMA_JSON: `{"$schema":"http://json-schema.org/draft-07/schema#","$metadata":{"uris":{"jsonLdContext":"https://schema.iden3.io/core/jsonld/auth.jsonld","jsonSchema":"https://schema.iden3.io/core/json/auth.json"},"serialization":{"indexDataSlotA":"x","indexDataSlotB":"y"}},"type":"object","required":["@context","id","type","issuanceDate","credentialSubject","credentialSchema","credentialStatus","issuer"],"properties":{"@context":{"type":["string","array","object"]},"id":{"type":"string"},"type":{"type":["string","array"],"items":{"type":"string"}},"issuer":{"type":["string","object"],"format":"uri","required":["id"],"properties":{"id":{"type":"string","format":"uri"}}},"issuanceDate":{"type":"string","format":"date-time"},"expirationDate":{"type":"string","format":"date-time"},"credentialSchema":{"type":"object","required":["id","type"],"properties":{"id":{"type":"string","format":"uri"},"type":{"type":"string"}}},"credentialSubject":{"type":"object","required":["x","y"],"properties":{"id":{"title":"Credential Subject ID","type":"string","format":"uri"},"x":{"type":"string"},"y":{"type":"string"}}}}}`,
    AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD: `{"@context":[{"@version":1.1,"@protected":true,"id":"@id","type":"@type","AuthBJJCredential":{"@id":"https://schema.iden3.io/core/jsonld/auth.jsonld#AuthBJJCredential","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","iden3_serialization":"iden3:v1:slotIndexA=x&slotIndexB=y","xsd":"http://www.w3.org/2001/XMLSchema#","auth-vocab":"https://schema.iden3.io/core/vocab/auth.md#","x":{"@id":"auth-vocab:x","@type":"xsd:positiveInteger"},"y":{"@id":"auth-vocab:y","@type":"xsd:positiveInteger"}}},"Iden3StateInfo2023":{"@id":"https://schema.iden3.io/core/jsonld/auth.jsonld#Iden3StateInfo2023","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","xsd":"http://www.w3.org/2001/XMLSchema#","@vocab":"https://schema.iden3.io/core/vocab/state-info.md#","@propagate":true,"stateContractAddress":{"@id":"stateContractAddress","@type":"xsd:string"},"published":{"@id":"published","@type":"xsd:boolean"},"info":{"@id":"info","@type":"@id","@context":{"@protected":true,"id":{"@id":"id","@type":"xsd:string"},"state":{"@id":"state","@type":"xsd:string"},"replacedByState":{"@id":"replacedByState","@type":"xsd:string"},"createdAtTimestamp":{"@id":"createdAtTimestamp","@type":"xsd:string"},"replacedAtTimestamp":{"@id":"replacedAtTimestamp","@type":"xsd:string"},"createdAtBlock":{"@id":"createdAtBlock","@type":"xsd:string"},"replacedAtBlock":{"@id":"replacedAtBlock","@type":"xsd:string"}}},"global":{"@id":"global","@type":"@id","@context":{"@protected":true,"sec":"https://w3id.org/security#","root":{"@id":"root","@type":"xsd:string"},"replacedByRoot":{"@id":"replacedByRoot","@type":"xsd:string"},"createdAtTimestamp":{"@id":"createdAtTimestamp","@type":"xsd:string"},"replacedAtTimestamp":{"@id":"replacedAtTimestamp","@type":"xsd:string"},"createdAtBlock":{"@id":"createdAtBlock","@type":"xsd:string"},"replacedAtBlock":{"@id":"replacedAtBlock","@type":"xsd:string"},"proof":{"@id":"sec:proof","@type":"@id","@container":"@graph"}}}}}}]}`
  }
});

/**
 * Proof type for Verifiable Credential supported by sdk
 *
 * @enum {number}
 */
export enum ProofType {
  // BJJSignatureProofType
  BJJSignature = 'BJJSignature2021',
  // Iden3SparseMerkleTreeProofType
  Iden3SparseMerkleTreeProof = 'Iden3SparseMerkleTreeProof'
}

/**
 * CredentialStatusType type for revocation type
 *
 * @enum {number}
 */
export enum CredentialStatusType {
  // SparseMerkleTreeProof is CredentialStatusType for standard MTP result handlers
  SparseMerkleTreeProof = 'SparseMerkleTreeProof',
  // Iden3ReverseSparseMerkleTreeProof is CredentialStatusType  for reverse iden3 algorithm
  Iden3ReverseSparseMerkleTreeProof = 'Iden3ReverseSparseMerkleTreeProof',
  // Iden3commRevocationStatusV1 is CredentialStatusType for iden3comm revocation status
  Iden3commRevocationStatusV1 = 'Iden3commRevocationStatusV1.0',
  // Iden3OnchainSparseMerkleTreeProof2023 is a proof type for MTP proofs with iden3 metadata from blockchain
  Iden3OnchainSparseMerkleTreeProof2023 = 'Iden3OnchainSparseMerkleTreeProof2023'
}

/**
 * W3C Proof purpose
 *
 * @enum {number}
 */
export enum ProofPurpose {
  Authentication = 'Authentication'
}

/**
 * Merklized Core.Claim root position for vc creation
 *
 * @enum {number}
 */
export enum MerklizedRootPosition {
  // PositionIndex merklized root is stored in index.
  Index = 'index',
  // Value merklized root is stored in value.
  Value = 'value',
  // None merklized root is not stored in the claim. By Default.
  None = ''
}

/**
 * Subject Core.Claim position for vc creation
 *
 * @enum {number}
 */
export enum SubjectPosition {
  // CredentialSubjectPositionNone is for self issued Iden3Credential
  None = '',
  // Index save subject in index part of claim. By default.
  Index = 'index',
  // Value save subject in value part of claim.
  Value = 'value'
}

/**
 * RefreshServiceType type for refreshService
 *
 * @enum {string}
 */
export enum RefreshServiceType {
  Iden3RefreshService2023 = 'Iden3RefreshService2023'
}

/**
 * PaymentRequestDataType type for payment requests
 * @beta
 * @enum {string}
 */
export enum PaymentRequestDataType {
  Iden3PaymentRequestCryptoV1 = 'Iden3PaymentRequestCryptoV1',
  Iden3PaymentRailsRequestV1 = 'Iden3PaymentRailsRequestV1',
  Iden3PaymentRailsERC20RequestV1 = 'Iden3PaymentRailsERC20RequestV1',
  Iden3PaymentRailsSolanaRequestV1 = 'Iden3PaymentRailsSolanaRequestV1',
  Iden3PaymentRailsSolanaSPLRequestV1 = 'Iden3PaymentRailsSolanaSPLRequestV1'
}

/**
 * PaymentType type for payment responses
 * @beta
 * @enum {string}
 */
export enum PaymentType {
  Iden3PaymentCryptoV1 = 'Iden3PaymentCryptoV1',
  Iden3PaymentRailsV1 = 'Iden3PaymentRailsV1',
  Iden3PaymentRailsERC20V1 = 'Iden3PaymentRailsERC20V1',
  Iden3PaymentRailsSolanaV1 = 'Iden3PaymentRailsSolanaV1',
  Iden3PaymentRailsSolanaSPLV1 = 'Iden3PaymentRailsSolanaSPLV1'
}

/**
 * SupportedPaymentProofType type for payment proofs
 * @beta
 * @enum {string}
 */
export enum SupportedPaymentProofType {
  EthereumEip712Signature2021 = 'EthereumEip712Signature2021',
  SolanaEd25519Signature2025 = 'SolanaEd25519Signature2025'
}

/**
 * Media types for Payment supported currencies
 * @beta
 * @deprecated
 * @enum {string}
 */
export enum SupportedCurrencies {
  ETH = 'ETH',
  ETH_WEI = 'ETHWEI',
  ETH_GWEI = 'ETHGWEI',
  MATIC = 'MATIC',
  POL = 'POL'
}

/**
 * Supported features for payment-request
 * @beta
 * @enum {string}
 */
export enum PaymentFeatures {
  EIP_2612 = 'EIP-2612'
}

/**
 * DisplayMethodType type for display method
 *
 * @enum {string}
 */
export enum DisplayMethodType {
  Iden3BasicDisplayMethodV1 = 'Iden3BasicDisplayMethodV1'
}

/**
 * Default cache max size for in-memory cache
 */
export const DEFAULT_CACHE_MAX_SIZE = 10_000;

/**
 * Solana chain reference
 */
export const SOLANA_CHAIN_REF = Object.freeze({
  DEVNET: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
  TESTNET: '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z',
  MAINNET: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
});
