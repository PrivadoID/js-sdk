import { NodeAux, Hash, Proof, ZERO_HASH } from '@iden3/js-merkletree';
import {
  buildTreeState,
  CircuitId,
  ClaimNonRevStatus,
  GISTProof,
  isValidOperation,
  Operators,
  QueryOperators
} from '../circuits';
import {
  MerkleTreeProofWithTreeState,
  RevocationStatus,
  W3CCredential,
  buildFieldPath,
  getSerializationAttrFromContext,
  getFieldSlotIndex,
  VerifiableConstants,
  ProofQuery
} from '../verifiable';
import { Merklizer, Options, Path } from '@iden3/js-jsonld-merklization';
import { byteEncoder } from '../utils';
import { JsonDocumentObject, VerifiablePresentation, ZeroKnowledgeProofQuery } from '../iden3comm';
import { Claim } from '@iden3/js-iden3-core';
import { poseidon } from '@iden3/js-crypto';
import { StateProof } from '../storage';

export type PreparedCredential = {
  credential: W3CCredential;
  credentialCoreClaim: Claim;
  revStatus?: RevocationStatus;
};

export type PreparedAuthBJJCredential = {
  credential: W3CCredential;
  incProof: MerkleTreeProofWithTreeState;
  nonRevProof: MerkleTreeProofWithTreeState;
  coreClaim: Claim;
};
/**
 * converts verifiable RevocationStatus model to circuits structure
 *
 * @param {RevocationStatus} - credential.status of the verifiable credential
 * @returns {ClaimNonRevStatus}
 */
export const toClaimNonRevStatus = (s?: RevocationStatus): ClaimNonRevStatus => {
  if (!s) {
    const hash = poseidon.hash(new Array(3).fill(0n));
    return {
      proof: new Proof(),
      treeState: {
        state: Hash.fromBigInt(hash),
        claimsRoot: ZERO_HASH,
        revocationRoot: ZERO_HASH,
        rootOfRoots: ZERO_HASH
      }
    };
  }
  return {
    proof: s.mtp,
    treeState: buildTreeState(
      s.issuer.state,
      s.issuer.claimsTreeRoot,
      s.issuer.revocationTreeRoot,
      s.issuer.rootOfRoots
    )
  };
};

/**
 * converts state info from smart contract to gist proof
 *
 * @param {StateProof} smtProof  - state proof from smart contract
 * @returns {GISTProof}
 */
export const toGISTProof = (smtProof: StateProof): GISTProof => {
  let existence = false;
  let nodeAux: NodeAux | undefined;

  if (smtProof.existence) {
    existence = true;
  } else {
    if (smtProof.auxExistence) {
      nodeAux = {
        key: Hash.fromBigInt(smtProof.auxIndex),
        value: Hash.fromBigInt(smtProof.auxValue)
      };
    }
  }

  const allSiblings: Hash[] = smtProof.siblings.map((s) => Hash.fromBigInt(s));

  const proof = new Proof({ siblings: allSiblings, nodeAux: nodeAux, existence: existence });

  const root = Hash.fromBigInt(smtProof.root);

  return {
    root,
    proof
  };
};

export type PropertyQuery = {
  fieldName: string;
  operator: Operators;
  operatorValue?: unknown;
};

export type QueryMetadata = PropertyQuery & {
  slotIndex: number;
  values: bigint[];
  path: Path;
  claimPathKey: bigint;
  datatype: string;
  merklizedSchema: boolean;
};

const ALLOWED_CREDENTIAL_STATUS_FIELDS = new Set([
  'credentialStatus.revocationNonce',
  'credentialStatus.id'
]);

export const parseZKPQuery = (query: ZeroKnowledgeProofQuery): PropertyQuery[] => {
  const propertiesMetadata: PropertyQuery[] = [];
  if (query.credentialSubject) {
    const credSubjFlattened = flattenNestedObject(
      query.credentialSubject as Record<string, JsonDocumentObject | undefined>,
      'credentialSubject'
    );
    propertiesMetadata.push(...parseJsonDocumentObject(credSubjFlattened));
  }
  if (query.expirationDate) {
    const expirationDate = parseJsonDocumentObject({ expirationDate: query.expirationDate });
    propertiesMetadata.push(...expirationDate);
  }
  if (query.issuanceDate) {
    const issuanceDate = parseJsonDocumentObject({ issuanceDate: query.issuanceDate });
    propertiesMetadata.push(...issuanceDate);
  }
  if (query.credentialStatus && Object.keys(query.credentialStatus).length > 0) {
    const flattenedObject = flattenNestedObject(
      query.credentialStatus as Record<string, JsonDocumentObject | undefined>,
      'credentialStatus'
    );
    const allowed = Object.fromEntries(
      Object.entries(flattenedObject).filter(([key]) => ALLOWED_CREDENTIAL_STATUS_FIELDS.has(key))
    );
    if (!Object.keys(allowed).length) {
      throw new Error(
        `credentialStatus query contains no allowed fields — permitted: ${[
          ...ALLOWED_CREDENTIAL_STATUS_FIELDS
        ].join(', ')}`
      );
    }
    propertiesMetadata.push(...parseJsonDocumentObject(allowed));
  }
  if (propertiesMetadata.length === 0) {
    return [{ operator: QueryOperators.$noop, fieldName: '' }];
  }
  return propertiesMetadata;
};

const flattenNestedObject = (
  input: Record<string, JsonDocumentObject | undefined>,
  parentKey: string
): Record<string, JsonDocumentObject> => {
  const result: Record<string, JsonDocumentObject> = {};

  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined) {
      result[`${parentKey}.${key}`] = value;
    }
  }
  return result;
};

export const parseDocumentToPropertyQueries = (
  documentName: 'credentialStatus' | 'credentialSubject',
  document?: JsonDocumentObject
): PropertyQuery[] => {
  if (!document) {
    return [{ operator: QueryOperators.$noop, fieldName: '' }];
  }
  const flattenedObject = flattenNestedObject(
    document as Record<string, JsonDocumentObject | undefined>,
    documentName
  );
  return parseJsonDocumentObject(flattenedObject);
};

export const parseJsonDocumentObject = (document?: JsonDocumentObject): PropertyQuery[] => {
  // document is empty
  if (!document) {
    return [{ operator: QueryOperators.$noop, fieldName: '' }];
  }

  const queries: PropertyQuery[] = [];
  const entries = Object.entries(document);
  if (!entries.length) {
    throw new Error(`query must have at least 1 predicate`);
  }

  for (const [fieldName, fieldReq] of entries) {
    const fieldReqEntries = Object.entries(fieldReq as { [key: string]: unknown });

    const isSelectiveDisclosure = fieldReqEntries.length === 0;

    if (isSelectiveDisclosure) {
      queries.push({ operator: QueryOperators.$sd, fieldName });
      continue;
    }

    for (const [operatorName, operatorValue] of fieldReqEntries) {
      if (!(operatorName in QueryOperators)) {
        throw new Error(`operator is not supported by lib`);
      }
      const operator = QueryOperators[operatorName as keyof typeof QueryOperators];
      queries.push({ operator, fieldName, operatorValue });
    }
  }
  return queries;
};

/**
 * @deprecated use parseDocumentToPropertyQueries instead
 * @param credentialSubject credentialSubject object
 * @returns PropertyQuery[]
 */
export const parseCredentialSubject = (credentialSubject?: JsonDocumentObject): PropertyQuery[] => {
  return parseJsonDocumentObject(credentialSubject);
};

export type ParseOptions = Options & {
  legacyNoopOperator?: boolean;
};
export const parseQueryMetadata = async (
  propertyQuery: PropertyQuery,
  ldContextJSON: string,
  credentialType: string,
  options: ParseOptions
): Promise<QueryMetadata> => {
  const originalFieldName = propertyQuery.fieldName;
  const [fieldParentObj] = originalFieldName.split('.');
  let strippedFieldName = originalFieldName;
  switch (fieldParentObj) {
    case 'credentialStatus':
      strippedFieldName = originalFieldName.replace('credentialStatus.', '');
      ldContextJSON = VerifiableConstants.JSONLD_SCHEMA.IDEN3_PROOFS_DEFINITION_DOCUMENT;
      break;
    case 'credentialSubject':
      strippedFieldName = originalFieldName.replace('credentialSubject.', '');
      break;
    case '':
      break;
    case 'expirationDate':
    case 'issuanceDate':
      ldContextJSON = VerifiableConstants.JSONLD_SCHEMA.W3C_VC_DOCUMENT_2018;
      credentialType = VerifiableConstants.CREDENTIAL_TYPE.W3C_VERIFIABLE_CREDENTIAL;
      break;
  }
  const query: QueryMetadata = {
    ...propertyQuery,
    fieldName: strippedFieldName,
    slotIndex: 0,
    merklizedSchema: false,
    datatype: '',
    claimPathKey: BigInt(0),
    values: [],
    path: new Path()
  };

  if (!strippedFieldName && propertyQuery.operator !== Operators.NOOP) {
    throw new Error('query must have a field name if operator is not $noop');
  }

  if (strippedFieldName) {
    query.datatype = await Path.newTypeFromContext(
      ldContextJSON,
      `${credentialType}.${strippedFieldName}`,
      options
    );
  }

  const serAttr = await getSerializationAttrFromContext(
    JSON.parse(ldContextJSON),
    options,
    credentialType
  );
  if (!serAttr) {
    query.merklizedSchema = true;
  }
  // for merklized credentials slotIndex in query must be equal to zero
  // and not a position of merklization root.
  // it has no influence on check in the off-chain circuits, but it aligns with onchain verification standard

  if (!query.merklizedSchema) {
    query.slotIndex = await getFieldSlotIndex(
      strippedFieldName,
      credentialType,
      byteEncoder.encode(ldContextJSON)
    );
  } else if (!options.legacyNoopOperator && query.operator === Operators.NOOP) {
    query.claimPathKey = BigInt(0);
    query.path = new Path(); // path is not needed for noop operator, but we need to initialize it to avoid errors in the circuits
  } else {
    try {
      const path = await buildFieldPath(ldContextJSON, credentialType, strippedFieldName, options);
      if (
        originalFieldName === 'credentialStatus.id' &&
        path.parts[path.parts.length - 1] === '@id'
      ) {
        path.parts.pop();
      }
      query.claimPathKey = await path.mtEntry();
      query.path = path;
    } catch (e) {
      throw new Error(`field does not exist in the schema ${(e as Error).message}`);
    }
  }

  if (propertyQuery.operatorValue !== undefined) {
    if (!isValidOperation(query.datatype, propertyQuery.operator)) {
      throw new Error(
        `operator ${propertyQuery.operator} is not supported for datatype ${query.datatype}`
      );
    }

    if (
      (propertyQuery.operator === Operators.NOOP || propertyQuery.operator === Operators.SD) &&
      propertyQuery.operatorValue
    ) {
      throw new Error(`operator value should be undefined for ${propertyQuery.operator} operator`);
    }

    let values: bigint[];
    switch (propertyQuery.operator) {
      case Operators.NOOP:
      case Operators.SD:
        values = [];
        break;
      case Operators.EXISTS:
        values = transformExistsValue(propertyQuery.operatorValue);
        break;
      default:
        values = await transformQueryValueToBigInts(propertyQuery.operatorValue, query.datatype);
    }
    query.values = values;
  }
  query.fieldName = originalFieldName;
  return query;
};

export const parseProofQueryMetadata = async (
  credentialType: string,
  ldContextJSON: string,
  query: ProofQuery,
  options: ParseOptions,
  vp?: VerifiablePresentation
): Promise<QueryMetadata[]> => {
  const propertyQuery: PropertyQuery[] = [];

  if (query.credentialSubject !== undefined) {
    propertyQuery.push(
      ...parseDocumentToPropertyQueries('credentialSubject', query.credentialSubject)
    );
  }
  if (query.expirationDate) {
    propertyQuery.push(...parseJsonDocumentObject({ expirationDate: query.expirationDate }));
  }
  if (query.issuanceDate) {
    propertyQuery.push(...parseJsonDocumentObject({ issuanceDate: query.issuanceDate }));
  }
  if (query.credentialStatus !== undefined && Object.keys(query.credentialStatus).length > 0) {
    const parsedCredentialStatusQueries = parseDocumentToPropertyQueries(
      'credentialStatus',
      query.credentialStatus
    ).filter((q) => ALLOWED_CREDENTIAL_STATUS_FIELDS.has(q.fieldName));
    if (!parsedCredentialStatusQueries.length) {
      throw new Error(
        `credentialStatus query contains no allowed fields — permitted: ${[
          ...ALLOWED_CREDENTIAL_STATUS_FIELDS
        ].join(', ')}`
      );
    }
    propertyQuery.push(...parsedCredentialStatusQueries);
  }

  if (propertyQuery.length === 0) {
    propertyQuery.push({ operator: QueryOperators.$noop, fieldName: '' });
  }

  return Promise.all(
    propertyQuery.map((p) => {
      let credType = credentialType;
      if (p.fieldName.startsWith('credentialStatus.')) {
        const statusType = vp?.verifiableCredential?.credentialStatus?.type;
        if (!statusType) {
          // the merklization path of credentialStatus fields (e.g. revocationNonce) is
          // status-type-specific, so the verifier needs the type from a verifiablePresentation
          throw new Error(
            'credentialStatus.type is required to verify a credentialStatus query: ' +
              'include it via a verifiablePresentation (selective disclosure)'
          );
        }
        credType = statusType;
      }
      return parseQueryMetadata(p, ldContextJSON, credType, options);
    })
  );
};

export const parseQueriesMetadata = async (
  credentialType: string,
  ldContextJSON: string,
  credentialSubject: JsonDocumentObject,
  options: ParseOptions
): Promise<QueryMetadata[]> => {
  const queriesMetadata = parseDocumentToPropertyQueries('credentialSubject', credentialSubject);
  return Promise.all(
    queriesMetadata.map((m) => parseQueryMetadata(m, ldContextJSON, credentialType, options))
  );
};

export const transformQueryValueToBigInts = async (
  value: unknown,
  ldType: string
): Promise<bigint[]> => {
  const values: bigint[] = [];

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      values[index] = await Merklizer.hashValue(ldType, value[index]);
    }
  } else {
    values[0] = await Merklizer.hashValue(ldType, value);
  }
  return values;
};

const transformExistsValue = (value: unknown): bigint[] => {
  if (typeof value == 'boolean') {
    return [BigInt(value)];
  }
  throw new Error('exists operator value must be true or false');
};

export const isAuthCircuit = (circuitId: CircuitId): boolean => {
  return [CircuitId.AuthV2, CircuitId.AuthV3, CircuitId.AuthV3_8_32].includes(circuitId);
};
