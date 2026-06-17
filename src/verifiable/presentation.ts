import { VerifiableConstants } from './constants';
import { Options, Path } from '@iden3/js-jsonld-merklization';
import { W3CCredential } from './credential';
import { QueryMetadata } from '../proof';
import { VerifiablePresentation, JsonDocumentObject } from '../iden3comm';
import { Operators } from '../circuits';

export const stringByPath = (obj: { [key: string]: unknown }, path: string): string => {
  const parts = path.split('.');

  let value = obj;
  for (let index = 0; index < parts.length; index++) {
    const key = parts[index];
    if (!key) {
      throw new Error('path is empty');
    }
    value = value[key] as { [key: string]: unknown };
    if (value === undefined) {
      throw new Error('path not found');
    }
  }
  return value.toString();
};

export const buildFieldPath = async (
  ldSchema: string,
  contextType: string,
  field: string,
  opts?: Options
): Promise<Path> => {
  let path = new Path();

  if (field) {
    path = await Path.getContextPathKey(ldSchema, contextType, field, opts);
  }

  switch (ldSchema) {
    case VerifiableConstants.JSONLD_SCHEMA.IDEN3_PROOFS_DEFINITION_DOCUMENT:
      path.prepend([VerifiableConstants.CREDENTIAL_STATUS_PATH]);
      break;
    case VerifiableConstants.JSONLD_SCHEMA.W3C_VC_DOCUMENT_2018:
      break;
    default:
      path.prepend([VerifiableConstants.CREDENTIAL_SUBJECT_PATH]);
  }
  return path;
};

export const findValue = (fieldName: string, credential: W3CCredential): JsonDocumentObject => {
  const [first, ...rest] = fieldName.split('.');
  let v: unknown = credential[first as keyof W3CCredential];

  for (const part of rest) {
    v = (v as JsonDocumentObject)[part];
  }
  return v as JsonDocumentObject;
};

export const createVerifiablePresentation = (
  context: string,
  tp: string,
  credential: W3CCredential,
  queries: QueryMetadata[]
): VerifiablePresentation => {
  const vc = VerifiableConstants.CREDENTIAL_TYPE.W3C_VERIFIABLE_CREDENTIAL;
  const vcTypes = [vc];
  if (tp !== vc) {
    vcTypes.push(tp);
  }

  const baseContext = [VerifiableConstants.JSONLD_SCHEMA.W3C_CREDENTIAL_2018];
  const ldContext = context && baseContext[0] !== context ? [...baseContext, context] : baseContext;
  const hasCredentialStatusQuery = queries.some((q) => q.fieldName.startsWith('credentialStatus.'));
  const skeleton = {
    '@context': ldContext,
    type: VerifiableConstants.CREDENTIAL_TYPE.W3C_VERIFIABLE_PRESENTATION,
    verifiableCredential: {
      '@context': credential['@context'],
      type: vcTypes,
      credentialSubject: {
        type: tp
      },
      ...(hasCredentialStatusQuery && credential.credentialStatus
        ? {
            credentialStatus: {
              type: credential.credentialStatus.type
            }
          }
        : {})
    }
  };

  const sdQueries = queries.filter((q) => q.operator === Operators.SD);
  const w3cResult: JsonDocumentObject = {};
  for (const query of sdQueries) {
    const parts = query.fieldName.split('.');
    const leaf = parts.pop() as string;
    let node = w3cResult;
    for (const part of parts) {
      if (typeof node[part] !== 'object' || node[part] === null) {
        node[part] = {};
      }
      node = node[part] as JsonDocumentObject;
    }
    node[leaf] = findValue(query.fieldName, credential);
  }

  if (w3cResult.credentialStatus) {
    w3cResult.credentialStatus = {
      ...skeleton.verifiableCredential.credentialStatus,
      ...(w3cResult.credentialStatus as JsonDocumentObject)
    };
  }

  if (w3cResult.credentialSubject) {
    w3cResult.credentialSubject = {
      ...skeleton.verifiableCredential.credentialSubject,
      ...(w3cResult.credentialSubject as JsonDocumentObject)
    };
  }

  skeleton.verifiableCredential = {
    ...skeleton.verifiableCredential,
    ...w3cResult
  };

  return skeleton;
};
