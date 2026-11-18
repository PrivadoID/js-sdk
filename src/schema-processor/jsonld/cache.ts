import { DocumentLoader, Options, getDocumentLoader } from '@iden3/js-jsonld-merklization';
import { RemoteDocument, Url } from 'jsonld/jsonld-spec';
import { VerifiableConstants } from '../../verifiable';

/**
 * cacheLoader returns a remote document with additional logic for caching the urls remote documents.
 * If the same url is called more then once, remote document will be not downloaded again but will returned from memory cache.
 * @param {Options } context - JSONLD loader options
 * @returns Promise<DocumentLoader>
 */

const doc = JSON.parse(VerifiableConstants.JSONLD_SCHEMA.W3C_VC_DOCUMENT_2018);
const docIden3Proofs = JSON.parse(
  VerifiableConstants.JSONLD_SCHEMA.IDEN3_PROOFS_DEFINITION_DOCUMENT
);
const docIden3DisplayMethod = JSON.parse(
  VerifiableConstants.JSONLD_SCHEMA.IDEN3_DISPLAY_METHOD_DEFINITION_DOCUMENT
);
const docIden3AuthBJJ = JSON.parse(VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD);
const docIden3AuthBJJJsonSchema = JSON.parse(
  VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSON
);

export const cacheLoader = (opts?: Options): DocumentLoader => {
  const cache = new Map<string, RemoteDocument>();
  cache.set(VerifiableConstants.JSONLD_SCHEMA.W3C_CREDENTIAL_2018, {
    document: doc,
    documentUrl: VerifiableConstants.JSONLD_SCHEMA.W3C_CREDENTIAL_2018
  });
  cache.set(VerifiableConstants.JSONLD_SCHEMA.IDEN3_CREDENTIAL, {
    document: docIden3Proofs,
    documentUrl: VerifiableConstants.JSONLD_SCHEMA.IDEN3_PROOFS_DEFINITION_DOCUMENT
  });
  cache.set(VerifiableConstants.JSONLD_SCHEMA.IDEN3_DISPLAY_METHOD, {
    document: docIden3DisplayMethod,
    documentUrl: VerifiableConstants.JSONLD_SCHEMA.IDEN3_DISPLAY_METHOD_DEFINITION_DOCUMENT
  });
  cache.set(VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD_URL, {
    document: docIden3AuthBJJ,
    documentUrl: VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD
  });
  cache.set(VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSON_URL, {
    document: docIden3AuthBJJJsonSchema,
    documentUrl: VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSON_URL
  });

  return async (url: Url): Promise<RemoteDocument> => {
    let remoteDoc = cache.get(url);
    if (remoteDoc) {
      return remoteDoc;
    }
    remoteDoc = await getDocumentLoader(opts)(url);
    cache.set(url, remoteDoc);
    return remoteDoc;
  };
};
