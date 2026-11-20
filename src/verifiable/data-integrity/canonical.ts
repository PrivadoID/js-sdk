import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { sha256 } from '@iden3/js-crypto';
import jsonld, { Options } from 'jsonld';
import { JsonDocumentObject } from '../../iden3comm';
import { cacheLoader } from '../../schema-processor';
import { byteEncoder, bytesToBase64url } from '../../utils';

const canonize = async (input: JsonDocumentObject, documentLoader: DocumentLoader) => {
  const canonical = await jsonld.canonize(input, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    safe: true,
    documentLoader
  } as unknown as Options.Normalize);
  if (!canonical) {
    throw new Error('canonical form is empty');
  }
  return sha256(byteEncoder.encode(canonical));
};

export const computeIden3JwzPayload = async (
  document: JsonDocumentObject,
  proofOptions: JsonDocumentObject,
  documentLoader: DocumentLoader = cacheLoader()
): Promise<string> => {
  if ('proof' in document) {
    throw new Error('the document must not have a proof');
  }
  if (!('@context' in document)) {
    throw new Error('the document must have an @context');
  }
  const options = { ...proofOptions };
  delete options.proofValue;
  const configuration = await canonize(
    { ...options, '@context': document['@context'] },
    documentLoader
  );
  const hash = await canonize(document, documentLoader);
  return bytesToBase64url(new Uint8Array([...configuration, ...hash]));
};
