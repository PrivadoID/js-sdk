import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { sha256 } from '@iden3/js-crypto';
import { base64url } from 'rfc4648';
import jsonld from 'jsonld';
import { Options } from 'jsonld';
import { JsonDocumentObject } from '../../iden3comm';
import { isKeyword, isRelativeIri, isURL } from './iri';

const MAX_IRI_LENGTH = 2083;
const MAX_DEEP_ITERATIONS = 1;
const MAX_BLANK_NODES = 256;
const MAX_VALUES = 4096;
const CONTEXT_KEY = '@context';

export class JsonLdCanonicalizationError extends Error {
  constructor(message: string) {
    super(`canonicalization failed: ${message}`);
    this.name = 'JsonLdCanonicalizationError';
  }
}

const plainCopy = (input: JsonDocumentObject): JsonDocumentObject =>
  JSON.parse(JSON.stringify(input)) as JsonDocumentObject;

const requireNoNull = (value: unknown, member: string | undefined): void => {
  if (value === null) {
    throw new JsonLdCanonicalizationError(
      member === undefined
        ? 'a null value is not signed'
        : `member ${JSON.stringify(
            member
          )} is null (or NaN, Infinity or undefined) and canonicalization drops it`
    );
  }
  if (Array.isArray(value)) {
    value.forEach((item) => requireNoNull(item, member));
    return;
  }
  if (typeof value === 'object') {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (key !== CONTEXT_KEY) {
        requireNoNull(item, key);
      }
    }
  }
};

const requireContextUrls = (value: unknown): void => {
  if (Array.isArray(value)) {
    value.forEach(requireContextUrls);
    return;
  }
  if (typeof value !== 'object' || value === null) {
    return;
  }
  for (const [key, member] of Object.entries(value as Record<string, unknown>)) {
    if (key !== CONTEXT_KEY) {
      requireContextUrls(member);
      continue;
    }
    const urls = Array.isArray(member) ? member : [member];
    if (!urls.every((url) => typeof url === 'string' && url !== '')) {
      throw new JsonLdCanonicalizationError(
        'an @context value must be a URL string or an array of URL strings'
      );
    }
  }
};

const requireSignedIRI = (role: string, iri: string): void => {
  if ([...iri].length >= MAX_IRI_LENGTH) {
    throw new JsonLdCanonicalizationError(`${role} IRI too long`);
  }
  if (isRelativeIri(iri)) {
    throw new JsonLdCanonicalizationError(`${role} ${JSON.stringify(iri)} is not an absolute IRI`);
  }
  if ((iri.startsWith('http://') || iri.startsWith('https://')) && !isURL(iri)) {
    throw new JsonLdCanonicalizationError(`${role} ${JSON.stringify(iri)} is not a valid URL`);
  }
};

const requireIRIValues = (key: string, member: unknown): void => {
  const values = Array.isArray(member) ? member : [member];
  for (const value of values) {
    if (typeof value !== 'string') {
      throw new JsonLdCanonicalizationError(`${key} is not an IRI`);
    }
    if (!isKeyword(value)) {
      requireSignedIRI(key, value);
    }
  }
};

const requireAbsoluteIRIs = (expanded: unknown): void => {
  if (Array.isArray(expanded)) {
    expanded.forEach(requireAbsoluteIRIs);
    return;
  }
  if (typeof expanded !== 'object' || expanded === null) {
    return;
  }
  const node = expanded as Record<string, unknown>;
  if (node['@type'] === '@json') {
    const literal = node['@value'];
    if (typeof literal !== 'object' || literal === null || Array.isArray(literal)) {
      throw new JsonLdCanonicalizationError('a JSON literal must be an object');
    }
  }
  for (const [key, member] of Object.entries(node)) {
    if (key === '@value') {
      continue;
    }
    if (key === '@index') {
      throw new JsonLdCanonicalizationError('an @index key is not signed');
    }
    if (key === '@id' || key === '@type') {
      requireIRIValues(key, member);
    } else if (isKeyword(key)) {
      requireAbsoluteIRIs(member);
    } else {
      requireSignedIRI('property', key);
      requireAbsoluteIRIs(member);
    }
  }
};

type WorkCount = { blankNodes: number; values: number };

const isBlankNode = (node: Record<string, unknown>): boolean => {
  const id = node['@id'];
  return typeof id !== 'string' || id.startsWith('_:');
};

const countWork = (expanded: unknown, count: WorkCount): void => {
  if (Array.isArray(expanded)) {
    count.values += expanded.length;
    expanded.forEach((item) => countWork(item, count));
    return;
  }
  if (typeof expanded !== 'object' || expanded === null || '@value' in expanded) {
    return;
  }
  const node = expanded as Record<string, unknown>;
  const list = node['@list'];
  if (Array.isArray(list)) {
    count.blankNodes += list.length;
  } else if (isBlankNode(node)) {
    count.blankNodes += 1;
  }
  Object.values(node).forEach((member) => countWork(member, count));
};

const requireBoundedWork = (expanded: unknown): void => {
  const count: WorkCount = { blankNodes: 0, values: 0 };
  countWork(expanded, count);
  if (count.blankNodes > MAX_BLANK_NODES) {
    throw new JsonLdCanonicalizationError(
      `the document has ${count.blankNodes} blank nodes, more than ${MAX_BLANK_NODES}`
    );
  }
  if (count.values > MAX_VALUES) {
    throw new JsonLdCanonicalizationError(
      `the document has ${count.values} values, more than ${MAX_VALUES}`
    );
  }
};

const wrapJsonLdError = (err: unknown): JsonLdCanonicalizationError =>
  err instanceof JsonLdCanonicalizationError
    ? err
    : new JsonLdCanonicalizationError(err instanceof Error ? err.message : String(err));

const toJsonLdLoader = (documentLoader: DocumentLoader): Options.DocLoader['documentLoader'] =>
  documentLoader as unknown as Options.DocLoader['documentLoader'];

const canonize = async (
  input: JsonDocumentObject,
  documentLoader: DocumentLoader
): Promise<string> => {
  const canonicalForm = await jsonld.canonize(input, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    safe: true,
    documentLoader: toJsonLdLoader(documentLoader),
    maxDeepIterations: MAX_DEEP_ITERATIONS
  } as Options.Normalize);
  if (typeof canonicalForm !== 'string' || canonicalForm === '') {
    throw new JsonLdCanonicalizationError('empty canonical form');
  }
  return canonicalForm;
};

const countEmptyArrays = (value: unknown): number => {
  if (Array.isArray(value)) {
    return value.length === 0
      ? 1
      : value.reduce<number>((total, item) => total + countEmptyArrays(item), 0);
  }
  if (typeof value !== 'object' || value === null) {
    return 0;
  }
  return Object.entries(value as Record<string, unknown>).reduce(
    (total, [key, member]) => (key === CONTEXT_KEY ? total : total + countEmptyArrays(member)),
    0
  );
};

const countSignedEmptyArrays = (expanded: unknown): number => {
  if (Array.isArray(expanded)) {
    return expanded.reduce<number>((total, item) => total + countSignedEmptyArrays(item), 0);
  }
  if (typeof expanded !== 'object' || expanded === null) {
    return 0;
  }
  const node = expanded as Record<string, unknown>;
  if (node['@type'] === '@json') {
    return countEmptyArrays(node['@value']);
  }
  return Object.entries(node).reduce((total, [key, member]) => {
    if (key === '@list' && Array.isArray(member) && member.length === 0) {
      return total + 1;
    }
    return total + countSignedEmptyArrays(member);
  }, 0);
};

export type CanonicalizeStrictOptions = { allowUnsignedEmptyArrays?: boolean };

export const canonicalizeStrict = async (
  input: JsonDocumentObject,
  documentLoader: DocumentLoader,
  options: CanonicalizeStrictOptions = {}
): Promise<string> => {
  try {
    const copy = plainCopy(input);
    requireNoNull(copy, undefined);
    requireContextUrls(copy);
    const expanded = await jsonld.expand(copy, {
      safe: true,
      documentLoader: toJsonLdLoader(documentLoader)
    } as Options.Expand);
    requireAbsoluteIRIs(expanded);
    requireBoundedWork(expanded);
    if (
      !options.allowUnsignedEmptyArrays &&
      countEmptyArrays(copy) !== countSignedEmptyArrays(expanded)
    ) {
      throw new JsonLdCanonicalizationError('an empty array is dropped by canonicalization');
    }
    return await canonize(copy, documentLoader);
  } catch (err) {
    throw wrapJsonLdError(err);
  }
};

const sha256OfText = (text: string): Uint8Array => sha256(new TextEncoder().encode(text));

export type Iden3JwzPayloadOptions = {
  documentLoader: DocumentLoader;
  allowUnsignedEmptyArrays?: boolean;
};

export const computeIden3JwzPayload = async (
  document: JsonDocumentObject,
  proofOptions: JsonDocumentObject,
  options: Iden3JwzPayloadOptions
): Promise<string> => {
  if ('proof' in document) {
    throw new JsonLdCanonicalizationError('the document must not hold a proof member');
  }
  if (!(CONTEXT_KEY in document)) {
    throw new JsonLdCanonicalizationError('the document has no @context');
  }
  const optionsWithoutValue = Object.fromEntries(
    Object.entries(proofOptions).filter(([member]) => member !== 'proofValue')
  );
  const configuration = { ...optionsWithoutValue, [CONTEXT_KEY]: document[CONTEXT_KEY] };
  const configurationHash = sha256OfText(
    await canonicalizeStrict(configuration, options.documentLoader, options)
  );
  const documentHash = sha256OfText(
    await canonicalizeStrict(document, options.documentLoader, options)
  );
  const payload = new Uint8Array(configurationHash.length + documentHash.length);
  payload.set(configurationHash, 0);
  payload.set(documentHash, configurationHash.length);
  return base64url.stringify(payload, { pad: false });
};
