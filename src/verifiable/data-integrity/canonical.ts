import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { sha256 } from '@iden3/js-crypto';
import { base64url } from 'rfc4648';
import jsonld from 'jsonld';
import { Options } from 'jsonld';
import { JsonDocumentObject } from '../../iden3comm';
import { isKeyword, isRelativeIri, isURL } from './iri';

const MAX_IRI_LENGTH = 2083;
const MAX_DEEP_ITERATIONS = 1;
const CONTEXT_KEY = '@context';

export class JsonLdCanonicalizationError extends Error {
  constructor(message: string) {
    super(`canonicalization failed: ${message}`);
    this.name = 'JsonLdCanonicalizationError';
  }
}

type PathStep = string | number;

const plainCopy = (input: JsonDocumentObject): JsonDocumentObject =>
  JSON.parse(JSON.stringify(input)) as JsonDocumentObject;

const requireNoNull = (value: unknown, member: string | undefined): void => {
  if (value === null) {
    throw new JsonLdCanonicalizationError(
      member === undefined
        ? 'a null value is not signed'
        : `member ${JSON.stringify(member)} is null and canonicalization drops it`
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

const findEmptyArrays = (value: unknown, path: PathStep[], found: PathStep[][]): void => {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      found.push(path);
      return;
    }
    value.forEach((item, index) => findEmptyArrays(item, [...path, index], found));
    return;
  }
  if (typeof value === 'object' && value !== null) {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (key !== CONTEXT_KEY) {
        findEmptyArrays(item, [...path, key], found);
      }
    }
  }
};

const withoutPath = (input: JsonDocumentObject, path: PathStep[]): JsonDocumentObject => {
  const copy = plainCopy(input);
  let parent = copy as unknown as Record<PathStep, unknown>;
  for (const step of path.slice(0, -1)) {
    parent = parent[step] as Record<PathStep, unknown>;
  }
  const last = path[path.length - 1];
  if (Array.isArray(parent)) {
    parent.splice(last as number, 1);
  } else {
    delete parent[last];
  }
  return copy;
};

const memberName = (path: PathStep[]): string => {
  const name = [...path].reverse().find((step) => typeof step === 'string');
  return JSON.stringify(name ?? '');
};

export type CanonicalizeStrictOptions = { allowUnsignedEmptyArrays?: boolean };

export const canonicalizeStrict = async (
  input: JsonDocumentObject,
  documentLoader: DocumentLoader,
  options: CanonicalizeStrictOptions = {}
): Promise<string> => {
  requireNoNull(input, undefined);
  const copy = plainCopy(input);
  let canonicalForm: string;
  try {
    const expanded = await jsonld.expand(copy, {
      safe: true,
      documentLoader: toJsonLdLoader(documentLoader)
    } as Options.Expand);
    requireAbsoluteIRIs(expanded);
    canonicalForm = await canonize(copy, documentLoader);
  } catch (err) {
    throw wrapJsonLdError(err);
  }
  if (options.allowUnsignedEmptyArrays) {
    return canonicalForm;
  }
  const emptyArrays: PathStep[][] = [];
  findEmptyArrays(copy, [], emptyArrays);
  for (const path of emptyArrays) {
    let without: string;
    try {
      without = await canonize(withoutPath(copy, path), documentLoader);
    } catch (err) {
      throw wrapJsonLdError(err);
    }
    if (without === canonicalForm) {
      throw new JsonLdCanonicalizationError(
        `member ${memberName(path)} is an empty array that canonicalization drops`
      );
    }
  }
  return canonicalForm;
};

const sha256OfText = (text: string): Uint8Array => sha256(new TextEncoder().encode(text));

export const computeIden3JwzPayload = async (
  document: JsonDocumentObject,
  proofOptions: JsonDocumentObject,
  options: { documentLoader: DocumentLoader; allowUnsignedEmptyArrays?: boolean }
): Promise<string> => {
  if ('proof' in document) {
    throw new Error('the document must not hold a proof member');
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
