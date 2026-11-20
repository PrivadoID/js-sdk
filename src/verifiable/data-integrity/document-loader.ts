import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { JsonLd } from 'jsonld/jsonld-spec';

export const createStrictDocumentLoader = (
  contexts: Readonly<Record<string, string | object>>
): DocumentLoader => {
  const parsed = new Map<string, unknown>();
  for (const [url, context] of Object.entries(contexts)) {
    parsed.set(url, typeof context === 'string' ? JSON.parse(context) : context);
  }
  return async (url) => {
    if (!parsed.has(url)) {
      throw new Error(`context ${url} is not bundled`);
    }
    return {
      documentUrl: url,
      document: structuredClone(parsed.get(url)) as JsonLd
    };
  };
};
