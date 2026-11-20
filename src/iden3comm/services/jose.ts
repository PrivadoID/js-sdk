import {
  decodeProtectedHeader,
  flattenedDecrypt,
  FlattenedJWE,
  generalDecrypt,
  GeneralDecryptResult,
  GeneralEncrypt,
  GeneralJWE,
  JWEHeaderParameters
} from 'jose';
import { VerificationMethodType } from '../constants';

export type JoseParams = {
  enc: string;
  typ: string;
  recipients: {
    alg: string;
    did: string;
    keyType: VerificationMethodType;
    kid: string;
    recipientJWK: JsonWebKey;
  }[];
};

/**
 * JoseService performs encryption and decryption of messages based on JOSE standard
 *
 * @beta
 * @class JoseService
 */
export class JoseService {
  constructor(private readonly resolvePrivateKeyByKid: (kid: string) => Promise<CryptoKey>) {}

  async encrypt(msg: Uint8Array, options: JoseParams): Promise<GeneralJWE> {
    const { enc, typ, recipients } = options;
    const generalJwe = new GeneralEncrypt(msg).setProtectedHeader({ enc, typ });

    recipients.forEach(({ recipientJWK, alg, kid }) => {
      generalJwe.addRecipient(recipientJWK).setUnprotectedHeader({
        alg,
        kid
      });
    });

    const jwe: GeneralJWE = await generalJwe.encrypt();

    return jwe;
  }

  async decrypt(data: GeneralJWE | FlattenedJWE): Promise<GeneralDecryptResult> {
    const getKey = (protectedHeaders: JWEHeaderParameters | undefined, jwe: FlattenedJWE) => {
      const kid = jwe.header?.kid || (protectedHeaders && protectedHeaders.kid);

      if (!kid) {
        throw new Error('kid is required');
      }
      return this.resolvePrivateKeyByKid(kid);
    };

    if (Object.prototype.hasOwnProperty.call(data, 'encrypted_key')) {
      const flattenedJWE: FlattenedJWE = data as FlattenedJWE;

      flattenedJWE.header = this.removeDuplicates(
        decodeProtectedHeader(flattenedJWE),
        flattenedJWE.header || {}
      );
      return flattenedDecrypt(data as FlattenedJWE, getKey);
    }
    return generalDecrypt(data as GeneralJWE, getKey);
  }

  // Some encoders (e.g. iden3comm's Go jwe.Encrypt) repeat protected header parameters,
  // including object-valued ones like epk, in the per-recipient header. jose requires the
  // two to be disjoint, so drop parameters whose values are equal. Differing values are
  // kept, so jose still rejects a per-recipient header that contradicts the protected one.
  private removeDuplicates = (
    protectedHeader: Record<string, unknown>,
    recipientHeader: Record<string, unknown>
  ) => {
    const cleaned = { ...recipientHeader };
    for (const [key, value] of Object.entries(protectedHeader)) {
      if (isEqualJSONValue(cleaned[key], value)) delete cleaned[key];
    }
    return cleaned;
  };
}

const isEqualJSONValue = (a: unknown, b: unknown): boolean => {
  if (a === b) return true;
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const aRecord = a as Record<string, unknown>;
  const bRecord = b as Record<string, unknown>;
  const aKeys = Object.keys(aRecord);
  return (
    aKeys.length === Object.keys(bRecord).length &&
    aKeys.every(
      (key) =>
        Object.prototype.hasOwnProperty.call(bRecord, key) &&
        isEqualJSONValue(aRecord[key], bRecord[key])
    )
  );
};
