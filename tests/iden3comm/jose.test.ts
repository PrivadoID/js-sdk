import { describe, expect, it } from 'vitest';
import { FlattenedJWE, JWK, importJWK } from 'jose';
import { JoseService, byteDecoder } from '../../src';

// An encrypted credential as issuer-node sends it: iden3comm (Go) jwe.Encrypt on top of
// lestrrat-go/jwx, ECDH-ES+A256KW with A256GCM, flattened JSON serialization. jwx writes
// the recipient's alg, epk and kid into both the protected header and the per-recipient
// `header`. The recipient key below is a throwaway key generated for this test.
const RECIPIENT_KID = 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX#ec-key';

const RECIPIENT_PRIVATE_JWK: JWK = {
  alg: 'ECDH-ES+A256KW',
  crv: 'P-256',
  d: 'CpURBKUSILWWEdf-ziXyru0uu93Qdn38emaNtmx9Vf4',
  kid: RECIPIENT_KID,
  kty: 'EC',
  x: '25g9JzDIqMogEFdddVi9Vr1y3MEEyzHh1c5XjntOMJs',
  y: '5KeNe2VYxEZpRQNtnnIHI_-hzw0HYyjcMHf1d780eRg'
};

const ISSUER_NODE_JWE: FlattenedJWE = {
  protected:
    'eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI4OXVxUjBLWDB0aWxaZlc3ZkMxaVdYSlowOWJ5N2RDUXVpTFg5SV8zX3lzIiwieSI6IjAyWC1RN3BTZVl0S091LWxZdU5MNFJBUXRFNmhpYXZYRWtjWVkteFhUZTgifSwia2lkIjoiZGlkOmlkZW4zOnBvbHlnb246YW1veTp4Q1JwNzVEZ0FkUzYzVzY1Zm1YSHo2cDlEd2RvbnVSVTllNDZEaWZoWCNlYy1rZXkifQ',
  header: {
    alg: 'ECDH-ES+A256KW',
    epk: {
      crv: 'P-256',
      kty: 'EC',
      x: '89uqR0KX0tilZfW7fC1iWXJZ09by7dCQuiLX9I_3_ys',
      y: '02X-Q7pSeYtKOu-lYuNL4RAQtE6hiavXEkcYY-xXTe8'
    },
    kid: RECIPIENT_KID
  },
  encrypted_key: '5EM-RDuJQ5mlQjT5uRxqkCigbt4e17pfdVov-SDHnyZpleBFG1uGTg',
  iv: '8cQcC4nXJ-kFI4gk',
  ciphertext:
    'ZJXZ-XWAV1G2hHgfjXFSKSoXpjId0gGf_Fkey40cq7267dozAnqKcLBRiOLadR3wi4m57EKZBVR46pGcj-YSOKf-eMGih1cZdOLTH6C6qW78RBHkV-UDNXvesX8iRap97hgOz5Xm86ieJkLUOpwSk6kIr9h95cFWwYw8cWOcoYHKLxcXq7CAda144w4E8dB_MUXNLx-fNEWhog6T6elzcmNsUeCSY1WsPd9A3g8xdwyCh0F1NSFG3e8oHO2flaIqxG7LTIOadv9uNELk0i2QRABRxJuyYmtyXlC8',
  tag: 'vfB6GgFb2086CbwrJ0w-Ww'
};

const PLAINTEXT = {
  id: 'urn:uuid:3f6e8f86-5c63-4d5e-9b1a-6c2f0e1d7a42',
  type: ['VerifiableCredential', 'KYCAgeCredential'],
  credentialSubject: {
    id: 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX',
    birthday: 19960424
  }
};

describe('JoseService.decrypt', () => {
  const newService = (requestedKids: string[] = []) =>
    new JoseService(async (kid) => {
      requestedKids.push(kid);
      return (await importJWK(RECIPIENT_PRIVATE_JWK, 'ECDH-ES+A256KW')) as CryptoKey;
    });

  it('decrypts a flattened ECDH-ES+A256KW JWE from issuer-node that repeats epk in the per-recipient header', async () => {
    const requestedKids: string[] = [];

    const { plaintext } = await newService(requestedKids).decrypt(structuredClone(ISSUER_NODE_JWE));

    expect(JSON.parse(byteDecoder.decode(plaintext))).toEqual(PLAINTEXT);
    expect(requestedKids).toEqual([RECIPIENT_KID]);
  });

  it('rejects a flattened JWE whose per-recipient epk differs from the protected one', async () => {
    const jwe = structuredClone(ISSUER_NODE_JWE);
    jwe.header = {
      ...jwe.header,
      epk: { ...(jwe.header?.epk as JWK), x: RECIPIENT_PRIVATE_JWK.x }
    };

    await expect(newService().decrypt(jwe)).rejects.toThrow(/must be disjoint/);
  });
});
