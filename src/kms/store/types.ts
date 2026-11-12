import { TypedDataDomain, TypedDataField } from 'ethers';

/**
 * Key type that can be used in the key management system
 *
 * @enum {number}
 */
export enum KmsKeyType {
  BabyJubJub = 'BJJ',
  Secp256k1 = 'Secp256k1',
  Ed25519 = 'Ed25519',
  RsaOaep256 = 'RSA-OAEP-256',
  P384 = 'P-384',
  X25519 = 'X25519'
}

/**
 * ID of the key that describe contain key type
 *
 * @public
 * @interface   KmsKeyId
 */
export interface KmsKeyId {
  type: KmsKeyType;
  id: string;
}

export interface TypedData {
  domain: TypedDataDomain;
  types: Record<string, Array<TypedDataField>>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  message: Record<string, any>;
}
