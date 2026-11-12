import { SUPPORTED_PUBLIC_KEY_TYPES } from '../constants';
import { DIDDocument, JsonWebKey, VerificationMethod } from 'did-resolver';
import { secp256k1 as sec } from '@noble/curves/secp256k1';

import { KmsKeyType } from '../../kms';
import {
  base58ToBytes,
  base64UrlToBytes,
  bytesToBase64url,
  bytesToHex,
  hexToBytes
} from '../../utils';
import { PROTOCOL_CONSTANTS } from '..';
import { p384 } from '@noble/curves/p384';
import { BytesHelper } from '@iden3/js-iden3-core';

const DIDAuthenticationSection = 'authentication';
export const resolveVerificationMethods = (didDocument: DIDDocument): VerificationMethod[] => {
  const vms: VerificationMethod[] = didDocument.verificationMethod || [];

  // prioritize: first verification methods to be chosen are from `authentication` section.
  const sortedVerificationMethods = (didDocument[DIDAuthenticationSection] || [])
    .map((verificationMethod) => {
      if (typeof verificationMethod === 'string') {
        return vms.find((i) => i.id === verificationMethod);
      }
      return verificationMethod as VerificationMethod;
    })
    .filter((key) => key) as VerificationMethod[];

  // add all other verification methods
  for (let index = 0; index < vms.length; index++) {
    const id = vms[index].id;
    if (sortedVerificationMethods.findIndex((vm) => vm.id === id) === -1) {
      sortedVerificationMethods.push(vms[index]);
    }
  }
  return sortedVerificationMethods;
};

export const extractPublicKeyBytes = (
  vm: VerificationMethod
): { publicKeyBytes: Uint8Array | null; kmsKeyType?: KmsKeyType } => {
  const isSupportedVmType = Object.keys(SUPPORTED_PUBLIC_KEY_TYPES).some((key) =>
    SUPPORTED_PUBLIC_KEY_TYPES[key as keyof typeof SUPPORTED_PUBLIC_KEY_TYPES].includes(vm.type)
  );
  if (vm.publicKeyBase58 && isSupportedVmType) {
    return { publicKeyBytes: base58ToBytes(vm.publicKeyBase58), kmsKeyType: KmsKeyType.Secp256k1 };
  }
  if (vm.publicKeyBase64 && isSupportedVmType) {
    return {
      publicKeyBytes: base64UrlToBytes(vm.publicKeyBase64),
      kmsKeyType: KmsKeyType.Secp256k1
    };
  }
  if (vm.publicKeyHex && isSupportedVmType) {
    return { publicKeyBytes: hexToBytes(vm.publicKeyHex), kmsKeyType: KmsKeyType.Secp256k1 };
  }
  if (
    vm.publicKeyJwk &&
    vm.publicKeyJwk.crv === 'secp256k1' &&
    vm.publicKeyJwk.x &&
    vm.publicKeyJwk.y
  ) {
    const [xHex, yHex] = [
      base64UrlToBytes(vm.publicKeyJwk.x),
      base64UrlToBytes(vm.publicKeyJwk.y)
    ].map(bytesToHex);
    const x = xHex.includes('0x') ? BigInt(xHex) : BigInt(`0x${xHex}`);
    const y = yHex.includes('0x') ? BigInt(yHex) : BigInt(`0x${yHex}`);
    return {
      publicKeyBytes: sec.ProjectivePoint.fromAffine({
        x,
        y
      }).toRawBytes(false),
      kmsKeyType: KmsKeyType.Secp256k1
    };
  }
  return { publicKeyBytes: null };
};

/**
 * toPublicKeyJwk - converts given key string to JsonWebKey format based on the algorithm
 * @param keyStr - public key in string format
 * @param alg - algorithm to be used for conversion
 * @returns JsonWebKey
 */
export const toPublicKeyJwk = (keyStr: string, keyType: KmsKeyType): JsonWebKey => {
  switch (keyType) {
    case KmsKeyType.RsaOaep256: {
      const pubJwk = JSON.parse(keyStr);

      return {
        kty: pubJwk.kty,
        n: pubJwk.n,
        e: pubJwk.e,
        alg: PROTOCOL_CONSTANTS.AcceptJweKEKAlgorithms.RSA_OAEP_256,
        ext: true
      };
    }

    case KmsKeyType.P384: {
      const pubJwk = p384.Point.fromHex(keyStr);

      const coordinateByteLength = 48;

      const xBytes = BytesHelper.intToNBytes(pubJwk.x, coordinateByteLength).reverse();
      const yBytes = BytesHelper.intToNBytes(pubJwk.y, coordinateByteLength).reverse();
      const x = bytesToBase64url(xBytes);
      const y = bytesToBase64url(yBytes);

      return {
        kty: 'EC',
        crv: 'P-384',
        alg: PROTOCOL_CONSTANTS.AcceptJweKEKAlgorithms.ECDH_ES_A256KW,
        x,
        y,
        ext: true
      };
    }

    case KmsKeyType.X25519: {
      return {
        kty: 'OKP',
        crv: 'X25519',
        x: bytesToBase64url(hexToBytes(keyStr)),
        alg: PROTOCOL_CONSTANTS.AcceptJweKEKAlgorithms.ECDH_ES_A256KW
      };
    }
    default:
      throw new Error(
        `Unsupported key type: ${keyType}. Supported key types ${KmsKeyType.RsaOaep256}, ${KmsKeyType.P384}, ${KmsKeyType.X25519}`
      );
  }
};
