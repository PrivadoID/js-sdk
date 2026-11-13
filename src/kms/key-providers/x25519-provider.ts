import { IKeyProvider } from '../kms';
import { AbstractPrivateKeyStore, KmsKeyId, KmsKeyType } from '../store';
import * as providerHelpers from '../provider-helpers';
import { x25519 } from '@noble/curves/ed25519';
import { base64UrlToBytes, bytesToBase64url, bytesToHex } from '../../utils';

const X25519_KEY_LENGTH = 32;

export class X25519Provider implements IKeyProvider {
  readonly keyType: KmsKeyType = KmsKeyType.X25519;

  constructor(private readonly _keyStore: AbstractPrivateKeyStore) {}

  async list(): Promise<{ alias: string; key: string }[]> {
    const allKeysFromKeyStore = await this._keyStore.list();
    return allKeysFromKeyStore.filter((key) => key.alias.startsWith(this.keyType));
  }

  async getPkStore(): Promise<AbstractPrivateKeyStore> {
    return this._keyStore;
  }

  async newPrivateKeyFromSeed(seed: Uint8Array): Promise<KmsKeyId> {
    if (seed.length !== X25519_KEY_LENGTH) {
      throw new Error(`Seed should be ${X25519_KEY_LENGTH} bytes`);
    }

    const publicKey = x25519.getPublicKey(seed);
    const kmsId = {
      type: this.keyType,
      id: providerHelpers.keyPath(this.keyType, bytesToHex(publicKey))
    };

    await this._keyStore.importKey({
      alias: kmsId.id,
      key: JSON.stringify({
        kty: 'OKP',
        crv: 'X25519',
        x: bytesToBase64url(publicKey),
        d: bytesToBase64url(seed)
      })
    });

    return kmsId;
  }

  async newPrivateKey(): Promise<KmsKeyId> {
    const seed = globalThis.crypto.getRandomValues(new Uint8Array(X25519_KEY_LENGTH));
    return this.newPrivateKeyFromSeed(seed);
  }

  async publicKey(keyId: KmsKeyId): Promise<string> {
    const privateJwk = JSON.parse(await this._keyStore.get({ alias: keyId.id }));
    return bytesToHex(x25519.getPublicKey(base64UrlToBytes(privateJwk.d)));
  }

  async sign(): Promise<Uint8Array> {
    throw new Error('X25519 keys do not sign');
  }

  async verify(): Promise<boolean> {
    throw new Error('X25519 keys do not sign');
  }
}
