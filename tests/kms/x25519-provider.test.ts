import { beforeEach, describe, expect, it } from 'vitest';
import {
  InMemoryPrivateKeyStore,
  KmsKeyType,
  X25519Provider,
  hexToBytes,
  toPublicKeyJwk
} from '../../src';

describe('X25519Provider', () => {
  const aliceSeed = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
  const alicePublicHex = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
  const alicePublicBase64Url = 'hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo';
  let store: InMemoryPrivateKeyStore;
  let provider: X25519Provider;

  beforeEach(() => {
    store = new InMemoryPrivateKeyStore();
    provider = new X25519Provider(store);
  });

  it('creates the key from a 32-byte seed with the alias X25519:<public hex>', async () => {
    const id = await provider.newPrivateKeyFromSeed(hexToBytes(aliceSeed));
    expect(id.type).to.equal(KmsKeyType.X25519);
    expect(id.id).to.equal(`X25519:${alicePublicHex}`);
    expect(await provider.publicKey(id)).to.equal(alicePublicHex);
  });

  it('creates a random key with a 64-character hex public key', async () => {
    const first = await provider.newPrivateKey();
    const second = await provider.newPrivateKey();
    expect(first.id).to.match(/^X25519:[0-9a-f]{64}$/);
    expect(first.id).to.not.equal(second.id);
    expect((await provider.list()).length).to.equal(2);
  });

  it('refuses a seed that is not 32 bytes', async () => {
    await expect(provider.newPrivateKeyFromSeed(new Uint8Array(31))).rejects.toThrow(
      'Seed should be 32 bytes'
    );
    await expect(provider.newPrivateKeyFromSeed(new Uint8Array(33))).rejects.toThrow(
      'Seed should be 32 bytes'
    );
  });

  it('stores the private key as an OKP X25519 JWK', async () => {
    const id = await provider.newPrivateKeyFromSeed(hexToBytes(aliceSeed));
    const stored = JSON.parse(await store.get({ alias: id.id }));
    expect(stored).to.deep.equal({
      kty: 'OKP',
      crv: 'X25519',
      x: alicePublicBase64Url,
      d: 'dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo'
    });
  });

  it('refuses to sign', async () => {
    const id = await provider.newPrivateKeyFromSeed(hexToBytes(aliceSeed));
    await expect(provider.sign(id, new Uint8Array(32))).rejects.toThrow('X25519 keys do not sign');
  });

  it('refuses to verify', async () => {
    const id = await provider.newPrivateKeyFromSeed(hexToBytes(aliceSeed));
    await expect(provider.verify(new Uint8Array(32), '00', id)).rejects.toThrow(
      'X25519 keys do not sign'
    );
  });

  it('gives the public JWK with alg ECDH-ES+A256KW', async () => {
    const id = await provider.newPrivateKeyFromSeed(hexToBytes(aliceSeed));
    const publicHex = await provider.publicKey(id);
    expect(toPublicKeyJwk(publicHex, KmsKeyType.X25519)).to.deep.equal({
      kty: 'OKP',
      crv: 'X25519',
      x: alicePublicBase64Url,
      alg: 'ECDH-ES+A256KW'
    });
  });

  it('exposes the private key store', async () => {
    expect(await provider.getPkStore()).to.equal(store);
  });
});
