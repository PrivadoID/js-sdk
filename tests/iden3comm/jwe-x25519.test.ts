import { describe, expect, it } from 'vitest';
import { DID } from '@iden3/js-iden3-core';
import {
  CredentialWallet,
  CredentialStatusResolverRegistry,
  CredentialStatusType,
  DefaultKMSKeyResolver,
  IdentityWallet,
  InMemoryPrivateKeyStore,
  IKeyProvider,
  JoseService,
  KMS,
  PROTOCOL_CONSTANTS,
  RHSResolver,
  RsaOAEPKeyProvider,
  X25519Provider,
  byteDecoder,
  byteEncoder,
  hexToBytes,
  toPublicKeyJwk
} from '../../src';
import {
  MOCK_STATE_STORAGE,
  getInMemoryDataStorage,
  registerKeyProvidersInMemoryKMS
} from '../helpers';

describe('JWE with X25519 keys', () => {
  const ownerDid = DID.parse('did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX');
  const aliceSeed = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');

  const registerKms = (...providers: IKeyProvider[]): KMS => {
    const kms = new KMS();
    providers.forEach((provider) => kms.registerKeyProvider(provider.keyType, provider));
    return kms;
  };

  const recipientFor = async (
    provider: IKeyProvider,
    alias: string,
    alg: PROTOCOL_CONSTANTS.AcceptJweKEKAlgorithms
  ) => ({
    alg,
    did: ownerDid.string(),
    keyType: 'JsonWebKey2020' as const,
    kid: `${ownerDid.string()}#${alias}`,
    recipientJWK: toPublicKeyJwk(
      await provider.publicKey({ type: provider.keyType, id: alias }),
      provider.keyType
    ) as JsonWebKey
  });

  it('decrypts a two-recipient JWE for an X25519 key and an RSA key', async () => {
    const x25519Provider = new X25519Provider(new InMemoryPrivateKeyStore());
    const rsaProvider = new RsaOAEPKeyProvider(new InMemoryPrivateKeyStore());
    const x25519KeyId = await x25519Provider.newPrivateKeyFromSeed(aliceSeed);
    const rsaKeyId = await rsaProvider.newPrivateKey();

    const plaintext = byteEncoder.encode(JSON.stringify({ hello: 'portal' }));
    const sender = new JoseService(async () => {
      throw new Error('The sender does not decrypt');
    });
    const jwe = await sender.encrypt(plaintext, {
      enc: PROTOCOL_CONSTANTS.CEKEncryption.A256GCM,
      typ: PROTOCOL_CONSTANTS.MediaType.EncryptedMessage,
      recipients: [
        await recipientFor(
          x25519Provider,
          x25519KeyId.id,
          PROTOCOL_CONSTANTS.AcceptJweKEKAlgorithms.ECDH_ES_A256KW
        ),
        await recipientFor(
          rsaProvider,
          rsaKeyId.id,
          PROTOCOL_CONSTANTS.AcceptJweKEKAlgorithms.RSA_OAEP_256
        )
      ]
    });
    expect(jwe.recipients).to.have.length(2);

    const holders = [
      registerKms(x25519Provider),
      registerKms(rsaProvider),
      registerKms(x25519Provider, rsaProvider)
    ];
    for (const kms of holders) {
      const receiver = new JoseService(new DefaultKMSKeyResolver(kms).resolvePrivateKeyByKid);
      const { plaintext: decrypted } = await receiver.decrypt(jwe);
      expect(byteDecoder.decode(decrypted)).to.equal(byteDecoder.decode(plaintext));
    }
  });

  it('adds the X25519 key under keyAgreement of the profile did_doc', async () => {
    const dataStorage = getInMemoryDataStorage(MOCK_STATE_STORAGE);
    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );
    const idWallet = new IdentityWallet(
      registerKeyProvidersInMemoryKMS(),
      dataStorage,
      new CredentialWallet(dataStorage, resolvers)
    );
    const x25519Provider = new X25519Provider(new InMemoryPrivateKeyStore());
    const verifier = 'verifier.example';

    const profileDid = await idWallet.createProfile(ownerDid, 7, verifier, {
      encryptionKeyOps: { provider: x25519Provider }
    });

    const [profile] = await idWallet.getProfilesByVerifier(verifier);
    const [{ alias }] = await x25519Provider.list();
    expect(alias).to.match(/^X25519:[0-9a-f]{64}$/);
    expect(profile.did_doc?.id).to.equal(profileDid.string());
    expect(profile.did_doc?.keyAgreement).to.deep.equal([`${profileDid.string()}#${alias}`]);
    const [verificationMethod] = profile.did_doc?.verificationMethod ?? [];
    expect(verificationMethod.id).to.equal(`${profileDid.string()}#${alias}`);
    expect(verificationMethod.publicKeyJwk?.alg).to.equal(
      PROTOCOL_CONSTANTS.AcceptJweKEKAlgorithms.ECDH_ES_A256KW
    );
    expect(verificationMethod.publicKeyJwk?.crv).to.equal('X25519');
  });
});
