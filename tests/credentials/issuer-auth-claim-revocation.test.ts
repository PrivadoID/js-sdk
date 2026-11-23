import { DID } from '@iden3/js-iden3-core';
import { Proof } from '@iden3/js-merkletree';
import { describe, expect, it, vi } from 'vitest';

import { CircuitClaim, CircuitId, getRequiredProofType, Query } from '../../src/circuits';
import {
  CredentialStatusResolver,
  CredentialStatusResolverRegistry,
  CredentialWallet,
  getIssuerAuthClaimRevocationStatus,
  isRevokedByIssuerAuthClaim
} from '../../src/credentials';
import { processZeroKnowledgeProofRequests, ZeroKnowledgeProofRequest } from '../../src/iden3comm';
import { IIdentityWallet } from '../../src/identity';
import { InputGenerator, IProofService, PreparedCredential, ProofService } from '../../src/proof';
import { ICircuitStorage, IDataStorage, IStateStorage } from '../../src/storage';
import {
  CredentialStatus,
  CredentialStatusType,
  ProofQuery,
  ProofType,
  RevocationStatus,
  VerifiableConstants,
  W3CCredential
} from '../../src/verifiable';

const ISSUER = 'did:iden3:polygon:amoy:xJNwv94NrHy1xXU3poKTRL24WJEXmkEggwbBWy6gu';
const ISSUER_STATE = {
  claimsTreeRoot: '1483789a545832ba69d54ed1691ce758f9b8297542b2749f6fa4786e74fbe80e',
  value: '310ccc3f33fbbfd50da56755e442896065b388e9c4adadd644588eaa6e171b1a',
  rootOfRoots: '0000000000000000000000000000000000000000000000000000000000000000',
  revocationTreeRoot: '0000000000000000000000000000000000000000000000000000000000000000'
};
const CORE_CLAIM =
  '637056ad190ec7df5fef1345fda35e1f2200000000000000000000000000000001a16e78ba913717bc15cbe326e236c7eef4f9201582b50e145cb669139c0d0068fbed6c1ddf63a9a4eaa0d4a577b770a5acaf37a542cf86cb6e9e93e9b608020000000000000000000000000000000000000000000000000000000000000000e7f8503a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
// auth claim with revocation nonce 0
const AUTH_CORE_CLAIM =
  'cca3371a6cb1b715004407e325bd993c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000079adcc5f988e5e6fb7d04adcb5e07afdd53babf34acdb75aa51ac8e1ddc0ee20211c823ff2b1ee62e988fba84247930add22fbbc2fcc4f1b4fd3a50e07f9e6170000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

const VALID_KEY_STATUS = 'https://issuer.example/valid-key';
const REVOKED_KEY_STATUS = 'https://issuer.example/revoked-key';
const REVOKED_CREDENTIAL_NONCE = 666;

/** Resolves every status as non-revoked, except the revoked key and the revoked credential nonce. */
class StubResolver implements CredentialStatusResolver {
  // ids of the resolved statuses, in call order
  readonly calls: string[] = [];

  async resolve(credentialStatus: CredentialStatus): Promise<RevocationStatus> {
    this.calls.push(credentialStatus.id);
    const mtp = new Proof();
    mtp.existence =
      credentialStatus.id === REVOKED_KEY_STATUS ||
      credentialStatus.revocationNonce === REVOKED_CREDENTIAL_NONCE;
    return { mtp, issuer: {} };
  }
}

const buildCredential = ({
  id,
  authKeyStatusId = VALID_KEY_STATUS,
  revocationNonce = 978385127,
  proofs
}: {
  id: string;
  authKeyStatusId?: string;
  revocationNonce?: number;
  proofs: ProofType[];
}): W3CCredential => {
  const sigProof = {
    type: ProofType.BJJSignature,
    issuerData: {
      id: ISSUER,
      state: ISSUER_STATE,
      mtp: { existence: true, siblings: [] },
      authCoreClaim: AUTH_CORE_CLAIM,
      credentialStatus: {
        id: authKeyStatusId,
        revocationNonce: 0,
        type: CredentialStatusType.Iden3commRevocationStatusV1
      }
    },
    coreClaim: CORE_CLAIM,
    signature:
      'b17ca01ab223b6281e0b22b4f8945729ffb39eaf4b2a0db59548db7ab0df092e423dfc2472cce2e269a80a4d37bb520eda59ab3a0adfae043caa38a464869505'
  };
  const mtpProof = {
    type: ProofType.Iden3SparseMerkleTreeProof,
    issuerData: { id: ISSUER, state: ISSUER_STATE },
    coreClaim: CORE_CLAIM,
    mtp: { existence: true, siblings: [] }
  };
  return W3CCredential.fromJSON({
    id,
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.iden3.io/core/jsonld/iden3proofs.jsonld',
      'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15'
    ],
    type: ['VerifiableCredential', 'operators'],
    credentialSubject: {
      id: 'did:iden3:privado:main:2SeEkMwamyzKWr3aGUT9AvDjiQK4rMEAZbUZgEzP72',
      type: 'operators'
    },
    issuer: ISSUER,
    credentialSchema: {
      id: 'https://ipfs.io/ipfs/QmWDmZQrtvidcNK7d6rJwq7ZSi8SUygJaKepN7NhKtGryc',
      type: 'JsonSchema2023'
    },
    credentialStatus: {
      id: 'https://issuer.example/credential-status',
      revocationNonce,
      type: CredentialStatusType.Iden3commRevocationStatusV1
    },
    issuanceDate: '2025-04-11T12:00:49.921271223Z',
    proof: proofs.map((p) => (p === ProofType.BJJSignature ? sigProof : mtpProof))
  });
};

const SIG = ProofType.BJJSignature;
const MTP = ProofType.Iden3SparseMerkleTreeProof;

const signedWithValidKey = buildCredential({ id: 'valid-key', proofs: [SIG] });
const signedWithRevokedKey = buildCredential({
  id: 'revoked-key',
  authKeyStatusId: REVOKED_KEY_STATUS,
  proofs: [SIG]
});
const signedWithRevokedKeyAndMtp = buildCredential({
  id: 'revoked-key-with-mtp',
  authKeyStatusId: REVOKED_KEY_STATUS,
  proofs: [SIG, MTP]
});
const mtpOnly = buildCredential({ id: 'mtp-only', proofs: [MTP] });
const revokedByOwnNonce = buildCredential({
  id: 'revoked-own-nonce',
  revocationNonce: REVOKED_CREDENTIAL_NONCE,
  proofs: [SIG]
});

const newCredentialWallet = (resolver = new StubResolver()) => {
  const resolvers = new CredentialStatusResolverRegistry();
  resolvers.register(CredentialStatusType.Iden3commRevocationStatusV1, resolver);
  return new CredentialWallet({} as IDataStorage, resolvers);
};

const newProofService = (credentials: W3CCredential[], credentialWallet = newCredentialWallet()) =>
  new ProofService(
    {
      findOwnedCredentialsByDID: async () => credentials,
      getGenesisDIDMetadata: async (did: DID) => ({ nonce: 0, genesisDID: did }),
      getCoreClaimFromCredential: async (credential: W3CCredential) =>
        credential.getCoreClaimFromProof(SIG)
    } as unknown as IIdentityWallet,
    credentialWallet,
    {} as ICircuitStorage,
    {} as IStateStorage
  );

const nonRevokedStatus = (): RevocationStatus => ({ mtp: new Proof(), issuer: {} });

const ALL_REVOKED = VerifiableConstants.ERRORS.CREDENTIAL_WALLET_ALL_CREDENTIALS_ARE_REVOKED;
const AUTH_CLAIM_REVOKED = VerifiableConstants.ERRORS.PROOF_SERVICE_ISSUER_AUTH_CLAIM_REVOKED;
const NO_CREDENTIAL_FOR_QUERY = VerifiableConstants.ERRORS.PROOF_SERVICE_NO_CREDENTIAL_FOR_QUERY;
const did = DID.parse(ISSUER);

describe('issuer auth claim revocation', () => {
  describe('getRequiredProofType', () => {
    it('is the signature for Sig V2 circuits, whatever the query says', () => {
      for (const circuitId of [CircuitId.AtomicQuerySigV2, CircuitId.AtomicQuerySigV2OnChain]) {
        expect(getRequiredProofType(circuitId, { proofType: MTP })).to.equal(SIG);
      }
    });

    it('is the MTP for MTP V2 circuits, whatever the query says', () => {
      for (const circuitId of [CircuitId.AtomicQueryMTPV2, CircuitId.AtomicQueryMTPV2OnChain]) {
        expect(getRequiredProofType(circuitId, { proofType: SIG })).to.equal(MTP);
      }
    });

    it('is the query proof type for V3 circuits', () => {
      for (const circuitId of [
        CircuitId.AtomicQueryV3,
        CircuitId.AtomicQueryV3OnChain,
        CircuitId.AtomicQueryV3Stable,
        CircuitId.AtomicQueryV3OnChainStable
      ]) {
        expect(getRequiredProofType(circuitId, { proofType: SIG })).to.equal(SIG);
        expect(getRequiredProofType(circuitId, { proofType: MTP })).to.equal(MTP);
        expect(getRequiredProofType(circuitId, {})).to.equal(undefined);
        expect(getRequiredProofType(circuitId, { proofType: 'unknown' })).to.equal(undefined);
      }
    });

    it('is undefined for circuits that do not use issuer proofs', () => {
      expect(getRequiredProofType(CircuitId.LinkedMultiQuery10, { proofType: SIG })).to.equal(
        undefined
      );
      expect(getRequiredProofType(CircuitId.AuthV3, undefined)).to.equal(undefined);
    });
  });

  describe('getIssuerAuthClaimRevocationStatus', () => {
    const credentialWallet = newCredentialWallet();

    it('resolves the status of the auth claim that signed the credential', async () => {
      const valid = await getIssuerAuthClaimRevocationStatus(credentialWallet, signedWithValidKey);
      const revoked = await getIssuerAuthClaimRevocationStatus(
        credentialWallet,
        signedWithRevokedKey
      );
      expect(valid?.mtp.existence).to.equal(false);
      expect(revoked?.mtp.existence).to.equal(true);
    });

    it('resolves nothing when the signature will not be used', async () => {
      expect(
        await getIssuerAuthClaimRevocationStatus(credentialWallet, signedWithRevokedKeyAndMtp)
      ).to.equal(undefined);
      expect(
        await getIssuerAuthClaimRevocationStatus(credentialWallet, signedWithValidKey, {
          proofType: MTP
        })
      ).to.equal(undefined);
    });
  });

  describe('isRevokedByIssuerAuthClaim', () => {
    const credentialWallet = newCredentialWallet();

    it('is true when the auth claim that signed the credential is revoked', async () => {
      expect(await isRevokedByIssuerAuthClaim(credentialWallet, signedWithRevokedKey)).to.equal(
        true
      );
    });

    it('is false when the auth claim that signed the credential is not revoked', async () => {
      expect(await isRevokedByIssuerAuthClaim(credentialWallet, signedWithValidKey)).to.equal(
        false
      );
    });

    it('is false by default when the credential also has an MTP proof', async () => {
      expect(
        await isRevokedByIssuerAuthClaim(credentialWallet, signedWithRevokedKeyAndMtp)
      ).to.equal(false);
    });

    it('checks the signature despite an MTP proof when the signature is required', async () => {
      expect(
        await isRevokedByIssuerAuthClaim(credentialWallet, signedWithRevokedKeyAndMtp, {
          proofType: SIG
        })
      ).to.equal(true);
    });

    it('ignores the signature when the MTP is required', async () => {
      expect(
        await isRevokedByIssuerAuthClaim(credentialWallet, signedWithRevokedKey, {
          proofType: MTP
        })
      ).to.equal(false);
    });
  });

  describe('ProofService.findCredentialByProofQuery', () => {
    it('skips credentials signed with a revoked issuer auth claim', async () => {
      const proofService = newProofService([signedWithRevokedKey, signedWithValidKey]);
      const { cred, revStatus, issuerAuthRevStatus } =
        await proofService.findCredentialByProofQuery(did, {});
      expect(cred.id).to.equal(signedWithValidKey.id);
      expect(revStatus?.mtp.existence).to.equal(false);
      // returned for the found credential, to be reused as its issuer auth non-revocation proof
      expect(issuerAuthRevStatus?.mtp.existence).to.equal(false);
    });

    it('fails with the issuer-auth-claim error when only such credentials are left', async () => {
      const proofService = newProofService([signedWithRevokedKey]);
      await expect(proofService.findCredentialByProofQuery(did, {})).rejects.toThrow(
        AUTH_CLAIM_REVOKED
      );
    });

    it('keeps credentials with an MTP proof by default', async () => {
      const proofService = newProofService([signedWithRevokedKeyAndMtp]);
      const { cred, issuerAuthRevStatus } = await proofService.findCredentialByProofQuery(did, {});
      expect(cred.id).to.equal(signedWithRevokedKeyAndMtp.id);
      expect(issuerAuthRevStatus).to.equal(undefined);
    });

    it('still skips credentials revoked by their own nonce', async () => {
      const proofService = newProofService([signedWithRevokedKey, revokedByOwnNonce]);
      await expect(proofService.findCredentialByProofQuery(did, {})).rejects.toThrow(ALL_REVOKED);
    });

    it('requires a signature with a valid key when the signature is required', async () => {
      const proofService = newProofService([
        mtpOnly,
        signedWithRevokedKeyAndMtp,
        signedWithValidKey
      ]);
      const { cred } = await proofService.findCredentialByProofQuery(did, {}, { proofType: SIG });
      expect(cred.id).to.equal(signedWithValidKey.id);
    });

    it('requires an MTP proof and ignores the signature when the MTP is required', async () => {
      const proofService = newProofService([signedWithValidKey, signedWithRevokedKeyAndMtp]);
      const { cred } = await proofService.findCredentialByProofQuery(did, {}, { proofType: MTP });
      expect(cred.id).to.equal(signedWithRevokedKeyAndMtp.id);
    });

    it('fails with credential-not-found when no credential has the required proof', async () => {
      const proofService = newProofService([signedWithValidKey]);
      await expect(
        proofService.findCredentialByProofQuery(did, {}, { proofType: MTP })
      ).rejects.toThrow(NO_CREDENTIAL_FOR_QUERY);
    });

    describe('with skipClaimRevocationCheck', () => {
      const query: ProofQuery = { skipClaimRevocationCheck: true };

      it('skips credentials signed with a revoked issuer auth claim', async () => {
        const proofService = newProofService([signedWithRevokedKey, revokedByOwnNonce]);
        const { cred, revStatus, issuerAuthRevStatus } =
          await proofService.findCredentialByProofQuery(did, query);
        // the credential's own revocation is not checked, the issuer auth claim always is
        expect(cred.id).to.equal(revokedByOwnNonce.id);
        expect(revStatus).to.equal(undefined);
        expect(issuerAuthRevStatus?.mtp.existence).to.equal(false);
      });

      it('applies the strict rule when the signature is required', async () => {
        const proofService = newProofService([signedWithRevokedKeyAndMtp, signedWithValidKey]);
        const { cred } = await proofService.findCredentialByProofQuery(did, query, {
          proofType: SIG
        });
        expect(cred.id).to.equal(signedWithValidKey.id);
      });

      it('fails with the issuer-auth-claim error when only such credentials are left', async () => {
        const proofService = newProofService([signedWithRevokedKey]);
        await expect(proofService.findCredentialByProofQuery(did, query)).rejects.toThrow(
          AUTH_CLAIM_REVOKED
        );
      });
    });
  });

  describe('required proof type is passed to credential selection', () => {
    it('by ProofService.generateProof, from the circuit', async () => {
      const proofService = newProofService([]);
      const findSpy = vi
        .spyOn(proofService, 'findCredentialByProofQuery')
        .mockRejectedValue(new Error('stop'));
      const query = { allowedIssuers: ['*'], context: 'ctx', type: 'operators' };

      await expect(
        proofService.generateProof({ id: 1, circuitId: CircuitId.AtomicQuerySigV2, query }, did)
      ).rejects.toThrow('stop');

      expect(findSpy).toHaveBeenCalledWith(did, query, { proofType: SIG });
    });

    it('by processZeroKnowledgeProofRequests, from any request of a linked group', async () => {
      const issuerAuthRevStatus = nonRevokedStatus();
      const findCredentialByProofQuery = vi
        .fn()
        .mockResolvedValue({ cred: signedWithValidKey, revStatus: undefined, issuerAuthRevStatus });
      const generateProof = vi.fn(async (req: ZeroKnowledgeProofRequest) => ({
        id: req.id,
        circuitId: req.circuitId,
        proof: {},
        pub_signals: []
      }));
      const proofService = {
        findCredentialByProofQuery,
        generateProof
      } as unknown as IProofService;
      const base = { allowedIssuers: ['*'], context: 'ctx', type: 'operators', groupId: 7 };

      await processZeroKnowledgeProofRequests(
        did,
        [
          { id: 1, circuitId: CircuitId.LinkedMultiQuery10, query: base },
          { id: 2, circuitId: CircuitId.AtomicQueryV3, query: { ...base, proofType: SIG } }
        ],
        undefined,
        proofService,
        { supportedCircuits: [CircuitId.LinkedMultiQuery10, CircuitId.AtomicQueryV3] }
      );

      expect(findCredentialByProofQuery).toHaveBeenCalledTimes(1);
      expect(findCredentialByProofQuery.mock.calls[0][2]).to.deep.equal({ proofType: SIG });
      // the issuer auth claim status found with the credential is reused for every proof
      expect(generateProof).toHaveBeenCalledTimes(2);
      for (const [, , opts] of generateProof.mock.calls as unknown as [
        unknown,
        unknown,
        { issuerAuthRevocationStatus?: RevocationStatus }
      ][]) {
        expect(opts.issuerAuthRevocationStatus).to.equal(issuerAuthRevStatus);
      }
    });
  });

  describe('issuer auth claim status is resolved once', () => {
    // self-contained context, so the query is parsed without network
    const ldContext = {
      '@context': {
        '@version': 1.1,
        '@protected': true,
        id: '@id',
        type: '@type',
        operators: {
          '@id': 'urn:uuid:operators',
          '@context': {
            '@version': 1.1,
            '@protected': true,
            id: '@id',
            type: '@type',
            field: { '@id': 'urn:uuid:field', '@type': 'http://www.w3.org/2001/XMLSchema#string' }
          }
        }
      }
    };

    it('from credential selection to proof inputs in ProofService.generateProof', async () => {
      const resolver = new StubResolver();
      const credential = buildCredential({ id: 'resolved-once', proofs: [SIG] });
      vi.spyOn(credential, 'merklize').mockResolvedValue({} as never);
      const proofService = newProofService([credential], newCredentialWallet(resolver));

      // stop at proof inputs, after building the claim data the circuit gets
      const internals = proofService as unknown as {
        loadLdContext: () => Promise<Uint8Array>;
        toCircuitsQuery: () => Promise<Query>;
        generateInputs: (preparedCredential: PreparedCredential) => Promise<never>;
        _inputsGenerator: InputGenerator;
      };
      vi.spyOn(internals, 'loadLdContext').mockResolvedValue(
        new TextEncoder().encode(JSON.stringify(ldContext))
      );
      vi.spyOn(internals, 'toCircuitsQuery').mockResolvedValue(new Query());
      let circuitClaim: CircuitClaim | undefined;
      vi.spyOn(internals, 'generateInputs').mockImplementation(async (preparedCredential) => {
        circuitClaim = await internals._inputsGenerator.newCircuitClaimData(preparedCredential);
        throw new Error('stop');
      });

      const query = {
        allowedIssuers: ['*'],
        context: 'ctx',
        type: 'operators',
        credentialSubject: { field: {} }
      };
      const subject = DID.parse(credential.credentialSubject['id'] as string);
      await expect(
        proofService.generateProof({ id: 1, circuitId: CircuitId.AtomicQuerySigV2, query }, subject)
      ).rejects.toThrow('stop');

      expect(resolver.calls.filter((id) => id === VALID_KEY_STATUS)).to.have.length(1);
      expect(circuitClaim?.signatureProof?.issuerAuthNonRevProof.proof?.existence).to.equal(false);
    });
  });

  describe('InputGenerator', () => {
    const inputGenerator = new InputGenerator(
      {} as IIdentityWallet,
      newCredentialWallet(),
      {} as IStateStorage
    );
    const generateInputs = (
      credential: W3CCredential,
      circuitId: CircuitId,
      query: ProofQuery = {}
    ) =>
      inputGenerator.generateInputs({
        preparedCredential: {
          credential,
          credentialCoreClaim: credential.getCoreClaimFromProof(SIG),
          revStatus: { mtp: new Proof(), issuer: {} }
        },
        identifier: did,
        proofReq: { id: 1, circuitId, query },
        params: { authProfileNonce: 0, credentialSubjectProfileNonce: 0 },
        circuitQueries: []
      } as never);

    it('rejects a revoked signing key when the circuit uses the signature', async () => {
      await expect(
        generateInputs(signedWithRevokedKeyAndMtp, CircuitId.AtomicQuerySigV2)
      ).rejects.toThrow(AUTH_CLAIM_REVOKED);
      await expect(
        generateInputs(signedWithRevokedKeyAndMtp, CircuitId.AtomicQueryV3, { proofType: SIG })
      ).rejects.toThrow(AUTH_CLAIM_REVOKED);
      await expect(generateInputs(signedWithRevokedKey, CircuitId.AtomicQueryV3)).rejects.toThrow(
        AUTH_CLAIM_REVOKED
      );
    });

    it('uses the passed issuer auth claim status instead of resolving it again', async () => {
      const resolver = new StubResolver();
      const generator = new InputGenerator(
        {} as IIdentityWallet,
        newCredentialWallet(resolver),
        {} as IStateStorage
      );
      const issuerAuthRevStatus = nonRevokedStatus();
      const circuitClaim = await generator.newCircuitClaimData({
        credential: signedWithRevokedKey,
        credentialCoreClaim: signedWithRevokedKey.getCoreClaimFromProof(SIG),
        issuerAuthRevStatus
      } as PreparedCredential);
      expect(resolver.calls).to.deep.equal([]);
      expect(circuitClaim.signatureProof?.issuerAuthNonRevProof.proof).to.equal(
        issuerAuthRevStatus.mtp
      );
    });

    it('resolves the issuer auth claim status when it is not passed', async () => {
      const resolver = new StubResolver();
      const generator = new InputGenerator(
        {} as IIdentityWallet,
        newCredentialWallet(resolver),
        {} as IStateStorage
      );
      await generator.newCircuitClaimData({
        credential: signedWithRevokedKey,
        credentialCoreClaim: signedWithRevokedKey.getCoreClaimFromProof(SIG)
      } as PreparedCredential);
      expect(resolver.calls).to.deep.equal([REVOKED_KEY_STATUS]);
    });

    it('does not reject it when the circuit uses the MTP', async () => {
      // inputs generation fails later on the incomplete test data, but not on the signing key
      const error = await generateInputs(signedWithRevokedKeyAndMtp, CircuitId.AtomicQueryV3).then(
        () => undefined,
        (e: Error) => e
      );
      expect(error?.message).not.to.equal(AUTH_CLAIM_REVOKED);
    });
  });
});
