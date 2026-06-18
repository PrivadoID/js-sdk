/**
 * Regression test for the BJJSignature2021 credential-forgery fix.
 *
 * Before the fix, verifyBJJSignatureProof trusted the public key embedded in
 * proof.issuerData.authCoreClaim and only checked that proof.issuerData.state.value
 * was published on-chain — it never verified that the auth claim is actually included
 * in that state's claimsTreeRoot (proof.issuerData.mtp was parsed but unused). That let
 * an attacker put their own key in authCoreClaim, sign with it, and forge a credential
 * from any issuer DID.
 *
 * The fix binds the signing key to the published state:
 *   1) state.value === poseidon(claimsTreeRoot, revocationTreeRoot, rootOfRoots), and
 *   2) rootFromProof(issuerData.mtp, hiAuth, hvAuth) === state.claimsTreeRoot.
 *
 * This test takes a genuine credential, swaps the issuer auth key for an attacker key,
 * re-signs, and asserts verifyProof now REJECTS it at the auth-claim inclusion check.
 */
import { AgentResolver, CredentialStatusResolverRegistry } from '../../src/credentials';
import {
  W3CCredential,
  CredentialStatusType,
  ProofType,
  BJJSignatureProof2021,
  W3CProofVerificationOptions
} from '../../src/verifiable';
import { PrivateKey, poseidon, getRandomBytes, PublicKey } from '@iden3/js-crypto';
import { Claim, ClaimOptions, SchemaHash } from '@iden3/js-iden3-core';
import { describe, expect, it, afterEach } from 'vitest';
import nock from 'nock';
import { IPFS_URL } from '../helpers';
import { schemaLoaderForTests } from '../mocks/schema';

const merklizeOpts = {
  documentLoader: schemaLoaderForTests({ ipfsNodeURL: IPFS_URL })
};

const RESOLVER_URL = 'http://my-universal-resolver/1.0/identifiers';

// A genuine, legitimately-issued BJJSignature2021 credential (the fixture from the
// SDK's "Validate BJJ signature proof agent status" test). Issuer DID and state are
// real; the DID resolver and the agent revocation endpoint are mocked below.
const BASE_CREDENTIAL = {
  id: 'urn:uuid:79d93584-ae2c-11ee-8050-a27b3ddbdc28',
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://schema.iden3.io/core/jsonld/iden3proofs.jsonld',
    'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld'
  ],
  type: ['VerifiableCredential', 'KYCAgeCredential'],
  expirationDate: '2361-03-21T21:14:48+02:00',
  issuanceDate: '2024-01-08T15:47:34.113565+02:00',
  credentialSubject: {
    birthday: 19960424,
    documentType: 2,
    id: 'did:polygonid:polygon:mumbai:2qFDziX3k3h7To2jDJbQiXFtcozbgSNNvQpb6TgtPE',
    type: 'KYCAgeCredential'
  },
  credentialStatus: {
    id: 'http://localhost:8001/api/v1/agent',
    revocationNonce: 3262660310,
    type: 'Iden3commRevocationStatusV1.0'
  },
  issuer: 'did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ',
  credentialSchema: {
    id: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json',
    type: 'JsonSchema2023'
  },
  proof: [
    {
      type: 'BJJSignature2021',
      issuerData: {
        id: 'did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ',
        state: {
          claimsTreeRoot: 'b35562873d9870f20e3d44dd94502f4156785a4b09d7906914758a7e0ed26829',
          value: '2de39210318bbc7fc79e24150c2790089c8385d7acffc0f0ebf1641b95087e0f'
        },
        authCoreClaim:
          'cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000167c1d2857ca6579d6e995198876cdfd4edb4fe2eeedeadbabaaed3008225205e7b8ab88a60b9ef0999be82625e0831872d8aca16b2932852c3731e9df69970a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        mtp: { existence: true, siblings: [] },
        credentialStatus: {
          id: 'http://localhost:8001/api/v1/agent',
          revocationNonce: 0,
          type: 'Iden3commRevocationStatusV1.0'
        }
      },
      coreClaim:
        'c9b2370371b7fa8b3dab2a5ba81b68382a00000000000000000000000000000002123cbcd9d0f3a493561510c72b47afcb02e2f09b3855291c6b77d224260d0014f503c3ab03eebe757d5b50b570186a69d90c49904155f5fc71e0e7f5b8aa120000000000000000000000000000000000000000000000000000000000000000d63e78c200000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      signature:
        '56ab45ad828c4860d02e111b2732c969005046ee26dbc7d1e5bd6a6c6604ed81c3f55ffb9349f4d407f59e2e210f6d256a328d30edae2c7c95dd057240ee8902'
    }
  ]
};

function mockIssuerResolver() {
  nock('http://my-universal-resolver')
    .get(
      '/1.0/identifiers/did%3Apolygonid%3Apolygon%3Amumbai%3A2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ?state=2de39210318bbc7fc79e24150c2790089c8385d7acffc0f0ebf1641b95087e0f'
    )
    .reply(
      200,
      '{"didDocument":{"@context":["https://www.w3.org/ns/did/v1","https://schema.iden3.io/core/jsonld/auth.jsonld"],"id":"did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ","verificationMethod":[{"id":"did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ#stateInfo","type":"Iden3StateInfo2023","controller":"did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ","stateContractAddress":"80001:0x134B1BE34911E39A8397ec6289782989729807a4","published":false,"global":{"root":"ff3e987dc4c279af0e77ac2b1983ed8cf627bfeebbc6d5d56be2526cc7286621","replacedByRoot":"0000000000000000000000000000000000000000000000000000000000000000","createdAtTimestamp":"1704719148","replacedAtTimestamp":"0","createdAtBlock":"44541667","replacedAtBlock":"0"}}]}}'
    );
  // Attacker-controlled revocation endpoint (would answer "not revoked"). Not reached:
  // verification fails at the auth-claim inclusion check before the revocation resolve.
  nock('http://localhost:8001')
    .post('/api/v1/agent')
    .reply(
      200,
      '{"body":{"issuer":{"claimsTreeRoot":"d9597e2fef206c9821f2425e513a68c8c793bc93c9216fb883fedaaf72abf51c","revocationTreeRoot":"0000000000000000000000000000000000000000000000000000000000000000","rootOfRoots":"eaa48e4a7d3fe2fabbd939c7df1048c3f647a9a7c9dfadaae836ec78ba673229","state":"96161f3fbbdd68c72bc430dae474e27b157586b33b9fbf4a3f07d75ce275570f"},"mtp":{"existence":false,"siblings":[]},"from":"did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ","to":"did:polygonid:polygon:mumbai:2qFDziX3k3h7To2jDJbQiXFtcozbgSNNvQpb6TgtPE","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/revocation/1.0/status"}'
    );
}

describe('BJJ signature proof forgery is rejected (auth key must be in issuer claims tree)', () => {
  afterEach(() => nock.cleanAll());

  it('rejects a credential re-signed by a key that is not in the issuer claims tree', async () => {
    const credential = W3CCredential.fromJSON(structuredClone(BASE_CREDENTIAL));
    const proof = (credential.proof as BJJSignatureProof2021[])[0];

    const originalSlots = proof.issuerData.authCoreClaim.rawSlotsAsInts();
    const originalPubKey = new PublicKey([originalSlots[2], originalSlots[3]]);

    // Attacker generates their own key, embeds it in a forged auth claim, and re-signs
    // the (unchanged) core claim with it. revNonce kept at 0 to match credentialStatus.
    const attackerSk = new PrivateKey(getRandomBytes(32));
    const attackerPub = attackerSk.public();
    expect(attackerPub.hex()).not.to.eq(originalPubKey.hex());

    const forgedAuthClaim = Claim.newClaim(
      SchemaHash.authSchemaHash,
      ClaimOptions.withIndexDataInts(attackerPub.p[0], attackerPub.p[1]),
      ClaimOptions.withRevocationNonce(BigInt(0))
    );

    const { hi, hv } = proof.coreClaim.hiHv();
    const forgedSignature = attackerSk.signPoseidon(poseidon.hash([hi, hv]));

    proof.issuerData.authCoreClaim = forgedAuthClaim;
    proof.signature = forgedSignature;

    mockIssuerResolver();

    const credStatusResolverRegistry = new CredentialStatusResolverRegistry();
    credStatusResolverRegistry.register(
      CredentialStatusType.Iden3commRevocationStatusV1,
      new AgentResolver()
    );
    const opts: W3CProofVerificationOptions = {
      credStatusResolverRegistry,
      merklizeOptions: merklizeOpts
    };

    // The forged credential's BJJ signature is valid under the attacker key, but that
    // key is not part of the issuer's published claims tree, so verification must fail.
    await expect(
      credential.verifyProof(ProofType.BJJSignature, RESOLVER_URL, opts)
    ).rejects.toThrow('issuer auth claim is not included in the issuer claims tree root');
  });
});
