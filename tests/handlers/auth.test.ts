/* eslint-disable no-console */

import path from 'path';
import {
  IDataStorage,
  CredentialRequest,
  CredentialWallet,
  ProofService,
  CircuitId,
  AuthHandler,
  EthStateStorage,
  FSCircuitStorage,
  IAuthHandler,
  IdentityWallet,
  byteEncoder,
  CredentialStatusType,
  AuthorizationRequestMessage,
  AuthorizationRequestMessageBody,
  IPackageManager,
  ZeroKnowledgeProofRequest,
  RHSResolver,
  CredentialStatusResolverRegistry,
  PROTOCOL_CONSTANTS,
  createAuthorizationRequestWithMessage,
  AuthorizationResponseMessage,
  ZeroKnowledgeProofResponse,
  ProofType,
  KmsKeyType,
  defaultEthConnectionConfig,
  InMemoryPrivateKeyStore,
  BjjProvider,
  KMS,
  CredentialStorage,
  InMemoryDataSource,
  IdentityStorage,
  Identity,
  Profile,
  InMemoryMerkleTreeStorage,
  W3CCredential,
  Sec256k1Provider,
  StateInfo,
  hexToBytes,
  NativeProver,
  VerifiableConstants,
  buildAccept,
  AcceptProfile,
  createAuthorizationRequest,
  createInMemoryCache,
  DEFAULT_CACHE_MAX_SIZE,
  RootInfo,
  InMemoryProofStorage,
  byteDecoder,
  getChallengeFromEthAddress
} from '../../src';
import {
  Blockchain,
  DID,
  DidMethod,
  getDateFromUnixTimestamp,
  NetworkId
} from '@iden3/js-iden3-core';
import { ProvingMethodAlg, Token, proving } from '@iden3/js-jwz';
import { describe, expect, it, beforeEach } from 'vitest';
import { ethers } from 'ethers';
import * as uuid from 'uuid';
import {
  getInMemoryDataStorage,
  registerKeyProvidersInMemoryKMS,
  IPFS_URL,
  getPackageMgr,
  createIdentity,
  SEED_USER,
  RHS_URL,
  WALLET_KEY,
  STATE_CONTRACT,
  RPC_URL,
  SEED_ISSUER,
  TEST_VERIFICATION_OPTS,
  MOCK_STATE_STORAGE,
  getPackageMgrV3,
  getPackageManagerWithDefaultZKPPacker
} from '../helpers';
import { getRandomBytes } from '@iden3/js-crypto';
import {
  AcceptAuthCircuits,
  AcceptJweKEKAlgorithms,
  CEKEncryption,
  defaultAcceptProfile,
  MediaType,
  ProtocolVersion
} from '../../src/iden3comm/constants';
import { schemaLoaderForTests } from '../mocks/schema';
import { Options } from '@iden3/js-jsonld-merklization';

describe('auth', () => {
  let idWallet: IdentityWallet;
  let credWallet: CredentialWallet;

  let dataStorage: IDataStorage;
  let proofService: ProofService;
  let authHandler: IAuthHandler;
  let packageMgr: IPackageManager;

  let userDID: DID;
  let issuerDID: DID;
  let circuitStorage: FSCircuitStorage;

  let merklizeOpts: Options;
  beforeEach(async () => {
    const kms = registerKeyProvidersInMemoryKMS();
    dataStorage = getInMemoryDataStorage(MOCK_STATE_STORAGE);
    circuitStorage = new FSCircuitStorage({
      dirname: path.join(__dirname, '../proofs/testdata')
    });

    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );
    credWallet = new CredentialWallet(dataStorage, resolvers);
    idWallet = new IdentityWallet(kms, dataStorage, credWallet);

    merklizeOpts = {
      documentLoader: schemaLoaderForTests({
        ipfsNodeURL: IPFS_URL
      })
    };

    proofService = new ProofService(
      idWallet,
      credWallet,
      circuitStorage,
      MOCK_STATE_STORAGE,
      merklizeOpts
    );

    packageMgr = await getPackageMgr(
      await circuitStorage.loadCircuitData(CircuitId.AuthV2),
      proofService.generateAuthInputs.bind(proofService),
      proofService.verifyState.bind(proofService)
    );

    authHandler = new AuthHandler(packageMgr, proofService);

    const { did: didUser, credential: userAuthCredential } = await createIdentity(idWallet, {
      seed: SEED_USER
    });
    userDID = didUser;

    expect(userAuthCredential).not.to.be.undefined;

    const { did: didIssuer, credential: issuerAuthCredential } = await createIdentity(idWallet);
    expect(issuerAuthCredential).not.to.be.undefined;
    issuerDID = didIssuer;
  });

  it('request-response flow identity (not profile)', async () => {
    const claimReq: CredentialRequest = {
      credentialSchema: 'ipfs://QmWDmZQrtvidcNK7d6rJwq7ZSi8SUygJaKepN7NhKtGryc',
      type: 'operators',
      credentialSubject: {
        id: userDID.string(),
        boolean1: true,
        'date-time1': '2024-11-04T12:39:00Z',
        integer1: 4321,
        'non-negative-integer1': '654321',
        number1: 1234,
        'positive-integer1': '123456789',
        string1: 'abcd'
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);

    await credWallet.save(issuerCred);
    const proofReq: ZeroKnowledgeProofRequest = {
      id: 1730736196,
      circuitId: CircuitId.AtomicQueryV3Stable,
      optional: false,
      query: {
        allowedIssuers: ['*'],
        context: 'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15',
        credentialSubject: {
          'positive-integer1': {
            $between: ['123456789', '1123456789']
          }
        },
        type: 'operators'
      }
    };

    const proofForNonExistingCondition: ZeroKnowledgeProofRequest = {
      id: 1730736198,
      circuitId: CircuitId.AtomicQueryV3Stable,
      optional: true,
      query: {
        allowedIssuers: ['*'],
        context: 'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15',
        credentialSubject: {
          string1: {
            $eq: 'non-existing-string-value'
          }
        },
        type: 'operators'
      }
    };
    const proofForNonExistingConditionWithGroupId: ZeroKnowledgeProofRequest = {
      id: 1730736199,
      circuitId: CircuitId.AtomicQueryV3Stable,
      optional: true,
      query: {
        allowedIssuers: ['*'],
        groupId: 1,
        context: 'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15',
        credentialSubject: {
          string1: {
            $eq: 'non-existing-string-value-2'
          }
        },
        type: 'operators'
      }
    };

    const profile: AcceptProfile = {
      protocolVersion: ProtocolVersion.V1,
      env: MediaType.ZKPMessage,
      circuits: [AcceptAuthCircuits.AuthV2]
    };

    const authReq = createAuthorizationRequest(
      'reason',
      issuerDID.string(),
      'http://localhost:8080/callback?id=1234442-123123-123123',
      {
        scope: [proofReq, proofForNonExistingCondition, proofForNonExistingConditionWithGroupId],
        accept: buildAccept([profile])
      }
    );

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);

    expect(authRes.authResponse.body.scope[0].circuitId).to.equal(
      'credentialAtomicQueryV3-16-16-64'
    );

    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const tokenBytes = byteEncoder.encode(tokenStr);

    const result = await packageMgr.unpack(tokenBytes);

    expect(JSON.stringify(result.unpackedMessage)).to.equal(JSON.stringify(authRes.authResponse));

    const authResEncrypted = await authHandler.handleAuthorizationRequest(userDID, msgBytes, {
      mediaType: MediaType.EncryptedMessage,
      packerOptions: {
        enc: CEKEncryption.A256GCM,
        recipients: [
          {
            alg: AcceptJweKEKAlgorithms.RSA_OAEP_256,
            did: DID.parse('did:iden3:billions:main:2VnNCwMe2hxUAU5sLqsaCYXJr4a6wkHZXeTM8iBhc2'),
            didDocument: {
              '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/jws-2020/v1'
              ],
              id: 'did:iden3:billions:main:2VnNCwMe2hxUAU5sLqsaCYXJr4a6wkHZXeTM8iBhc2',
              keyAgreement: [
                'did:iden3:billions:main:2VnNCwMe2hxUAU5sLqsaCYXJr4a6wkHZXeTM8iBhc2#RSA-OAEP-256:0xfd49a959865e7740f600fc3af4b670a8d107e0f80214ac03c58e416f1cdf6864'
              ],
              verificationMethod: [
                {
                  controller: 'did:iden3:billions:main:2VnNCwMe2hxUAU5sLqsaCYXJr4a6wkHZXeTM8iBhc2',
                  id: 'did:iden3:billions:main:2VnNCwMe2hxUAU5sLqsaCYXJr4a6wkHZXeTM8iBhc2#RSA-OAEP-256:0xfd49a959865e7740f600fc3af4b670a8d107e0f80214ac03c58e416f1cdf6864',
                  publicKeyJwk: {
                    alg: 'RSA-OAEP-256',
                    // eslint-disable-next-line @cspell/spellchecker
                    e: 'AQAB',
                    ext: true,
                    kty: 'RSA',
                    n: 'ngY1zZibNQUYVrPfhYxiw5gbM1-zMucYPxYAoAmd6F3A0T-VBiwnTpoHYAYpu5iZCz_l4mchj2H2sN8R4wy-jF3lTimp08E7FM-GRkCOAK_Bf3-2X11efV_WShGbfU0toCJlAQhHHobwb4Vkgy2wAxvjA5R6yZLerpsoRmHm6GeUq4bUza-sDMYvw_-SwAbWMkg9vW8AACa70XwcENga2L1ST1y0pJFIqTo91kD0qY8zJrpwbm3DbohnHpHA6MWh2T4pxvMrEyzZFs69ZK8lkea4eV_H1dgholMWQ67HAXL1rg86Lc2ruCKG-oK-x-HloqsWsyhNgLeMrANfMwkU2w'
                  },
                  type: 'JsonWebKey2020'
                }
              ]
            }
          }
        ]
      }
    });
    expect(authResEncrypted.token).to.be.a('string');
  });

  it('request-response flow profiles', async () => {
    // assume that we authorized to the issuer with profile did
    const profileDID = await idWallet.createProfile(userDID, 50, issuerDID.string());

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: profileDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);

    await credWallet.save(issuerCred);

    const proofReq: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQuerySigV2,
      optional: false,
      query: {
        allowedIssuers: ['*'],
        type: claimReq.type,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
        credentialSubject: {
          documentType: {
            $eq: 99
          }
        }
      }
    };

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      accept: buildAccept([defaultAcceptProfile]),
      scope: [proofReq as ZeroKnowledgeProofRequest]
    };

    const verifierDID = 'did:example:123#JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw';
    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: verifierDID
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));

    // you can create new profile here for auth or if you want to login with genesis set to 0.

    const authR = await authHandler.parseAuthorizationRequest(msgBytes);

    // let's check that we didn't create profile for verifier
    const authProfiles = await idWallet.getProfilesByVerifier(authR.from);
    const authProfileDID = authProfiles.length
      ? DID.parse(authProfiles[0].id)
      : await idWallet.createProfile(userDID, 100, authR.from);

    const resp = await authHandler.handleAuthorizationRequest(authProfileDID, msgBytes);
    expect(resp).not.to.be.undefined;
  });

  it('auth flow identity (profile) with circuits V3', async () => {
    const profileDID = await idWallet.createProfile(userDID, 777, issuerDID.string());

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);
    const employeeCredRequest: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCEmployee-v101.json',
      type: 'KYCEmployee',
      credentialSubject: {
        id: profileDID.string(),
        ZKPexperiance: true,
        hireDate: '2023-12-11',
        position: 'boss',
        salary: 200,
        documentType: 1
      },
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const employeeCred = await idWallet.issueCredential(
      issuerDID,
      employeeCredRequest,
      merklizeOpts
    );

    await credWallet.saveAll([employeeCred, issuerCred]);

    const res = await idWallet.addCredentialsToMerkleTree([employeeCred], issuerDID);
    await idWallet.publishStateToRHS(issuerDID, RHS_URL);

    const ethSigner = new ethers.Wallet(WALLET_KEY, dataStorage.states.getRpcProvider());

    const txId = await proofService.transitState(
      issuerDID,
      res.oldTreeState,
      true,
      dataStorage.states,
      ethSigner
    );

    const credsWithIden3MTPProof = await idWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

    await credWallet.saveAll(credsWithIden3MTPProof);

    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.AtomicQueryV3Stable,
        optional: false,
        query: {
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCAgeCredential',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
          credentialSubject: {
            documentType: {
              $eq: 99
            }
          }
        }
      },
      {
        id: 2,
        circuitId: CircuitId.LinkedMultiQueryStable,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.Iden3SparseMerkleTreeProof,
          allowedIssuers: ['*'],
          type: 'KYCEmployee',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            documentType: {
              $eq: 1
            },
            position: {
              $eq: 'boss',
              $ne: 'employee'
            }
          }
        }
      },
      {
        id: 3,
        circuitId: CircuitId.AtomicQueryV3Stable,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCEmployee',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            hireDate: {
              $eq: '2023-12-11'
            }
          }
        },
        params: {
          nullifierSessionId: '12345'
        }
      }
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: proofReqs
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const token = await Token.parse(tokenStr);
    expect(token).to.be.a('object');

    const { response } = await authHandler.handleAuthorizationResponse(
      authRes.authResponse,
      authReq
    );
    expect(response).to.be.a('object');

    expect(response.body.scope).to.have.lengthOf(3);
    const circuits = response.body.scope.map((c) => c.circuitId);
    expect(circuits).toContain('credentialAtomicQueryV3-16-16-64');
    expect(circuits).toContain('linkedMultiQuery3');
  });

  it('auth flow identity (profile) with circuits V3 and caching', async () => {
    proofService = new ProofService(idWallet, credWallet, circuitStorage, MOCK_STATE_STORAGE, {
      ...merklizeOpts,
      proofsCacheStorage: new InMemoryProofStorage()
    });
    authHandler = new AuthHandler(packageMgr, proofService);

    const profileDID = await idWallet.createProfile(userDID, 777, issuerDID.string());

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const ageCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);
    await credWallet.save(ageCred);
    // all optional, currently have only KYCAgeCredential credential
    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.AtomicQueryV3,
        optional: true,
        query: {
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCAgeCredential',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
          credentialSubject: {
            documentType: {
              $eq: 99
            }
          }
        }
      },
      {
        id: 2,
        circuitId: CircuitId.AtomicQueryV3,
        optional: true,
        query: {
          groupId: 1,
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCEmployee',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            hireDate: {
              $eq: '2023-12-11'
            }
          }
        },
        params: {
          nullifierSessionId: '12345'
        }
      }
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: proofReqs
    };

    const authReq: AuthorizationRequestMessage = {
      id: uuid.v4(),
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: uuid.v4(),
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    // handle and cache KYCAgeCredential, skip others (all optional)
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
    expect(authRes.authResponse.body.scope).to.have.lengthOf(1);
    const generatedKYCAgeCredential = authRes.authResponse.body.scope[0];
    expect(generatedKYCAgeCredential).to.not.be.undefined;

    // issue KYCEmployee credential
    const employeeCredRequest: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCEmployee-v101.json',
      type: 'KYCEmployee',
      credentialSubject: {
        id: profileDID.string(),
        ZKPexperiance: true,
        hireDate: '2023-12-11',
        position: 'boss',
        salary: 200,
        documentType: 1
      },
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const employeeCred = await idWallet.issueCredential(
      issuerDID,
      employeeCredRequest,
      merklizeOpts
    );

    await credWallet.save(employeeCred);

    // now all proofs should be returned, one from cache, two generated
    const authResWithCached = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
    expect(authResWithCached.authResponse.body.scope).to.have.lengthOf(2);
    const cachedKYCAgeCredential = authResWithCached.authResponse.body.scope.find(
      (pr) => pr.id === 1
    );
    expect(cachedKYCAgeCredential).to.not.be.undefined;
    const timestampPubSignalIndex = 11;
    expect(generatedKYCAgeCredential.pub_signals[timestampPubSignalIndex]).to.equal(
      cachedKYCAgeCredential?.pub_signals[timestampPubSignalIndex]
    );

    // bypass cache and generate all new proofs
    const authResWithoutCache = await authHandler.handleAuthorizationRequest(userDID, msgBytes, {
      mediaType: MediaType.ZKPMessage,
      bypassProofsCache: true
    });
    expect(authResWithoutCache.authResponse.body.scope).to.have.lengthOf(2);
    const bypassCacheKYCAgeCredential = authResWithoutCache.authResponse.body.scope.find(
      (pr) => pr.id === 1
    );
    expect(bypassCacheKYCAgeCredential).to.not.be.undefined;
    expect(cachedKYCAgeCredential?.pub_signals[timestampPubSignalIndex]).to.not.equal(
      bypassCacheKYCAgeCredential?.pub_signals[timestampPubSignalIndex]
    );
  });

  it('auth flow identity (profile) with ethereum identity issuer with circuits V3', async () => {
    const ethSigner = new ethers.Wallet(WALLET_KEY, dataStorage.states.getRpcProvider());

    const { did: didIssuer, credential: issuerAuthCredential } =
      await idWallet.createEthereumBasedIdentity({
        method: DidMethod.PolygonId,
        blockchain: Blockchain.Polygon,
        networkId: NetworkId.Mumbai,
        seed: SEED_ISSUER,
        revocationOpts: {
          type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
          id: RHS_URL
        },
        ethSigner
      });
    expect(issuerAuthCredential).not.to.be.undefined;

    const profileDID = await idWallet.createProfile(userDID, 777, didIssuer.string());

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(didIssuer, claimReq, merklizeOpts);
    const employeeCredRequest: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCEmployee-v101.json',
      type: 'KYCEmployee',
      credentialSubject: {
        id: profileDID.string(),
        ZKPexperiance: true,
        hireDate: '2023-12-11',
        position: 'boss',
        salary: 200,
        documentType: 1
      },
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const employeeCred = await idWallet.issueCredential(
      didIssuer,
      employeeCredRequest,
      merklizeOpts
    );

    await credWallet.saveAll([employeeCred, issuerCred]);

    const res = await idWallet.addCredentialsToMerkleTree([employeeCred], didIssuer);
    await idWallet.publishStateToRHS(didIssuer, RHS_URL);

    const txId = await proofService.transitState(
      didIssuer,
      res.oldTreeState,
      true,
      dataStorage.states,
      ethSigner
    );

    const credsWithIden3MTPProof = await idWallet.generateIden3SparseMerkleTreeProof(
      didIssuer,
      res.credentials,
      txId
    );

    await credWallet.saveAll(credsWithIden3MTPProof);

    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.AtomicQueryV3,
        optional: false,
        query: {
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCAgeCredential',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
          credentialSubject: {
            documentType: {
              $eq: 99
            }
          }
        }
      },
      {
        id: 2,
        circuitId: CircuitId.LinkedMultiQuery10,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.Iden3SparseMerkleTreeProof,
          allowedIssuers: ['*'],
          type: 'KYCEmployee',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            documentType: {
              $eq: 1
            },
            position: {
              $eq: 'boss',
              $ne: 'employee'
            }
          }
        }
      },
      {
        id: 3,
        circuitId: CircuitId.AtomicQueryV3,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCEmployee',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            hireDate: {
              $eq: '2023-12-11'
            }
          }
        },
        params: {
          nullifierSessionId: '12345'
        }
      }
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: proofReqs
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: didIssuer.string()
    };

    // Ethereum identities should have a previous state in state storage. We mock it here.
    const previousGetLatestStateById = MOCK_STATE_STORAGE.getLatestStateById;
    MOCK_STATE_STORAGE.getLatestStateById = async (id: bigint): Promise<StateInfo> => {
      return {
        id,
        state: res.oldTreeState.state.bigInt(),
        replacedByState: 0n,
        createdAtTimestamp: 1712062738n,
        replacedAtTimestamp: 0n,
        createdAtBlock: 5384981n,
        replacedAtBlock: 0n
      };
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);

    // Restore the mock state storage
    MOCK_STATE_STORAGE.getLatestStateById = previousGetLatestStateById;

    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const token = await Token.parse(tokenStr);
    expect(token).to.be.a('object');
  });

  // SKIPPED : ethereum identity integration test
  it.skip('auth flow identity (profile) with ethereum identity issuer with circuits V3 (integration)', async () => {
    const stateEthConfig = defaultEthConnectionConfig;
    stateEthConfig.url = RPC_URL;
    stateEthConfig.contractAddress = STATE_CONTRACT;
    stateEthConfig.chainId = 80002; // Amoy

    const memoryKeyStore = new InMemoryPrivateKeyStore();
    const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, memoryKeyStore);
    const sec256k1Provider = new Sec256k1Provider(KmsKeyType.Secp256k1, memoryKeyStore);
    const kms = new KMS();
    kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);
    kms.registerKeyProvider(KmsKeyType.Secp256k1, sec256k1Provider);

    dataStorage = {
      credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
      identity: new IdentityStorage(
        new InMemoryDataSource<Identity>(),
        new InMemoryDataSource<Profile>()
      ),
      mt: new InMemoryMerkleTreeStorage(40),
      states: new EthStateStorage(stateEthConfig)
    };
    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );
    credWallet = new CredentialWallet(dataStorage, resolvers);

    idWallet = new IdentityWallet(kms, dataStorage, credWallet);

    proofService = new ProofService(
      idWallet,
      credWallet,
      circuitStorage,
      dataStorage.states,
      merklizeOpts
    );

    packageMgr = await getPackageMgr(
      await circuitStorage.loadCircuitData(CircuitId.AuthV2),
      proofService.generateAuthInputs.bind(proofService),
      proofService.verifyState.bind(proofService)
    );

    authHandler = new AuthHandler(packageMgr, proofService);

    const { did: didUser, credential: userAuthCredential } = await idWallet.createIdentity({
      method: DidMethod.PolygonId,
      blockchain: Blockchain.Polygon,
      networkId: NetworkId.Amoy,
      seed: SEED_USER,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    });

    expect(userAuthCredential).not.to.be.undefined;

    const ethSigner = new ethers.Wallet(WALLET_KEY, dataStorage.states.getRpcProvider());

    const { did: didIssuer, credential: issuerAuthCredential } =
      await idWallet.createEthereumBasedIdentity({
        method: DidMethod.PolygonId,
        blockchain: Blockchain.Polygon,
        networkId: NetworkId.Amoy,
        seed: hexToBytes(WALLET_KEY),
        revocationOpts: {
          type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
          id: RHS_URL
        },
        ethSigner
      });
    expect(issuerAuthCredential).not.to.be.undefined;

    const profileDID = await idWallet.createProfile(didUser, 777, didIssuer.string());

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: didUser.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(didIssuer, claimReq, merklizeOpts);
    const employeeCredRequest: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCEmployee-v101.json',
      type: 'KYCEmployee',
      credentialSubject: {
        id: profileDID.string(),
        ZKPexperiance: true,
        hireDate: '2023-12-11',
        position: 'boss',
        salary: 200,
        documentType: 1
      },
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const employeeCred = await idWallet.issueCredential(
      didIssuer,
      employeeCredRequest,
      merklizeOpts
    );

    await credWallet.saveAll([employeeCred, issuerCred]);

    const res = await idWallet.addCredentialsToMerkleTree([employeeCred], didIssuer);
    await idWallet.publishStateToRHS(didIssuer, RHS_URL);

    const txId = await proofService.transitState(
      didIssuer,
      res.oldTreeState,
      false,
      dataStorage.states,
      ethSigner
    );

    const credsWithIden3MTPProof = await idWallet.generateIden3SparseMerkleTreeProof(
      didIssuer,
      res.credentials,
      txId
    );

    await credWallet.saveAll(credsWithIden3MTPProof);

    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.AtomicQueryV3,
        optional: false,
        query: {
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCAgeCredential',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
          credentialSubject: {
            documentType: {
              $eq: 99
            }
          }
        }
      },
      {
        id: 2,
        circuitId: CircuitId.LinkedMultiQuery10,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.Iden3SparseMerkleTreeProof,
          allowedIssuers: ['*'],
          type: 'KYCEmployee',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            documentType: {
              $eq: 1
            },
            position: {
              $eq: 'boss',
              $ne: 'employee'
            }
          }
        }
      },
      {
        id: 3,
        circuitId: CircuitId.AtomicQueryV3,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCEmployee',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            hireDate: {
              $eq: '2023-12-11'
            }
          }
        },
        params: {
          nullifierSessionId: '12345'
        }
      }
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: proofReqs
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: didIssuer.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(didUser, msgBytes);
    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const token = await Token.parse(tokenStr);
    expect(token).to.be.a('object');
  });

  it('auth flow with credentialAtomicQueryV3OnChain/auth proof and sender challenge', async () => {
    const sender = '0x0E7263bE4DEAC0bbC02F86B3eBF0fd28aA41b211';
    const expectedChallenge = getChallengeFromEthAddress(sender);

    const employeeCredRequest: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCEmployee-v101.json',
      type: 'KYCEmployee',
      credentialSubject: {
        id: userDID.string(),
        ZKPexperiance: true,
        hireDate: '2023-12-11',
        position: 'boss',
        salary: 200,
        documentType: 1
      },
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, employeeCredRequest, merklizeOpts);
    await credWallet.save(issuerCred);

    const expectedAuthChallenge =
      '1234567890123456789012345678901234567890123456789012345678901234';

    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.AtomicQueryV3OnChainStable,
        optional: false,
        query: {
          allowedIssuers: ['*'],
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            ZKPexperiance: {}
          },
          type: 'KYCEmployee'
        },
        params: {
          sender
        }
      },
      {
        id: 2,
        circuitId: CircuitId.AuthV3_8_32,
        params: {
          challenge: expectedAuthChallenge
        }
      } as ZeroKnowledgeProofRequest
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'https://httpbin.org/anything',
      reason: 'for testing purposes',
      scope: [...proofReqs]
    };

    const authReq: AuthorizationRequestMessage = {
      id: uuid.v4(),
      typ: MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: uuid.v4(),
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);

    expect(authRes.authResponse.body.scope).to.have.lengthOf(2);
    const [onChainProofResp, authProofResp] = authRes.authResponse.body.scope;
    expect(onChainProofResp.circuitId).to.contain(CircuitId.AtomicQueryV3OnChainStable);

    expect(onChainProofResp.pub_signals[8]).to.equal(expectedChallenge.toString());

    expect(authProofResp.pub_signals[1]).to.equal(expectedAuthChallenge.toString());

    expect(authProofResp.circuitId).to.equal(CircuitId.AuthV3_8_32);
  });

  it('auth response: TestVerifyWithAtomicMTPProof', async () => {
    const sender = 'did:polygonid:polygon:mumbai:1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
    const callback = 'https://test.com/callback';
    const userId = 'did:polygonid:polygon:mumbai:2qPDLXDaU1xa1ERTb1XKBfPCB3o2wA46q49neiXWwY';
    const reason = 'test';
    const message = 'message to sign';
    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 23,
      circuitId: CircuitId.AtomicQueryMTPV2,
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
        type: 'KYCCountryOfResidenceCredential',
        credentialSubject: {
          countryCode: {
            $nin: [840, 120, 340, 509]
          }
        }
      }
    };
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      reason,
      message,
      sender,
      callback,
      {
        scope: [proofRequest]
      }
    );
    expect(request.body.scope.length).to.be.eq(1);
    expect(request.body.callbackUrl).to.be.eq(callback);
    expect(request.body.reason).to.be.eq(reason);
    expect(request.from).to.be.eq(sender);
    request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542';
    const mtpProof: ZeroKnowledgeProofResponse = {
      id: proofRequest.id,
      circuitId: 'credentialAtomicQueryMTPV2',
      proof: {
        pi_a: [
          '261068577516437401613944053873182458364288414130914048345483377226144652651',
          '14191260071695980011679501808453222267520721767757759150101974382053161674611',
          '1'
        ],
        pi_b: [
          [
            '7670847844015116957526183728196977957312627307797919554134684901401436021977',
            '14957845472630017095821833222580194061266186851634053897768738253663253650835'
          ],
          [
            '17835642458484628627556329876919077333912011235308758832172880012813397022104',
            '18100861130149678153133025031709897120097098591298817367491920553037011650228'
          ],
          ['1', '0']
        ],
        pi_c: [
          '6217865949299990642832523256863048932210546049203189113362851476966824162191',
          '19016949225277755690019647385855936969928994210905992628301967883803670436510',
          '1'
        ],
        protocol: 'groth16'
      },
      pub_signals: [
        '1',
        '27152676987128542066808591998573000370436464722519513348891049644813718018',
        '23',
        '27752766823371471408248225708681313764866231655187366071881070918984471042',
        '21545768883509657340209171549441005603306012513932221371599501498534807719689',
        '1',
        '21545768883509657340209171549441005603306012513932221371599501498534807719689',
        '1679323038',
        '336615423900919464193075592850483704600',
        '0',
        '17002437119434618783545694633038537380726339994244684348913844923422470806844',
        '0',
        '5',
        '840',
        '120',
        '340',
        '509',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0'
      ]
    };

    const response: AuthorizationResponseMessage = {
      id: uuid.v4(),
      thid: request.thid,
      typ: request.typ,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      from: userId,
      to: sender,
      body: {
        message: request.body.message,
        scope: [mtpProof]
      }
    };

    await authHandler.handleAuthorizationResponse(response, request, TEST_VERIFICATION_OPTS);
  });

  it('auth response: TestVerifyWithAtomicSigProofNonMerklized', async () => {
    const sender = 'did:polygonid:polygon:mumbai:1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
    const callback = 'https://test.com/callback';
    const userId = 'did:polygonid:polygon:mumbai:2qKzaaAewvBVv11iZjJZzjTxBQioZLEujPYTUJp7gQ';
    const reason = 'test';
    const message = 'message to sign';
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      reason,
      message,
      sender,
      callback
    );
    expect(request.body.scope.length).to.be.eq(0);
    expect(request.body.callbackUrl).to.be.eq(callback);
    expect(request.body.reason).to.be.eq(reason);
    expect(request.from).to.be.eq(sender);

    request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542';

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 84239,
      circuitId: CircuitId.AtomicQuerySigV2,
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
        type: 'KYCAgeCredential',
        credentialSubject: {
          documentType: {
            $eq: [99]
          }
        }
      }
    };
    request.body.scope.push(proofRequest);

    expect(request.body.scope.length).to.be.eq(1);

    const mtpProof: ZeroKnowledgeProofResponse = {
      id: proofRequest.id,
      circuitId: 'credentialAtomicQuerySigV2',
      proof: {
        pi_a: [
          '14056228231956087288378518013493130710375131807243578639863710060510262038676',
          '15685597096933930175890593905690244171450509041610585092210638200145586390285',
          '1'
        ],
        pi_b: [
          [
            '6867891861795556838771075779522609255721689620651295420993290050538780283807',
            '12803728874072821363624664338413776845757845422512289455246307343796729670516'
          ],
          [
            '1556511867067742689232747109877739227261867306751037654148240512509806309140',
            '3417379743049361186708759271231315501277403869916476403120965486647240758779'
          ],
          ['1', '0']
        ],
        pi_c: [
          '10569434133480072042978475540156042501239134571700053665222790798542811352807',
          '16412506719218682682070660169432465369639644911994254460610287965570092298694',
          '1'
        ],
        protocol: 'groth16'
      },
      pub_signals: [
        '0',
        '23556362286864724741858679466282977995723542763829611007300550436288008706',
        '6488011081960287964570775172930943914920953982696735236025195378048754598764',
        '84239',
        '21803003425107230045260507608510138502859759480520560654156359021447614978',
        '1',
        '6488011081960287964570775172930943914920953982696735236025195378048754598764',
        '1693230616',
        '198285726510688200335207273836123338699',
        '1',
        '0',
        '3',
        '1',
        '99',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0'
      ]
    };

    const response: AuthorizationResponseMessage = {
      id: uuid.v4(),
      thid: request.thid,
      typ: request.typ,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      from: userId,
      to: sender,
      body: {
        message: request.body.message,
        scope: [mtpProof]
      }
    };

    await authHandler.handleAuthorizationResponse(response, request, TEST_VERIFICATION_OPTS);
  });

  it('auth response: TestVerifyV3MessageWithSigProof_NonMerklized', async () => {
    const request: AuthorizationRequestMessage = {
      id: '28b15cd4-3aa1-4ddc-88a3-c05a0f788065',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: '28b15cd4-3aa1-4ddc-88a3-c05a0f788065',
      body: {
        callbackUrl: 'https://test.com/callback',
        reason: 'test',
        message: 'message to sign',
        scope: [
          {
            id: 1,
            circuitId: CircuitId.AtomicQueryV3,
            optional: true,
            query: {
              allowedIssuers: ['*'],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
              credentialSubject: { documentType: { $eq: 99 } },
              // proofType: ProofType.BJJSignature, <-- proof type is optional
              type: 'KYCAgeCredential'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    // response
    const message: AuthorizationResponseMessage = {
      id: '59fbefd2-39ce-4346-94f1-49ec86141ba9',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/response',
      thid: '28b15cd4-3aa1-4ddc-88a3-c05a0f788065',
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 1,
            circuitId: CircuitId.AtomicQueryV3,
            proof: {
              pi_a: [
                '4931850785213949686128999530866355140504398167046521116795481546947184272648',
                '332774575245859134568137417770603285619416893331837204312155221564587668094',
                '1'
              ],
              pi_b: [
                [
                  '14792271695016162952390815554867533625013692933642600379618564819732493637941',
                  '18215310934256606244114322866050307053902107679161350635408930840065889072916'
                ],
                [
                  '17048410972040698560239088146160392663861669520384562422376544822376801389912',
                  '21559641235416117505150830172567831599407748749353430076073365383629391654250'
                ],
                ['1', '0']
              ],
              pi_c: [
                '1398727697779021690907399287414954376665288113096930249445808929806707726439',
                '627223672270092807254159968400380256577737860448215394733886462613367964620',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '0',
              '21568225469889458305914841490175280093555015071329787375641431262509208065',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '0',
              '0',
              '0',
              '1',
              '1',
              '25191641634853875207018381290409317860151551336133597267061715643603096065',
              '1',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '1708958378',
              '198285726510688200335207273836123338699',
              '0',
              '3',
              '1',
              '99',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '1',
              '0',
              '0'
            ]
          }
        ]
      },
      from: 'did:iden3:polygon:mumbai:wuw5tydZ7AAd3efwEqPprnqjiNHR24jqruSPKmV1V',
      to: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    await authHandler.handleAuthorizationResponse(message, request, TEST_VERIFICATION_OPTS);
  });

  it('auth response: TestVerifyV3MessageWithMtpProof_Merklized', async () => {
    const request: AuthorizationRequestMessage = {
      id: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        callbackUrl: 'https://test.com/callback',
        reason: 'test',
        message: 'message to sign',
        scope: [
          {
            id: 1,
            circuitId: CircuitId.AtomicQueryV3,
            optional: false,
            query: {
              allowedIssuers: ['*'],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
              credentialSubject: { documentType: { $eq: 99 } },
              proofType: ProofType.Iden3SparseMerkleTreeProof,
              type: 'KYCAgeCredential'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    const message: AuthorizationResponseMessage = {
      id: 'a8ceddf8-24c8-4797-bb94-234a17c6b551',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/response',
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 1,
            circuitId: CircuitId.AtomicQueryV3,
            proof: {
              pi_a: [
                '21670105620652703601477810515677208955235385482913430843458796496505567239793',
                '13288728367063292010057292794440148934003973173769496254360913324078694891034',
                '1'
              ],
              pi_b: [
                [
                  '16370966906841564400313385717883093075944937381897969856709983472924165509408',
                  '7778887146640489720647167503138118335113598059976826778839162024634297503509'
                ],
                [
                  '3056709170897468503543133506346448343248296922943029424017396286992125449008',
                  '18924324019871646744005830283614996965229851563759352746018105419445741419358'
                ],
                ['1', '0']
              ],
              pi_c: [
                '11756251835947810289905030105462848637445985844896239324130081980601483358204',
                '3744754840803796468374265874229396141965695715998580645165923368421757602995',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '1',
              '21568225469889458305914841490175280093555015071329787375641431262509208065',
              '6880296436594660732089540737768771091806334429473963727848865469054445967519',
              '0',
              '0',
              '0',
              '2',
              '1',
              '19898531390599208021876718705689344940605246460654065917270282371355906561',
              '1',
              '5224437024673068498206105743424598123651101873588696368477339341771571761791',
              '1708958971',
              '74977327600848231385663280181476307657',
              '17040667407194471738958340146498954457187839778402591036538781364266841966',
              '0',
              '1',
              '99',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '1',
              '0',
              '0'
            ]
          }
        ]
      },
      from: 'did:iden3:polygon:mumbai:wuw5tydZ7AAd3efwEqPprnqjiNHR24jqruSPKmV1V',
      to: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    await authHandler.handleAuthorizationResponse(message, request, TEST_VERIFICATION_OPTS);
  });

  it('auth response: linked multi query', async () => {
    const authRequest: AuthorizationRequestMessage = {
      id: 'f5bcdfc9-3819-4052-ad97-c059119e563c',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: 'f5bcdfc9-3819-4052-ad97-c059119e563c',
      body: {
        callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
        reason: 'reason',
        message: 'message',
        scope: [
          {
            id: 1,
            circuitId: CircuitId.AtomicQueryV3,
            optional: false,
            query: {
              proofType: ProofType.BJJSignature,
              allowedIssuers: ['*'],
              type: 'KYCAgeCredential',
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
              credentialSubject: {
                documentType: {
                  $eq: 99
                }
              }
            }
          },
          {
            id: 2,
            circuitId: CircuitId.LinkedMultiQuery10,
            optional: false,
            query: {
              groupId: 1,
              proofType: ProofType.Iden3SparseMerkleTreeProof,
              allowedIssuers: ['*'],
              type: 'KYCEmployee',
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
              credentialSubject: {
                documentType: {
                  $eq: 1
                },
                position: {
                  $eq: 'boss',
                  $ne: 'employee'
                }
              }
            }
          },
          {
            id: 3,
            circuitId: CircuitId.AtomicQueryV3,
            optional: false,
            query: {
              groupId: 1,
              proofType: ProofType.BJJSignature,
              allowedIssuers: ['*'],
              type: 'KYCEmployee',
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
              credentialSubject: {
                hireDate: {
                  $eq: '2023-12-11'
                }
              }
            },
            params: {
              nullifierSessionId: '12345'
            }
          }
        ]
      },
      from: 'did:iden3:polygon:mumbai:wzokvZ6kMoocKJuSbftdZxTD6qvayGpJb3m4FVXth'
    };

    const response = JSON.parse(
      `{"id":"9f8c5eaf-761b-45a3-9291-e716809ace80","typ":"application/iden3-zkp-json","type":"https://iden3-communication.io/authorization/1.0/response","thid":"f1db2356-9f44-48ad-9b76-f89d47f21f6a","body":{"message":"message","scope":[{"id":1,"circuitId":"credentialAtomicQueryV3-beta.1","proof":{"pi_a":["1957042983521939777779358613512940538748371001503599796504079991585151845626","5980467088491530700980741867186770936154186459285094575907693303048036963689","1"],"pi_b":[["5742671146783049896789457637506168650313117608892287762091826086179746860469","7867980002214299883401553001814837114723536790472835510365975534274190677490"],["6409919485783982335585179727042442194321707383499872699189740318445051390961","1369980068779537226244190127504408237299520988801560937733214682094782613117"],["1","0"]],"pi_c":["5711121494820066463200893985386651555980045684596061159643138162113786427802","4095818364808367579242275974249584152089253995861921406668522195898158853090","1"],"protocol":"groth16","curve":"bn128"},"pub_signals":["0","21568225469889458305914841490175280093555015071329787375641431262509208065","4487386332479489158003597844990487984925471813907462483907054425759564175341","0","0","0","1","1","25191641634853875207018381290409317860151551336133597267061715643603096065","1","4487386332479489158003597844990487984925471813907462483907054425759564175341","1709225461","198285726510688200335207273836123338699","0","3","1","99","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","1","25191641634853875207018381290409317860151551336133597267061715643603096065","0"]},{"id":2,"circuitId":"linkedMultiQuery10-beta.1","proof":{"pi_a":["10008762987135252748343336852440821999292200194586609431123158877924829442619","643120883606370243165315267728925724383441131555632496875810966571180142836","1"],"pi_b":[["20325202427888218305042001051611691791013545949589864140437875458628437599770","8717600144533993361171658192288756446811108221293161636717237909993926710318"],["14981619958191157581227114000872054457371373393565997302166302876147503284338","16553636587728487263592580154123194292472350845107268041191122057483030032517"],["1","0"]],"pi_c":["16072126589976107857236142821613193518209749401521398065019425748092192614959","303906682296869502342276988123716958990500798695456357531107835924939259150","1"],"protocol":"groth16","curve":"bn128"},"pub_signals":["14840595334989550616466083197180000787621620083536890923904228235213356726165","1","0","0","0","0","0","0","0","0","0","0","15577114799056939633552845531011024672939493492769628285661359711655214561162","16998762965396944782667557741185828136467747762830028217027973617373862301958","9302526208507753799501130128908494673412443631541424409551205277529949662394","14612518006493998037149299647974237771551070312096882407440651052752259038403","14612518006493998037149299647974237771551070312096882407440651052752259038403","14612518006493998037149299647974237771551070312096882407440651052752259038403","14612518006493998037149299647974237771551070312096882407440651052752259038403","14612518006493998037149299647974237771551070312096882407440651052752259038403","14612518006493998037149299647974237771551070312096882407440651052752259038403","14612518006493998037149299647974237771551070312096882407440651052752259038403"]},{"id":3,"circuitId":"credentialAtomicQueryV3-beta.1","proof":{"pi_a":["4918421968222994875065132919357788716527410020013314076838075601739876838116","10576714801149162526665883185954136825228282980216373802495776414648547250389","1"],"pi_b":[["11108578138197665525735155920251801717888098160693764639454679880928722733880","3997721247159844618817277585055198811110117246676622629879543401795646667027"],["20635473172141447711225783196574171578493742575849493414547293568487122129963","6948443179619059689387710642006412901626278322232965354300544053846217743110"],["1","0"]],"pi_c":["469119326794229447935775203453233806548971393125675053242929084072054328769","178813906627150338283979844326455982590598033322249897359697376726879654625","1"],"protocol":"groth16","curve":"bn128"},"pub_signals":["1","21568225469889458305914841490175280093555015071329787375641431262509208065","4487386332479489158003597844990487984925471813907462483907054425759564175341","14840595334989550616466083197180000787621620083536890923904228235213356726165","21051816437711998017249050444244727806861025707804897813951842286690382472927","0","1","3","25191641634853875207018381290409317860151551336133597267061715643603096065","1","4487386332479489158003597844990487984925471813907462483907054425759564175341","1709225477","219578617064540016234161640375755865412","1296351758269061173317105041968067077451914386086222931516199194959869463882","0","1","1702252800000000000","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","1","25191641634853875207018381290409317860151551336133597267061715643603096065","12345"]}]},"from":"did:iden3:polygon:mumbai:wuw5tydZ7AAd3efwEqPprnqjiNHR24jqruSPKmV1V","to":"did:iden3:polygon:mumbai:wzokvZ6kMoocKJuSbftdZxTD6qvayGpJb3m4FVXth"}`
    ) as AuthorizationResponseMessage;
    await authHandler.handleAuthorizationResponse(response, authRequest, TEST_VERIFICATION_OPTS);
  });

  it('null scope auth request', async () => {
    const msgBytes = byteEncoder.encode(
      '{"id":"f3688b54-248d-4a75-b743-39f99a49adb8","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/authorization/1.0/request","thid":"f3688b54-248d-4a75-b743-39f99a49adb8","body":{"callbackUrl":"https://issuer-admin.polygonid.me/v1/credentials/links/callback?sessionID=1bd6b1cb-cfc1-4817-8b77-3bc150435e29\u0026linkID=880face8-43b7-428b-80b1-adb6da0632ac","reason":"authentication","scope":null},"from":"did:polygonid:polygon:mumbai:2qMLpQ5py1YzBTTuLEeX2yr6pDGQ7gyXAfygaPakzq"}'
    );
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);

    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const token = await Token.parse(tokenStr);
    expect(token).to.be.a('object');
  });

  it('auth response: TestVerifyV3MessageWithMtpProof_Merklized_exists (AuthV3 from preferred handler option)', async () => {
    const stateEthConfig = defaultEthConnectionConfig;
    stateEthConfig.url = RPC_URL;
    stateEthConfig.contractAddress = STATE_CONTRACT;
    stateEthConfig.chainId = 80002;

    const stateCache = createInMemoryCache<StateInfo>({
      ttl: PROTOCOL_CONSTANTS.DEFAULT_PROOF_VERIFY_DELAY,
      maxSize: DEFAULT_CACHE_MAX_SIZE * 2
    });
    const rootCache = createInMemoryCache<RootInfo>({
      ttl: PROTOCOL_CONSTANTS.DEFAULT_AUTH_VERIFY_DELAY,
      maxSize: DEFAULT_CACHE_MAX_SIZE * 2
    });

    const eth = new EthStateStorage(stateEthConfig, {
      stateCacheOptions: {
        cache: stateCache
      },
      rootCacheOptions: {
        cache: rootCache
      }
    });

    const kms = registerKeyProvidersInMemoryKMS();
    dataStorage = getInMemoryDataStorage(eth);

    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );
    credWallet = new CredentialWallet(dataStorage, resolvers);
    idWallet = new IdentityWallet(kms, dataStorage, credWallet);

    proofService = new ProofService(idWallet, credWallet, circuitStorage, eth, merklizeOpts);
    const { did: issuerDID } = await createIdentity(idWallet, {
      seed: getRandomBytes(32)
    });
    const { did: userDID } = await createIdentity(idWallet, {
      seed: getRandomBytes(32)
    });

    packageMgr = await getPackageMgrV3(
      [
        await circuitStorage.loadCircuitData(CircuitId.AuthV2),
        await circuitStorage.loadCircuitData(CircuitId.AuthV3),
        await circuitStorage.loadCircuitData(CircuitId.AuthV3_8_32)
      ],
      [
        {
          circuitId: CircuitId.AuthV2,
          prepareFunc: proofService.generateAuthInputs.bind(proofService)
        },
        {
          circuitId: CircuitId.AuthV3,
          prepareFunc: proofService.generateAuthInputs.bind(proofService)
        },
        {
          circuitId: CircuitId.AuthV3_8_32,
          prepareFunc: proofService.generateAuthInputs.bind(proofService)
        }
      ],
      proofService.verifyState.bind(proofService)
    );

    authHandler = new AuthHandler(packageMgr, proofService);

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v4.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);

    await credWallet.save(issuerCred);

    const proofReq: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      query: {
        groupId: 1,
        allowedIssuers: ['*'],
        type: claimReq.type,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        credentialSubject: {
          documentType: {
            $exists: true
          }
        },
        proofType: ProofType.BJJSignature
      }
    };

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      scope: [proofReq],
      accept: buildAccept([
        {
          protocolVersion: ProtocolVersion.V1,
          env: MediaType.ZKPMessage,
          circuits: [AcceptAuthCircuits.AuthV3]
        }
      ])
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const jwzRequest = await packageMgr.pack(MediaType.ZKPMessage, msgBytes, {
      senderDID: issuerDID,
      provingMethodAlg: new ProvingMethodAlg('groth16', 'authV3')
    });
    const authRes = await authHandler.handleAuthorizationRequest(userDID, jwzRequest, {
      mediaType: MediaType.ZKPMessage,
      preferredAuthProvingMethod: new ProvingMethodAlg('groth16', 'authV3')
    });

    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');

    const resToken = await Token.parse(tokenStr);
    expect(resToken.circuitId).to.be.eq(CircuitId.AuthV3);

    const { response } = await authHandler.handleAuthorizationResponse(
      authRes.authResponse,
      authReq,
      TEST_VERIFICATION_OPTS
    );

    const token = await packageMgr.pack(
      PROTOCOL_CONSTANTS.MediaType.ZKPMessage,
      byteEncoder.encode(JSON.stringify(response)),
      {
        senderDID: issuerDID,
        provingMethodAlg: new ProvingMethodAlg('groth16', 'authV3')
      }
    );

    expect(token).to.be.a.string;

    /*

    const res = await idWallet.addCredentialsToMerkleTree([issuerCred], issuerDID);

    // publish to rhs

    await idWallet.publishStateToRHS(issuerDID, RHS_URL);

    // you must store stat info (e.g. state and it's roots)

    const ethSigner = new ethers.Wallet(WALLET_KEY, dataStorage.states.getRpcProvider());
    const txId = await proofService.transitState(
      issuerDID,
      res.oldTreeState,
      true,
      dataStorage.states,
      ethSigner
    );

    const credsWithIden3MTPProof = await idWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

    await credWallet.saveAll(credsWithIden3MTPProof);

    const { response: resp2 } = await authHandler.handleAuthorizationResponse(
      authRes.authResponse,
      authReq,
      TEST_VERIFICATION_OPTS
    );

    const token2 = await packageMgr.pack(
      PROTOCOL_CONSTANTS.MediaType.ZKPMessage,
      byteEncoder.encode(JSON.stringify(resp2)),
      {
        senderDID: issuerDID,
        provingMethodAlg: new ProvingMethodAlg('groth16', 'authV2')
      }
    );

    expect(token2).to.be.a.string;
    */
  });

  it('auth response: TestVerifyV3MessageWithSigProof_Linked_SD&LT (AuthV3-8-32 from accept)', async () => {
    const stateEthConfig = defaultEthConnectionConfig;
    stateEthConfig.url = RPC_URL;
    stateEthConfig.contractAddress = STATE_CONTRACT;
    stateEthConfig.chainId = 80002;
    const eth = new EthStateStorage(stateEthConfig);

    const kms = registerKeyProvidersInMemoryKMS();
    dataStorage = getInMemoryDataStorage(eth);
    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );
    credWallet = new CredentialWallet(dataStorage, resolvers);
    idWallet = new IdentityWallet(kms, dataStorage, credWallet);

    proofService = new ProofService(idWallet, credWallet, circuitStorage, eth, merklizeOpts);
    const { did: issuerDID } = await createIdentity(idWallet, {
      seed: getRandomBytes(32)
    });
    const { did: userDID } = await createIdentity(idWallet, {
      seed: getRandomBytes(32)
    });

    packageMgr = getPackageManagerWithDefaultZKPPacker(circuitStorage, proofService);

    authHandler = new AuthHandler(packageMgr, proofService);

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v4.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);

    await credWallet.save(issuerCred);

    const proofReq: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      query: {
        groupId: 1,
        allowedIssuers: ['*'],
        type: claimReq.type,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        credentialSubject: {
          documentType: {
            $exists: true
          }
        },
        proofType: ProofType.BJJSignature
      }
    };

    const proofReq2: ZeroKnowledgeProofRequest = {
      id: 2,
      circuitId: CircuitId.LinkedMultiQuery10,
      optional: false,
      query: {
        groupId: 1,
        allowedIssuers: ['*'],
        type: claimReq.type,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        credentialSubject: {
          birthday: {},
          documentType: {}
        },
        proofType: ProofType.BJJSignature
      }
    };

    const proofReq3: ZeroKnowledgeProofRequest = {
      id: 3,
      circuitId: CircuitId.LinkedMultiQuery10,
      optional: false,
      query: {
        groupId: 1,
        allowedIssuers: ['*'],
        type: claimReq.type,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        credentialSubject: {
          birthday: {
            $lt: 10000000000
          }
        },
        proofType: ProofType.BJJSignature
      }
    };

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      scope: [proofReq, proofReq2, proofReq3],
      accept: buildAccept([
        {
          protocolVersion: ProtocolVersion.V1,
          env: MediaType.ZKPMessage,
          circuits: [AcceptAuthCircuits.AuthV3_8_32]
        }
      ])
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const jwzRequest = await packageMgr.pack(MediaType.ZKPMessage, msgBytes, {
      senderDID: issuerDID,
      provingMethodAlg: new ProvingMethodAlg('groth16', 'authV3-8-32')
    });
    const authRes = await authHandler.handleAuthorizationRequest(userDID, jwzRequest);

    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const resToken = await Token.parse(tokenStr);
    expect(resToken.circuitId).to.be.eq(CircuitId.AuthV3_8_32);

    const { response } = await authHandler.handleAuthorizationResponse(
      authRes.authResponse,
      authReq,
      TEST_VERIFICATION_OPTS
    );
    const token = await packageMgr.pack(
      PROTOCOL_CONSTANTS.MediaType.ZKPMessage,
      byteEncoder.encode(JSON.stringify(response)),
      {
        senderDID: userDID,
        provingMethodAlg: new ProvingMethodAlg('groth16', 'authV3-8-32')
      }
    );

    expect(token).to.be.a.string;

    expect(byteDecoder.decode(token)).toBeTypeOf('string');

    const unpacked = await packageMgr.unpack(token);

    expect(unpacked.unpackedMediaType).to.eq(PROTOCOL_CONSTANTS.MediaType.ZKPMessage);
  });

  it('auth response: Preferred is set, but no accept - default should be used', async () => {
    const stateEthConfig = defaultEthConnectionConfig;
    stateEthConfig.url = RPC_URL;
    stateEthConfig.contractAddress = STATE_CONTRACT;
    stateEthConfig.chainId = 80002;
    const eth = new EthStateStorage(stateEthConfig);

    const kms = registerKeyProvidersInMemoryKMS();
    dataStorage = getInMemoryDataStorage(eth);
    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );
    credWallet = new CredentialWallet(dataStorage, resolvers);
    idWallet = new IdentityWallet(kms, dataStorage, credWallet);

    proofService = new ProofService(idWallet, credWallet, circuitStorage, eth, merklizeOpts);
    const { did: issuerDID } = await createIdentity(idWallet, {
      seed: getRandomBytes(32)
    });
    const { did: userDID } = await createIdentity(idWallet, {
      seed: getRandomBytes(32)
    });

    packageMgr = getPackageManagerWithDefaultZKPPacker(circuitStorage, proofService);

    authHandler = new AuthHandler(packageMgr, proofService);

    // no accept here
    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      scope: []
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    // preferred auth proving method set to auth V3_8_32, but no accept, so auth v2 should be used
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes, {
      mediaType: PROTOCOL_CONSTANTS.MediaType.ZKPMessage,
      preferredAuthProvingMethod: proving.provingMethodGroth16AuthV3_8_32Instance.methodAlg
    });

    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const resToken = await Token.parse(tokenStr);
    expect(resToken.circuitId).to.be.eq(CircuitId.AuthV2);
  });

  it('auth response: TestVerifyV3MessageWithMtpProof_Merklized_noop', async () => {
    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v4.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);

    await credWallet.save(issuerCred);

    const proofReq: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      query: {
        allowedIssuers: ['*'],
        type: claimReq.type,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        proofType: ProofType.BJJSignature
      }
    };

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      scope: [proofReq as ZeroKnowledgeProofRequest]
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);

    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
  });

  it('auth request: v2 sig sd', async () => {
    const sender = 'did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL';
    const callback = 'https://test.com/callback';
    const reason = 'age verification';
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      reason,
      '',
      sender,
      callback
    );

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v4.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };

    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);
    await credWallet.save(issuerCred);

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQuerySigV2,
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        type: 'KYCAgeCredential',
        credentialSubject: {
          birthday: {}
        }
      }
    };
    request.body.scope.push(proofRequest);
    request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
    request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542';

    const msgBytes = byteEncoder.encode(JSON.stringify(request));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
  });

  it('auth response: TestVerify v2 sig sd', async () => {
    const sender = 'did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL';
    const callback = 'https://test.com/callback';
    const reason = 'age verification';
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      reason,
      '',
      sender,
      callback
    );

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQuerySigV2,
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        type: 'KYCAgeCredential',
        credentialSubject: {
          birthday: {}
        }
      }
    };
    request.body.scope.push(proofRequest);

    request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
    request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; // because it's used in the response

    const response = JSON.parse(`{
      "id": "f3f5f3bd-2d8b-4949-a069-9759be7cf50a",
      "typ": "application/iden3comm-plain-json",
      "type": "https://iden3-communication.io/authorization/1.0/response",
      "thid": "7f38a193-0918-4a48-9fac-36adfdb8b542",
      "from": "did:polygonid:polygon:mumbai:2qJpRqZNRTxkiCUN4VSfLQ7KA4PzHSwwVwnSKSFKtw",
      "to": "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL",
      "body": {
          "did_doc": {
              "@context": [
                  "https://www.w3.org/ns/did/v1"
              ],
              "id": "did:polygonid:polygon:mumbai:2qJpRqZNRTxkiCUN4VSfLQ7KA4PzHSwwVwnSKSFKtw",
              "service": [
                  {
                      "id": "did:polygonid:polygon:mumbai:2qJpRqZNRTxkiCUN4VSfLQ7KA4PzHSwwVwnSKSFKtw#push",
                      "type": "push-notification",
                      "serviceEndpoint": "https://push-staging.polygonid.com/api/v1",
                      "metadata": {
                          "devices": [
                              {
                                  "ciphertext": "0I0yYaUj1x91uYozBbrC8nA1jdvC7nb0KprOmSBIjYtZfq/eXUPvmt4vjl9pGd7LhIx6lUYOMMhsIM58VkVXcTXv2wbZL092LVwSWvOv7fvUuhi2m4nUTzojaTuvmuuGmMZafjIZW20Zy4Etu+itiUEw6qc9OPm1fiqY6+ixapaJcuV1CSG3Eo8WXvG5lksJYG8bkBmfIsGiQwiwYGpAVePnk2u6FvGiWiJL5lqfwF7OgI3zmj5JBiM/uJK4eyBVSSprkiYktJNvJAbm3sXkXnu8yS7Igkyjzd+nKKUSOYaS4P6hS7eMCNZgdlMPCjd5PagjxMl5bHpPB4ElzBPnGT7yd8iWEGDjVCnhD4APdTeQUr9WEemBjnibm+S8C8k2xAw8AZo4OmsJHx7Kg5VItarwrLy4CGS5WWea6S488c2r4noVlnmAOrND7LmQ6L/0lzWM1AxGcQ1SsyCcTteuZg56gwiMQ+6cMzAX/f2IN3FlmtplRRKqc2cRL8nsVyIEq0y37QaaAlnotFI3vHNtctVTR5nqZ3zznXDan5jmwKebEPVvdLxWp10DSLnSXiQoET2SrHC1YvlffDAvj+b+1U152qhINgU+Omw2VE2T1oP0UCmbCkGBlC+7CBwtUgrhF7htxL9oAKECPWFHSRQsf8gIkmALyO9VCj1xeappQ9I=",
                                  "alg": "RSA-OAEP-512"
                              }
                          ]
                      }
                  }
              ]
          },
          "message": null,
          "scope": [
              {
                  "id": 1,
                  "circuitId": "credentialAtomicQuerySigV2",
                  "proof": {
                      "pi_a": [
                          "13823044472745786908995378977428468334691339903626253052467645595896751884324",
                          "14356457032265788557275947130052372307935357245172088694540617048200164735550",
                          "1"
                      ],
                      "pi_b": [
                          [
                              "14038837468790150555724321214321987303645407592127362465185807730734687008748",
                              "16127175500346693425201237491221604626317337533699053876931967535723744623628"
                          ],
                          [
                              "7835726266684299556756486695743627845524382286636757992786728500640304024078",
                              "12625109860013174660697550528873760592255929049947026704702790117950465030893"
                          ],
                          [
                              "1",
                              "0"
                          ]
                      ],
                      "pi_c": [
                          "14831812078422268302721284760494652587846937966905721763323843636407425073891",
                          "11403849275523392594161040440544799981358458631868290791807186627510321438823",
                          "1"
                      ],
                      "protocol": "groth16",
                      "curve": "bn128"
                  },
                  "pub_signals": [
                      "1",
                      "21513140530233921515809235388780134681245612858744900297740490447738573314",
                      "14172770088602255825733611365398718935371244575253056361307823303028442907950",
                      "1",
                      "27752766823371471408248225708681313764866231655187366071881070918984471042",
                      "1",
                      "2298258970899685167511194049923695919137720894525468335857057655221098924973",
                      "1681384483",
                      "267831521922558027206082390043321796944",
                      "0",
                      "20376033832371109177683048456014525905119173674985843915445634726167450989630",
                      "0",
                      "1",
                      "19960424",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0",
                      "0"
                  ],
                  "vp": {
                      "@type": "VerifiablePresentation",
                      "@context": [
                          "https://www.w3.org/2018/credentials/v1"
                      ],
                      "verifiableCredential": {
                          "@context": [
                              "https://www.w3.org/2018/credentials/v1",
                              "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld"
                          ],
                          "@type": [
                              "VerifiableCredential",
                              "KYCAgeCredential"
                          ],
                          "credentialSubject": {
                              "@type": "KYCAgeCredential",
                              "birthday": 19960424
                          }
                      }
                  }
              }
          ]
      }
  }`) as AuthorizationResponseMessage;

    await authHandler.handleAuthorizationResponse(response, request, TEST_VERIFICATION_OPTS);
  });

  it('auth flow identity (profile) with circuits V3', async () => {
    const profileDID = await idWallet.createProfile(userDID, 777, issuerDID.string());

    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);
    const employeeCredRequest: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCEmployee-v101.json',
      type: 'KYCEmployee',
      credentialSubject: {
        id: profileDID.string(),
        ZKPexperiance: true,
        hireDate: '2023-12-11',
        position: 'boss',
        salary: 200,
        documentType: 1
      },
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const employeeCred = await idWallet.issueCredential(
      issuerDID,
      employeeCredRequest,
      merklizeOpts
    );

    await credWallet.saveAll([employeeCred, issuerCred]);

    const res = await idWallet.addCredentialsToMerkleTree([employeeCred], issuerDID);
    await idWallet.publishStateToRHS(issuerDID, RHS_URL);

    const ethSigner = new ethers.Wallet(WALLET_KEY, dataStorage.states.getRpcProvider());

    const txId = await proofService.transitState(
      issuerDID,
      res.oldTreeState,
      true,
      dataStorage.states,
      ethSigner
    );

    const credsWithIden3MTPProof = await idWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

    await credWallet.saveAll(credsWithIden3MTPProof);

    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.AtomicQueryV3,
        optional: false,
        query: {
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCAgeCredential',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
          credentialSubject: {
            documentType: {
              $eq: 99
            }
          }
        }
      },
      {
        id: 2,
        circuitId: CircuitId.LinkedMultiQuery10,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.Iden3SparseMerkleTreeProof,
          allowedIssuers: ['*'],
          type: 'KYCEmployee',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            documentType: {
              $eq: 1
            },
            position: {
              $eq: 'boss',
              $ne: 'employee'
            }
          }
        }
      },
      {
        id: 3,
        circuitId: CircuitId.AtomicQueryV3,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCEmployee',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
          credentialSubject: {
            hireDate: {
              $eq: '2023-12-11'
            }
          }
        },
        params: {
          nullifierSessionId: '12345'
        }
      }
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: proofReqs
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const token = await Token.parse(tokenStr);
    expect(token).to.be.a('object');
  });

  it('key rotation use case', async () => {
    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v4.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);
    await credWallet.save(issuerCred);
    const res = await idWallet.addCredentialsToMerkleTree([issuerCred], issuerDID);
    await idWallet.publishStateToRHS(issuerDID, RHS_URL);

    const proofReq: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      query: {
        allowedIssuers: ['*'],
        type: claimReq.type,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        credentialSubject: {
          documentType: {
            $eq: 99
          }
        },
        proofType: ProofType.BJJSignature
      }
    };

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: [proofReq as ZeroKnowledgeProofRequest]
    };

    const handleAuthorizationRequest = async (
      userDID: DID,
      authReqBody: AuthorizationRequestMessageBody
    ) => {
      const id = uuid.v4();
      const authReq: AuthorizationRequestMessage = {
        id,
        typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
        type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
        thid: id,
        body: authReqBody,
        from: issuerDID.string()
      };

      const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
      const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
      expect(authRes.token).to.be.a('string');
      const token = await Token.parse(authRes.token);
      expect(token).to.be.a('object');
    };

    await handleAuthorizationRequest(userDID, authReqBody);

    // add second Bjj auth credential
    const prover = new NativeProver(circuitStorage);

    const ethSigner = new ethers.Wallet(WALLET_KEY, dataStorage.states.getRpcProvider());
    const opts = {
      seed: SEED_USER,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };

    const treesModel = await idWallet.getDIDTreeModel(issuerDID);
    const [ctrHex, rtrHex, rorTrHex] = await Promise.all([
      treesModel.claimsTree.root(),
      treesModel.revocationTree.root(),
      treesModel.rootsTree.root()
    ]);

    const oldTreeState = {
      state: treesModel.state,
      claimsRoot: ctrHex,
      revocationRoot: rtrHex,
      rootOfRoots: rorTrHex
    };

    // add k2 auth credential (we have k1 already)
    const credential2 = await idWallet.addBJJAuthCredential(
      issuerDID,
      oldTreeState,
      false,
      ethSigner,
      opts,
      prover
    );

    expect(credential2?.proof).not.to.be.undefined;

    // get actual auth credential (k1)
    const { authCredential: issuerAuthCredential } = await idWallet.getActualAuthCredential(
      issuerDID
    );

    // revoke k1 auth credential
    const nonce = await idWallet.revokeCredential(issuerDID, issuerAuthCredential);
    await idWallet.publishStateToRHS(issuerDID, RHS_URL, [nonce]);
    await proofService.transitState(
      issuerDID,
      res.oldTreeState,
      false,
      dataStorage.states,
      ethSigner
    );

    await handleAuthorizationRequest(userDID, authReqBody);

    // get actual auth credential (k2)
    const { authCredential: issuerAuthCredential2 } = await idWallet.getActualAuthCredential(
      issuerDID
    );
    expect(issuerAuthCredential2).to.be.deep.equal(credential2);

    // check we can issue new credential with k2
    const issuerCred2 = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);
    expect(issuerCred2).to.be.not.undefined;

    const treesModel2 = await idWallet.getDIDTreeModel(issuerDID);
    const [ctrHex2, rtrHex2, rorTrHex2] = await Promise.all([
      treesModel2.claimsTree.root(),
      treesModel2.revocationTree.root(),
      treesModel2.rootsTree.root()
    ]);

    const oldTreeState2 = {
      state: treesModel2.state,
      claimsRoot: ctrHex2,
      revocationRoot: rtrHex2,
      rootOfRoots: rorTrHex2
    };

    // revoke k2 auth credential
    const nonce2 = await idWallet.revokeCredential(issuerDID, issuerAuthCredential2);
    await idWallet.publishStateToRHS(issuerDID, RHS_URL, [nonce2]);
    await proofService.transitState(issuerDID, oldTreeState2, false, dataStorage.states, ethSigner);

    // check that we don't have auth credentials now
    await expect(idWallet.getActualAuthCredential(issuerDID)).rejects.toThrow(
      VerifiableConstants.ERRORS.NO_AUTH_CRED_FOUND
    );

    // check that we can't issue new credential
    await expect(idWallet.issueCredential(issuerDID, claimReq, merklizeOpts)).rejects.toThrow(
      VerifiableConstants.ERRORS.NO_AUTH_CRED_FOUND
    );

    // this should this work because we haven't revoked user keys
    await handleAuthorizationRequest(userDID, authReqBody);

    // get actual auth credential for user
    const { authCredential: userAuthCredential } = await idWallet.getActualAuthCredential(userDID);

    const treesModel3 = await idWallet.getDIDTreeModel(userDID);
    const [ctrHex3, rtrHex3, rorTrHex3] = await Promise.all([
      treesModel3.claimsTree.root(),
      treesModel3.revocationTree.root(),
      treesModel3.rootsTree.root()
    ]);

    const oldTreeState3 = {
      state: treesModel3.state,
      claimsRoot: ctrHex3,
      revocationRoot: rtrHex3,
      rootOfRoots: rorTrHex3
    };

    // revoke user keys
    const nonce3 = await idWallet.revokeCredential(userDID, userAuthCredential);
    await idWallet.publishStateToRHS(userDID, RHS_URL, [nonce3]);
    await proofService.transitState(userDID, oldTreeState3, true, dataStorage.states, ethSigner);

    // this should not work because we revoked user keys
    await expect(handleAuthorizationRequest(userDID, authReqBody)).rejects.toThrow(
      VerifiableConstants.ERRORS.NO_AUTH_CRED_FOUND
    );
  });

  it('request-response flow identity - accept header not supported', async () => {
    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);

    await credWallet.save(issuerCred);

    const proofReq: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQuerySigV2,
      optional: false,
      query: {
        allowedIssuers: ['*'],
        type: claimReq.type,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
        credentialSubject: {
          documentType: {
            $eq: 99
          }
        }
      }
    };

    const authV3NotSupportedProfile: AcceptProfile = {
      protocolVersion: ProtocolVersion.V1,
      env: MediaType.ZKPMessage,
      circuits: [AcceptAuthCircuits.AuthV3]
    };
    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      accept: buildAccept([authV3NotSupportedProfile]),
      scope: [proofReq as ZeroKnowledgeProofRequest]
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    await expect(authHandler.handleAuthorizationRequest(userDID, msgBytes)).rejects.toThrow(
      'no packer with profile which meets `accept` header requirements'
    );
  });

  it('auth flow with expired credential and allowExpiredCredentials option', async () => {
    const claimReq: CredentialRequest = {
      credentialSchema:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json',
      type: 'KYCAgeCredential',
      credentialSubject: {
        id: userDID.string(),
        birthday: 19960424,
        documentType: 99
      },
      expiration: 1770651804, // expired credential
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      }
    };
    const issuerCred = await idWallet.issueCredential(issuerDID, claimReq, merklizeOpts);
    await credWallet.save(issuerCred);

    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.AtomicQueryV3Stable,
        optional: false,
        query: {
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'KYCAgeCredential',
          context:
            'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
          credentialSubject: {
            documentType: {
              $eq: 99
            }
          }
        }
      }
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: proofReqs
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    await expect(authHandler.handleAuthorizationRequest(userDID, msgBytes)).rejects.toThrow(
      VerifiableConstants.ERRORS.PROOF_SERVICE_CREDENTIAL_IS_EXPIRED
    );

    try {
      await authHandler.handleAuthorizationRequest(userDID, msgBytes, {
        allowExpiredCredentials: true,
        mediaType: MediaType.ZKPMessage
      });
      throw new Error('Expected error was not thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(Error);
      expect((err as Error).message).to.include('Proof generation failed for circuit ');
      expect((err as Error).cause).to.be.instanceOf(Error);
    }
  });

  it('w3c field request: revocation nonce $eq, expirationDate $eq, issuanceDate SD', async () => {
    const profileDID = await idWallet.createProfile(userDID, 777, issuerDID.string());

    const basicPersonCredRequest: CredentialRequest = {
      credentialSchema: 'ipfs://QmTojMfyzxehCJVw7aUrdWuxdF68R7oLYooGHCUr9wwsef',
      type: 'BasicPerson',
      credentialSubject: {
        id: profileDID.string(),
        fullName: 'John Doe',
        firstName: 'John',
        familyName: 'Doe',
        dateOfBirth: 838531598,
        governmentIdentifier: 'RRRRR',
        governmentIdentifierType: 'passport',
        placeOfBirth: {
          countryCode: 'UA-ua'
        }
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL,
        nonce: 2837597946
      }
    };
    const employeeCred = await idWallet.issueCredential(
      issuerDID,
      basicPersonCredRequest,
      merklizeOpts
    );

    await credWallet.saveAll([employeeCred]);

    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.LinkedMultiQuery10,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'BasicPerson',
          context: 'ipfs://QmZbsTnRwtCmbdg3r9o7Txid37LmvPcvmzVi1Abvqu1WKL',
          credentialStatus: {
            revocationNonce: {
              $eq: 2837597946
            }
          },
          expirationDate: {
            $eq: getDateFromUnixTimestamp(2793526400).toISOString()
          },
          issuanceDate: {},
          credentialSubject: {
            'placeOfBirth.countryCode': {}
          }
        }
      }
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: proofReqs
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const token = await Token.parse(tokenStr);
    expect(token).to.be.a('object');

    await authHandler.handleAuthorizationResponse(
      authRes.authResponse,
      authReq,
      TEST_VERIFICATION_OPTS
    );
  });

  it('w3c field request: revocation nonce SD, expirationDate SD, issuanceDate SD', async () => {
    const profileDID = await idWallet.createProfile(userDID, 777, issuerDID.string());

    const basicPersonCredRequest: CredentialRequest = {
      credentialSchema: 'ipfs://QmTojMfyzxehCJVw7aUrdWuxdF68R7oLYooGHCUr9wwsef',
      type: 'BasicPerson',
      credentialSubject: {
        id: profileDID.string(),
        fullName: 'John Doe',
        firstName: 'John',
        familyName: 'Doe',
        dateOfBirth: 838531598,
        governmentIdentifier: 'RRRRR',
        governmentIdentifierType: 'passport',
        placeOfBirth: {
          countryCode: 'UA-ua'
        }
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL,
        nonce: 2837597946
      }
    };
    const employeeCred = await idWallet.issueCredential(
      issuerDID,
      basicPersonCredRequest,
      merklizeOpts
    );

    await credWallet.saveAll([employeeCred]);

    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.LinkedMultiQuery10,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'BasicPerson',
          context: 'ipfs://QmZbsTnRwtCmbdg3r9o7Txid37LmvPcvmzVi1Abvqu1WKL',
          credentialStatus: {
            revocationNonce: {},
            id: {}
          },
          expirationDate: {},
          issuanceDate: {},
          credentialSubject: {
            'placeOfBirth.countryCode': {}
          }
        }
      }
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: proofReqs
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
    const tokenStr = authRes.token;
    expect(tokenStr).to.be.a('string');
    const token = await Token.parse(tokenStr);
    expect(token).to.be.a('object');

    const vpCredentialStatus =
      authRes.authResponse.body.scope[0].vp?.verifiableCredential.credentialStatus;
    expect(vpCredentialStatus?.revocationNonce).to.equal(
      basicPersonCredRequest.revocationOpts.nonce
    );
    expect(authRes.authResponse.body.scope[0].vp?.verifiableCredential['expirationDate']).to.equal(
      getDateFromUnixTimestamp(basicPersonCredRequest.expiration as number).toISOString()
    );
    expect(authRes.authResponse.body.scope[0].vp?.verifiableCredential['issuanceDate']).to.be.a(
      'string'
    );
    expect(vpCredentialStatus?.type).to.equal(basicPersonCredRequest.revocationOpts.type);

    await authHandler.handleAuthorizationResponse(
      authRes.authResponse,
      authReq,
      TEST_VERIFICATION_OPTS
    );
  });

  it('w3c field request: credentialStatus $eq only — VP carries skeleton for verifier', async () => {
    const profileDID = await idWallet.createProfile(userDID, 777, issuerDID.string());

    const basicPersonCredRequest: CredentialRequest = {
      credentialSchema: 'ipfs://QmTojMfyzxehCJVw7aUrdWuxdF68R7oLYooGHCUr9wwsef',
      type: 'BasicPerson',
      credentialSubject: {
        id: profileDID.string(),
        fullName: 'John Doe',
        firstName: 'John',
        familyName: 'Doe',
        dateOfBirth: 838531598,
        governmentIdentifier: 'RRRRR',
        governmentIdentifierType: 'passport',
        placeOfBirth: {
          countryCode: 'UA-ua'
        }
      },
      expiration: 2793526400,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL,
        nonce: 2837597946
      }
    };
    const employeeCred = await idWallet.issueCredential(
      issuerDID,
      basicPersonCredRequest,
      merklizeOpts
    );

    await credWallet.saveAll([employeeCred]);

    // Only $eq on credentialStatus — no SD fields.
    // The prover creates a VP skeleton (id + type) so the verifier can resolve the
    // merklization path even when no values are selectively disclosed.
    const proofReqs: ZeroKnowledgeProofRequest[] = [
      {
        id: 1,
        circuitId: CircuitId.LinkedMultiQuery10,
        optional: false,
        query: {
          groupId: 1,
          proofType: ProofType.BJJSignature,
          allowedIssuers: ['*'],
          type: 'BasicPerson',
          context: 'ipfs://QmZbsTnRwtCmbdg3r9o7Txid37LmvPcvmzVi1Abvqu1WKL',
          credentialStatus: {
            revocationNonce: {
              $eq: 2837597946
            }
          },
          credentialSubject: {
            'placeOfBirth.countryCode': {
              $eq: 'UA-ua'
            }
          }
        }
      }
    ];

    const authReqBody: AuthorizationRequestMessageBody = {
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: proofReqs
    };

    const id = uuid.v4();
    const authReq: AuthorizationRequestMessage = {
      id,
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: id,
      body: authReqBody,
      from: issuerDID.string()
    };

    const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);

    const vp = authRes.authResponse.body.scope[0].vp;
    expect(vp).not.to.be.undefined;
    // type is required by verifier for merklization path resolution
    expect(vp?.verifiableCredential?.credentialStatus?.type).to.be.a('string').and.not.empty;
    // id has no ZKP — must not be in the skeleton
    expect(vp?.verifiableCredential?.credentialStatus?.id).to.be.undefined;
    // no SD fields — credentialStatus values must NOT be disclosed
    expect(vp?.verifiableCredential?.credentialStatus?.revocationNonce).to.be.undefined;

    await authHandler.handleAuthorizationResponse(
      authRes.authResponse,
      authReq,
      TEST_VERIFICATION_OPTS
    );
  });
});
