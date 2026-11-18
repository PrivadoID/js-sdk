import { InMemoryDataSource } from './../../src/storage/memory/data-source';
import { CredentialStorage } from './../../src/storage/shared/credential-storage';
import { IDataStorage } from './../../src/storage/interfaces/data-storage';
import { CredentialWallet } from '../../src/credentials';
import { SearchError } from '../../src/storage/filters/jsonQuery';
import { MockedLegacyCredential, cred1, cred2, cred3, cred4 } from './mock';
import {
  ProofQuery,
  W3CCredential,
  CredentialStatusType,
  Iden3SparseMerkleTreeProof
} from '../../src/verifiable';
import { BrowserDataSource } from '../../src/storage/local-storage/data-source';
import { describe, expect, it } from 'vitest';

import { CredentialStatusResolverRegistry } from '../../src/credentials';
import { RHSResolver } from '../../src/credentials';
import { IDataSource } from '../../src';
import { Claim, DID, SchemaHash } from '@iden3/js-iden3-core';
import { Hash, Proof, ZERO_HASH } from '@iden3/js-merkletree';

class LocalStorageMock {
  store: object;
  constructor() {
    this.store = {};
  }

  clear() {
    this.store = {};
  }

  getItem(key: string) {
    return this.store[key] || null;
  }

  setItem(key: string, value: string) {
    this.store[key] = value;
  }

  removeItem(key: string) {
    delete this.store[key];
  }
}

const mockedProof = new Iden3SparseMerkleTreeProof({
  issuerData: {
    id: DID.parse('did:polygonid:polygon:mumbai:2qKCnKB6smYGToFJLbjQ2kajWqVxXHJCaJ97vVCiPv'),
    state: {
      value: ZERO_HASH,
      claimsTreeRoot: ZERO_HASH,
      revocationTreeRoot: ZERO_HASH,
      rootOfRoots: ZERO_HASH
    }
  },
  mtp: new Proof({
    siblings: [Hash.fromBigInt(1n), ZERO_HASH, Hash.fromBigInt(2n)],
    nodeAux: { key: ZERO_HASH, value: ZERO_HASH },
    existence: true
  }),
  coreClaim: Claim.newClaim(SchemaHash.authSchemaHash)
});

global.localStorage = new LocalStorageMock() as unknown as Storage;

const mockedDataSource: IDataSource<W3CCredential> = {
  load: function (): Promise<W3CCredential[]> {
    throw new Error('Function not implemented.');
  },
  save: function (): Promise<void> {
    throw new Error('Function not implemented.');
  },
  get: function (key: string): Promise<W3CCredential | undefined> {
    const credential = cred1;
    credential.id = key;
    credential.proof = [mockedProof];

    switch (credential.id) {
      case 'test1':
        // hash-as-string-ints
        credential.proof = [(credential.proof[0] as Iden3SparseMerkleTreeProof).toJSON()];

        return Promise.resolve(credential);

      case 'urn:fa4f7b0f-284d-4a24-9bff-023246582d76':
        return Promise.resolve(MockedLegacyCredential as unknown as W3CCredential);

      default:
        throw new Error('test identifier is not supported');
    }
  },
  delete: (): Promise<void> => {
    throw new Error('Function not implemented.');
  }
};

const credentialFlow = async (storage: IDataStorage) => {
  const resolvers = new CredentialStatusResolverRegistry();
  resolvers.register(
    CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    new RHSResolver(storage.states)
  );
  const credentialWallet = new CredentialWallet(storage, resolvers);

  await credentialWallet.saveAll([cred1, cred2]);

  const credentials = await credentialWallet.list();
  expect(credentials.length).to.equal(2);

  await credentialWallet.save(cred3);
  await credentialWallet.save(cred4);
  const credentialAll = await credentialWallet.list();
  expect(credentialAll.length).to.equal(4);

  // present id
  const credById = await credentialWallet.findById(cred2.id);
  if (!credById) {
    throw new Error('credById is undefined');
  }
  expect(Object.entries(credById).toString()).to.deep.equal(Object.entries(cred2).toString());

  // not present id
  const emptyCredById = await credentialWallet.findById('otherId');
  expect(!!emptyCredById).to.be.false;

  // findByContextType
  const [credByContextType] = await credentialWallet.findByContextType('context1', 'type1_2');
  expect(credByContextType.id).to.equal(cred1.id);

  const queries: {
    query: ProofQuery;
    expected: W3CCredential[];
  }[] = [
    {
      query: {
        allowedIssuers: ['*'],
        type: 'type1_1'
      },
      expected: [cred1]
    },
    {
      query: {
        allowedIssuers: ['issuer3', 'issuer2']
      },
      expected: [cred3, cred2]
    },
    {
      query: {
        allowedIssuers: ['*'],
        context: 'context3_2',
        type: 'type3_3',
        schema: 'credentialSchemaId'
      },
      expected: [cred3]
    },
    {
      query: {
        allowedIssuers: ['*'],
        context: 'context2_2',
        type: 'type2_3',
        schema: 'credentialSchemaId',
        credentialSubject: {
          birthday: {
            $gt: 20000100
          }
        }
      },
      expected: [cred2]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          birthday: {
            $lt: 20000102
          }
        }
      },
      expected: [cred1, cred2]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          countryCode: {
            $eq: 120
          }
        }
      },
      expected: [cred3]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          countryCode: {
            $in: [11, 120]
          }
        }
      },
      expected: [cred3]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          countryCode: {
            $nin: [11, 111]
          }
        }
      },
      expected: [cred3]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          countOfFines: {
            $nin: [1, 2]
          }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          countOfFines: {
            $in: [0]
          }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          countOfFines: {
            $eq: 0
          }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          countOfFines: {
            $eq: 1
          }
        }
      },
      expected: []
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          countOfFines: {}
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.name': { $eq: 'Spain' }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.insured': { $eq: 'true' }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.insured': { $eq: 1 }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.insured': { $eq: true }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.insured': { $ne: 'false' }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.insured': { $ne: 0 }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.insured': { $ne: false }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.hasOwnPackage': { $eq: 'false' }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.hasOwnPackage': { $eq: 0 }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.hasOwnPackage': { $eq: false }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.name': { $eq: 'Spain' },
          countOfFines: {
            $eq: 0
          }
        }
      },
      expected: [cred4]
    },
    {
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          'country.name': { $eq: 'Spain' },
          countOfFines: {
            $eq: 1
          },
          'country.hasOwnPackage': { $eq: 0 }
        }
      },
      expected: []
    },
    {
      query: {
        allowedIssuers: undefined
      },
      expected: [cred1, cred2, cred3, cred4]
    },
    {
      query: {
        allowedIssuers: ['issuer1', '*']
      },
      expected: [cred1, cred2, cred3, cred4]
    }
  ];

  for (const item of queries) {
    const creds = await credentialWallet.findByQuery(item.query);
    const expectedIds = item.expected.map(({ id }) => id);
    const credsIds = creds.map(({ id }) => id);
    expect(credsIds).to.have.members(expectedIds);
  }

  // operator error
  const query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      countryCode: {
        $custom: [11, 111]
      }
    }
  };
  await expect(credentialWallet.findByQuery(query)).rejects.toThrow(
    SearchError.NotDefinedComparator
  );

  // invalid query
  const query2 = {
    allowedIssuers: ['*'],
    someProp: ''
  };
  await expect(credentialWallet.findByQuery(query2)).rejects.toThrow(
    SearchError.NotDefinedQueryKey
  );

  // remove credential error
  await expect(credentialWallet.remove('unknownId')).rejects.toThrow(
    'item not found to delete: unknownId'
  );

  await credentialWallet.remove('test1');
  const finalList = await credentialWallet.list();
  expect(finalList.length).to.equal(3);
};

describe('credential-wallet', () => {
  it('run in memory with 3 credential', async () => {
    const storage = {
      credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>())
    } as unknown as IDataStorage;
    await credentialFlow(storage);
  });
  it('run in local storage with 4 credential', async () => {
    const storage = {
      credential: new CredentialStorage(
        new BrowserDataSource<W3CCredential>(CredentialStorage.storageKey)
      )
    } as unknown as IDataStorage;
    await credentialFlow(storage);
  });

  it('Backward compatibility test - hash-as-string-ints', async () => {
    const credentialStorage = new CredentialStorage(mockedDataSource);

    const cred = await credentialStorage.findCredentialById(cred1.id);
    expect(cred?.proof).not.to.be.undefined;
    const proof = (cred?.proof as unknown[])[0] as Iden3SparseMerkleTreeProof;

    expect(proof.coreClaim.getSchemaHash().bigInt().toString()).to.equal(
      SchemaHash.authSchemaHash.bigInt().toString()
    );
    expect(proof.mtp.allSiblings()).to.deep.equal(mockedProof.mtp.allSiblings());
    expect(proof.issuerData.state.claimsTreeRoot.bigInt().toString()).to.equal(
      mockedProof.issuerData.state.claimsTreeRoot.bigInt().toString()
    );
  });

  it('Credential search by query', async () => {
    const credentialStorage = new CredentialStorage(new InMemoryDataSource<W3CCredential>());

    const credToTest = W3CCredential.fromJSON(
      JSON.parse(`{
    "id": "urn:uuid:9c421fdc-16cc-11f0-9a77-0a58a9feac02",
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
        "ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15"
    ],
    "type": [
        "VerifiableCredential",
        "operators"
    ],
    "credentialSubject": {
        "boolean1": true,
        "date-time1": "2025-04-09T15:48:08.800+02:00",
        "id": "did:iden3:privado:main:2SeEkMwamyzKWr3aGUT9AvDjiQK4rMEAZbUZgEzP72",
        "integer1": 5342,
        "non-negative-integer1": "32423",
        "number1": 1234,
        "positive-integer1": "12345555",
        "string1": "testData",
        "type": "operators"
    },
    "issuer": "did:iden3:polygon:amoy:xJNwv94NrHy1xXU3poKTRL24WJEXmkEggwbBWy6gu",
    "credentialSchema": {
        "id": "https://ipfs.io/ipfs/QmWDmZQrtvidcNK7d6rJwq7ZSi8SUygJaKepN7NhKtGryc",
        "type": "JsonSchema2023"
    },
    "credentialStatus": {
        "id": "https://issuer-node-core-api-testing.privado.id/v2/agent",
        "revocationNonce": 978385127,
        "type": "Iden3commRevocationStatusV1.0"
    },
    "issuanceDate": "2025-04-11T12:00:49.921271223Z",
    "proof": [
        {
            "issuerData": {
                "id": "did:iden3:polygon:amoy:xJNwv94NrHy1xXU3poKTRL24WJEXmkEggwbBWy6gu",
                "state": {
                    "claimsTreeRoot": "1483789a545832ba69d54ed1691ce758f9b8297542b2749f6fa4786e74fbe80e",
                    "value": "310ccc3f33fbbfd50da56755e442896065b388e9c4adadd644588eaa6e171b1a",
                    "rootOfRoots": "0000000000000000000000000000000000000000000000000000000000000000",
                    "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000"
                },
                "mtp": {
                    "existence": true,
                    "siblings": []
                },
                "authCoreClaim": "cca3371a6cb1b715004407e325bd993c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000079adcc5f988e5e6fb7d04adcb5e07afdd53babf34acdb75aa51ac8e1ddc0ee20211c823ff2b1ee62e988fba84247930add22fbbc2fcc4f1b4fd3a50e07f9e6170000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "credentialStatus": {
                    "id": "https://issuer-node-core-api-testing.privado.id/v2/agent",
                    "revocationNonce": 0,
                    "type": "Iden3commRevocationStatusV1.0"
                }
            },
            "type": "BJJSignature2021",
            "coreClaim": "637056ad190ec7df5fef1345fda35e1f2200000000000000000000000000000001a16e78ba913717bc15cbe326e236c7eef4f9201582b50e145cb669139c0d0068fbed6c1ddf63a9a4eaa0d4a577b770a5acaf37a542cf86cb6e9e93e9b608020000000000000000000000000000000000000000000000000000000000000000e7f8503a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "b17ca01ab223b6281e0b22b4f8945729ffb39eaf4b2a0db59548db7ab0df092e423dfc2472cce2e269a80a4d37bb520eda59ab3a0adfae043caa38a464869505"
        }
    ]
}`)
    );
    await credentialStorage.saveCredential(credToTest);

    // positive-integer

    let cred = await credentialStorage.findCredentialsByQuery({
      allowedIssuers: ['*'],
      context: 'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15',
      credentialSubject: {
        'positive-integer1': {
          $gt: '2'
        }
      },
      groupId: 1745320529,
      type: 'operators'
    });
    expect(1).to.be.equal(cred.length);
    expect(cred[0].credentialSubject['positive-integer1']).to.be.equal('12345555');

    //number

    cred = await credentialStorage.findCredentialsByQuery({
      allowedIssuers: ['*'],
      context: 'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15',
      credentialSubject: {
        number1: {
          $gt: 1
        }
      },
      groupId: 1745320529,
      type: 'operators'
    });
    expect(1).to.be.equal(cred.length);
    expect(cred[0].credentialSubject['number1']).to.be.equal(1234);

    //boolean

    cred = await credentialStorage.findCredentialsByQuery({
      allowedIssuers: ['*'],
      context: 'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15',
      credentialSubject: {
        boolean1: {
          $eq: true
        }
      },
      groupId: 1745320529,
      type: 'operators'
    });
    expect(1).to.be.equal(cred.length);
    expect(cred[0].credentialSubject['boolean1']).to.be.equal(true);

    //datetime lt

    cred = await credentialStorage.findCredentialsByQuery({
      allowedIssuers: ['*'],
      context: 'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15',
      credentialSubject: {
        'date-time1': {
          $lt: '2027-04-09T15:48:08.800+02:00'
        }
      },
      groupId: 1745320529,
      type: 'operators'
    });
    expect(1).to.be.equal(cred.length);
    expect(cred[0].credentialSubject['date-time1']).to.be.equal('2025-04-09T15:48:08.800+02:00');

    // datetime gt
    cred = await credentialStorage.findCredentialsByQuery({
      allowedIssuers: ['*'],
      context: 'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15',
      credentialSubject: {
        'date-time1': {
          $gt: '2022-04-09T15:48:08.800+02:00'
        }
      },
      groupId: 1745320529,
      type: 'operators'
    });
    expect(1).to.be.equal(cred.length);
    expect(cred[0].credentialSubject['date-time1']).to.be.equal('2025-04-09T15:48:08.800+02:00');

    // datetime YYYY-MM-DD
    cred = await credentialStorage.findCredentialsByQuery({
      allowedIssuers: ['*'],
      context: 'ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15',
      credentialSubject: {
        'date-time1': {
          $gt: '2022-04-01'
        }
      },
      groupId: 1745320529,
      type: 'operators'
    });
    expect(1).to.be.equal(cred.length);
    expect(cred[0].credentialSubject['date-time1']).to.be.equal('2025-04-09T15:48:08.800+02:00');
  });
});


describe.only('credential-wallet-operators', () => {
  it('datetime-between', async () => {
    const storage = {
      credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>())
    } as unknown as IDataStorage;

    const cred = W3CCredential.fromJSON( JSON.parse(`{
    "id": "urn:uuid:79db702b-08ae-11f0-bf3e-0a58a9feac02",
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
        "ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15"
    ],
    "type": [
        "VerifiableCredential",
        "operators"
    ],
    "credentialSubject": {
        "boolean1": true,
        "date-time1": "2025-03-27T00:00:00.000+02:00",
        "id": "did:iden3:privado:main:2SahfWEAtkmt5P8Rjif4bUwKR1nx8aWbAnb4j2WeQE",
        "integer1": 1,
        "non-negative-integer1": "1",
        "number1": 2.3,
        "positive-integer1": "1",
        "string1": "test",
        "type": "operators"
    },
    "issuer": "did:iden3:polygon:amoy:xHV7UUYn7tx3KyzcyXTcnLjvAA9tJRVWCVGErQFRV",
    "credentialSchema": {
        "id": "ipfs://QmWDmZQrtvidcNK7d6rJwq7ZSi8SUygJaKepN7NhKtGryc",
        "type": "JsonSchema2023"
    },
    "credentialStatus": {
        "id": "https://rhs-staging.polygonid.me/node?state=9d918246529c325db5592a6b286fb667876e8e13164658eb803e8da41024bb13",
        "revocationNonce": 1914156308,
        "statusIssuer": {
            "id": "https://issuer-node-core-api-testing.privado.id/v2/agent",
            "revocationNonce": 1914156308,
            "type": "Iden3commRevocationStatusV1.0"
        },
        "type": "Iden3ReverseSparseMerkleTreeProof"
    },
    "issuanceDate": "2025-03-24T12:49:51.0251603Z",
    "proof": [
        {
            "issuerData": {
                "id": "did:iden3:polygon:amoy:xHV7UUYn7tx3KyzcyXTcnLjvAA9tJRVWCVGErQFRV",
                "state": {
                    "claimsTreeRoot": "dd80f4cbef4290fdb5aa73ae95d9c65ea421b766a9d335ad1204255386851d1c",
                    "value": "1d633c6d18e8101341f67da2d2e4448244d5e75f230080d8ae802781e8220d19",
                    "rootOfRoots": "0000000000000000000000000000000000000000000000000000000000000000",
                    "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000"
                },
                "mtp": {
                    "existence": true,
                    "siblings": []
                },
                "authCoreClaim": "cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f4223360d1687fa64ab33ee8ce4ed1c03cba411d6205e418b844be5cbe7be5041468649e0d60e2294f9f5e866b8670d198c0f3110b2f093317ba368e6264b91d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "credentialStatus": {
                    "id": "https://rhs-staging.polygonid.me/node?state=1d633c6d18e8101341f67da2d2e4448244d5e75f230080d8ae802781e8220d19",
                    "revocationNonce": 0,
                    "statusIssuer": {
                        "id": "https://issuer-node-core-api-testing.privado.id/v2/agent",
                        "revocationNonce": 0,
                        "type": "Iden3commRevocationStatusV1.0"
                    },
                    "type": "Iden3ReverseSparseMerkleTreeProof"
                }
            },
            "type": "BJJSignature2021",
            "coreClaim": "637056ad190ec7df5fef1345fda35e1f2200000000000000000000000000000001a1209526ff82be3f4c1588e4ebfbc99ec4fefa2d771a81fddc3509436a0f0099a4fb9df56c5e91d077eb30717c6c720239f0c57b8c0e2b61885ac101fff424000000000000000000000000000000000000000000000000000000000000000014b5177200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "f7f1b7dbc6fbeefe68482da24d182171911fa6a28c752a21fd0ff96e17a7161e2bba9eb5046a7334a1418a21c945b4290e92eb07c9a9f478772af0ae9ac3fa04"
        }
    ]
    }`));

   await storage.credential.saveCredential(cred);
   const list = await storage.credential.findCredentialsByQuery({
        "allowedIssuers": [
            "*"
        ],
        "context": "ipfs://Qmb48rJ5SiQMLXjVkaLQB6fWbT7C8LK75MHsCoHv8GAc15",
        "credentialSubject": {
            "date-time1": {
                "$between": [
                    "2022-11-15T12:28:35.100+01:00",
                    "2026-11-15T12:28:35.100+01:00"
                ]
            }
        },
        "type": "operators"
    })
  expect( list.length).to.equal(1);
  });
});
