import { describe, expect, it } from 'vitest';
import {
  buildDIDFromEthAddress,
  calculateMultiRequestId,
  buildDIDFromEthPubKey,
  CACHE_KEY_VERSION,
  CircuitId,
  createZkpRequestCacheKey,
  JsonDocumentObject,
  mergeObjects,
  ProofType,
  ZeroKnowledgeProofRequest
} from '../../src';
import { Blockchain, buildDIDType, DID, DidMethod, NetworkId } from '@iden3/js-iden3-core';
import * as uuid from 'uuid';

describe('merge credential subjects to create query', () => {
  it('should merge two valid JsonDocumentObjects correctly', () => {
    const testCases: JsonDocumentObject[] = [
      {
        subj1: {
          documentType: {
            $eq: 25
          },
          position: {
            $eq: 'boss'
          },
          salary: {
            $gte: 2
          }
        },

        subj2: {
          documentType: {
            $eq: 26
          },
          position: {
            $ne: 'employee'
          },
          salary: {
            $gte: 10
          },
          hireDate: {
            $eq: '2023-12-11'
          }
        },

        expectedResult: {
          documentType: {
            $eq: [25, 26]
          },
          position: {
            $eq: 'boss',
            $ne: 'employee'
          },
          salary: {
            $gte: [2, 10]
          },
          hireDate: {
            $eq: '2023-12-11'
          }
        }
      },

      {
        subj1: {
          documentType: {
            $eq: 25,
            $ne: 26,
            $gt: 27,
            $lt: 28
          },
          position: {
            $eq: 'boss',
            $ne: 'bad boy'
          }
        },

        subj2: {
          documentType: {
            $eq: 27,
            $ne: 30
          },
          position: {
            $eq: 'employee'
          },
          salary: {
            $gte: 10
          },
          hireDate: {
            $eq: '2023-12-11'
          }
        },

        expectedResult: {
          documentType: {
            $eq: [25, 27],
            $ne: [26, 30],
            $gt: 27,
            $lt: 28
          },
          position: {
            $eq: ['boss', 'employee'],
            $ne: 'bad boy'
          },
          salary: {
            $gte: 10
          },
          hireDate: {
            $eq: '2023-12-11'
          }
        }
      },
      {
        subj2: {
          hireDate: {
            $eq: '2023-12-11'
          },
          salary: {
            $gte: 3
          },
          position: {
            $eq: 'boss',
            $ne: 'badJoke'
          }
        },

        subj1: {
          documentType: {
            $eq: 1
          },
          position: {
            $ne: 'employee'
          },
          salary: {
            $gte: 2
          }
        },

        expectedResult: {
          documentType: {
            $eq: 1
          },
          position: {
            $eq: 'boss',
            $ne: ['employee', 'badJoke']
          },
          salary: {
            $gte: [2, 3]
          },
          hireDate: {
            $eq: '2023-12-11'
          }
        }
      }
    ];

    for (const testCase of testCases) {
      expect(
        mergeObjects(testCase.subj1 as JsonDocumentObject, testCase.subj2 as JsonDocumentObject)
      ).to.deep.equal(testCase.expectedResult);
    }
  });
});

describe('build did from ethereum public key', () => {
  it('should build did from ethereum public key correctly', async () => {
    const pubKeyHexEth =
      '8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5';
    const didType = buildDIDType(DidMethod.Iden3, Blockchain.Polygon, NetworkId.Amoy);
    const did = buildDIDFromEthPubKey(didType, pubKeyHexEth);

    expect(did.string()).to.equal(
      'did:iden3:polygon:amoy:x6x5sor7zpycB7z7Q9348dXJxZ9s5b9AgmPeSccZz'
    );
  });
});

describe('build did from ethereum address', () => {
  it('should build did from ethereum address correctly', async () => {
    const ethAddress = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
    const didType = buildDIDType(DidMethod.Iden3, Blockchain.Polygon, NetworkId.Amoy);
    const did = buildDIDFromEthAddress(didType, ethAddress);

    expect(did.string()).to.equal(
      'did:iden3:polygon:amoy:x6x5sor7zpycB7z7Q9348dXJxZ9s5b9AgmPeSccZz'
    );
  });
});

describe('createZkpRequestCacheKey', () => {
  const profileDID = DID.parse('did:iden3:polygon:amoy:x6x5sor7zpycB7z7Q9348dXJxZ9s5b9AgmPeSccZz');
  const credId = uuid.v4();
  it('produces the same key for same request with different property order', () => {
    const r1: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      query: {
        context: 'https://example.com/ctx',
        type: 'EmailCredential',
        proofType: ProofType.BJJSignature,
        skipClaimRevocationCheck: false,
        allowedIssuers: ['did:issuer:1', 'did:issuer:2'],
        credentialSubject: {
          email: {}
        }
      },
      params: {
        nullifierSessionId: 'session-1'
      }
    };

    const r2: ZeroKnowledgeProofRequest = {
      params: {
        nullifierSessionId: 'session-1'
      },
      query: {
        credentialSubject: {
          email: {}
        },
        allowedIssuers: ['did:issuer:2', 'did:issuer:1'],
        skipClaimRevocationCheck: false,
        proofType: ProofType.BJJSignature,
        type: 'EmailCredential',
        context: 'https://example.com/ctx'
      },
      optional: false,
      circuitId: CircuitId.AtomicQueryV3,
      id: 1
    };

    const key1 = createZkpRequestCacheKey(CACHE_KEY_VERSION.V1, profileDID, r1, credId);
    const key2 = createZkpRequestCacheKey(CACHE_KEY_VERSION.V1, profileDID, r2, credId);

    expect(key1).to.equal(key2);
  });

  it('produces different key for different request', () => {
    const r1: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      query: {
        context: 'https://example.com/ctx',
        type: 'EmailCredential',
        proofType: ProofType.BJJSignature,
        skipClaimRevocationCheck: false,
        allowedIssuers: ['did:issuer:1', 'did:issuer:2'],
        credentialSubject: {
          email: {}
        }
      },
      params: {
        nullifierSessionId: 'session-1'
      }
    };

    const r2: ZeroKnowledgeProofRequest = {
      params: {
        nullifierSessionId: 'session-1'
      },
      query: {
        credentialSubject: {
          email: {
            $eq: 'me@me.com'
          }
        },
        allowedIssuers: ['did:issuer:1', 'did:issuer:2'],
        skipClaimRevocationCheck: false,
        proofType: ProofType.BJJSignature,
        type: 'EmailCredential',
        context: 'https://example.com/ctx'
      },
      optional: false,
      circuitId: CircuitId.AtomicQueryV3,
      id: 1
    };

    const key1 = createZkpRequestCacheKey(CACHE_KEY_VERSION.V1, profileDID, r1, credId);
    const key2 = createZkpRequestCacheKey(CACHE_KEY_VERSION.V1, profileDID, r2, credId);

    expect(key1).not.to.equal(key2);
  });
});

describe('calculateMultiRequestId', () => {
  const creator = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

  it('matches the Verifier contract abi.encode hash', () => {
    expect(calculateMultiRequestId([1n, 2n], [3n], creator)).toBe(
      66503760665935913562240386324712378963640632111451708259404193967361426232039n
    );
    expect(calculateMultiRequestId([1n], [2n, 3n], creator)).toBe(
      91988463783048594944755115311468848995689516967739366854287315972498619061768n
    );
  });

  it('different requestIds/groupIds splits give different ids', () => {
    // With abi.encodePacked both splits packed to the same bytes and collided.
    expect(calculateMultiRequestId([1n, 2n], [3n], creator)).not.toBe(
      calculateMultiRequestId([1n], [2n, 3n], creator)
    );
  });
});
