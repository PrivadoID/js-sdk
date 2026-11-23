import { AtomicQueryMTPV2OnChainPubSignals } from './atomic-query-mtp-v2-on-chain';
import { AtomicQuerySigV2OnChainPubSignals } from './atomic-query-sig-v2-on-chain';
import { AtomicQueryV3OnChainPubSignals } from './atomic-query-v3-on-chain';
import { AuthV2PubSignals } from './auth-v2';
import { AuthV3PubSignals } from './auth-v3';
import { IUnmarshallerPubSignals } from './common';
import { Operators, QueryOperators } from './comparer';
import { CircuitId } from './models';
import { ProofType } from '../verifiable';

const allOperations = Object.values(QueryOperators);
const v2Operations = [
  Operators.NOOP,
  Operators.EQ,
  Operators.LT,
  Operators.GT,
  Operators.IN,
  Operators.NIN,
  Operators.NE,
  Operators.SD
];
const v2OnChainOperations = [
  Operators.EQ,
  Operators.LT,
  Operators.GT,
  Operators.IN,
  Operators.NIN,
  Operators.NE
];

const noQueriesValidation = { validation: { maxQueriesCount: 0, supportedOperations: [] } };
const credentialAtomicQueryV2Validation = {
  validation: { maxQueriesCount: 1, supportedOperations: v2Operations }
};
const credentialAtomicQueryV2OnChainValidation = {
  validation: { maxQueriesCount: 1, supportedOperations: v2OnChainOperations }
};
const credentialAtomicQueryV3Validation = {
  validation: { maxQueriesCount: 1, supportedOperations: allOperations }
};

export type CircuitSubversion = {
  mtLevel?: number;
  mtLevelClaim?: number;
  mtLevelOnChain?: number;
  queryCount?: number;
  targetCircuitId: CircuitId;
};

export type CircuitValidatorItem = {
  validation: { maxQueriesCount: number; supportedOperations: Operators[] };
  subVersions?: CircuitSubversion[];
  unmarshaller?: new (opts?: {
    mtLevel?: number;
    mtLevelClaim?: number;
    mtLevelOnChain?: number;
  }) => IUnmarshallerPubSignals;
  mtLevel?: number;
  mtLevelClaim?: number;
  mtLevelOnChain?: number;
};

export const circuitValidator: {
  [k in CircuitId]: CircuitValidatorItem;
} = {
  [CircuitId.AtomicQueryMTPV2]: credentialAtomicQueryV2Validation,
  [CircuitId.AtomicQueryMTPV2OnChain]: {
    ...credentialAtomicQueryV2OnChainValidation,
    unmarshaller: AtomicQueryMTPV2OnChainPubSignals
  },
  [CircuitId.AtomicQuerySigV2]: credentialAtomicQueryV2Validation,
  [CircuitId.AtomicQuerySigV2OnChain]: {
    ...credentialAtomicQueryV2OnChainValidation,
    unmarshaller: AtomicQuerySigV2OnChainPubSignals
  },
  [CircuitId.AtomicQueryV3]: credentialAtomicQueryV3Validation,
  [CircuitId.AtomicQueryV3OnChain]: {
    ...credentialAtomicQueryV3Validation,
    unmarshaller: AtomicQueryV3OnChainPubSignals
  },
  [CircuitId.AuthV2]: { ...noQueriesValidation, unmarshaller: AuthV2PubSignals },
  [CircuitId.AuthV3]: { ...noQueriesValidation, unmarshaller: AuthV3PubSignals },
  [CircuitId.AuthV3_8_32]: {
    ...noQueriesValidation,
    unmarshaller: AuthV3PubSignals,
    mtLevel: 8,
    mtLevelClaim: 32
  },
  [CircuitId.StateTransition]: noQueriesValidation,
  [CircuitId.LinkedMultiQuery10]: {
    validation: { maxQueriesCount: 10, supportedOperations: allOperations }
  },

  [CircuitId.AtomicQueryV3Stable]: {
    ...credentialAtomicQueryV3Validation,
    subVersions: [
      {
        mtLevel: 16,
        mtLevelClaim: 16,
        targetCircuitId: (CircuitId.AtomicQueryV3Stable + '-16-16-64') as CircuitId
      }
    ]
  },
  [CircuitId.AtomicQueryV3OnChainStable]: {
    ...credentialAtomicQueryV3Validation,
    subVersions: [
      {
        mtLevel: 16,
        mtLevelClaim: 16,
        mtLevelOnChain: 32,
        targetCircuitId: (CircuitId.AtomicQueryV3OnChainStable + '-16-16-64-16-32') as CircuitId
      }
    ],
    unmarshaller: AtomicQueryV3OnChainPubSignals
  },
  [CircuitId.LinkedMultiQueryStable]: {
    validation: { maxQueriesCount: 10, supportedOperations: allOperations },
    subVersions: [
      {
        queryCount: 3,
        targetCircuitId: (CircuitId.LinkedMultiQueryStable + '3') as CircuitId
      },
      {
        queryCount: 5,
        targetCircuitId: (CircuitId.LinkedMultiQueryStable + '5') as CircuitId
      }
    ]
  }
};

export const getCircuitIdsWithSubVersions = (filterCircuitIds?: CircuitId[]): CircuitId[] => {
  return [
    ...Object.keys(circuitValidator).reduce((acc, key) => {
      const circuitId = key as CircuitId;

      const applyFilter = filterCircuitIds && filterCircuitIds.length > 0;
      // if filterCircuitIds is provided, only include circuits that are in the filterCircuitIds, else include all circuits
      if (applyFilter && !filterCircuitIds.includes(circuitId)) {
        return acc;
      }

      acc.add(circuitId);
      const targetCircuitIds =
        circuitValidator[circuitId]?.subVersions?.map((subversion) => subversion.targetCircuitId) ??
        [];
      targetCircuitIds.forEach((id) => acc.add(id));
      return acc;
    }, new Set<CircuitId>())
  ];
};

export const getGroupedCircuitIdsWithSubVersions = (filterCircuitId: CircuitId): CircuitId[] => {
  for (const key of Object.keys(circuitValidator)) {
    const circuitId = key as CircuitId;
    const subVersions = circuitValidator[circuitId]?.subVersions ?? [];
    const group = [...subVersions.map((subversion) => subversion.targetCircuitId), circuitId];

    if (group.includes(filterCircuitId)) {
      return group;
    }
  }

  const validatorItem = circuitValidator[filterCircuitId];
  if (validatorItem) {
    const subVersions = validatorItem.subVersions ?? [];
    return [...subVersions.map((subversion) => subversion.targetCircuitId), filterCircuitId];
  }

  return [filterCircuitId];
};

export const getUnmarshallerForCircuitId = (
  circuitIdToFind: CircuitId
):
  | {
      unmarshaller: new (opts?: {
        mtLevel?: number;
        mtLevelClaim?: number;
        mtLevelOnChain?: number;
      }) => IUnmarshallerPubSignals;
      opts?: { mtLevel?: number; mtLevelClaim?: number; mtLevelOnChain?: number };
    }
  | undefined => {
  for (const key of Object.keys(circuitValidator)) {
    const circuitId = key as CircuitId;

    if (circuitId === circuitIdToFind && circuitValidator[circuitId].unmarshaller) {
      return {
        unmarshaller: circuitValidator[circuitId].unmarshaller,
        opts:
          circuitValidator[circuitId].mtLevel ||
          circuitValidator[circuitId].mtLevelClaim ||
          circuitValidator[circuitId].mtLevelOnChain
            ? {
                mtLevel: circuitValidator[circuitId].mtLevel,
                mtLevelClaim: circuitValidator[circuitId].mtLevelClaim,
                mtLevelOnChain: circuitValidator[circuitId].mtLevelOnChain
              }
            : undefined
      };
    }

    const subVersions = circuitValidator[circuitId]?.subVersions ?? [];
    if (subVersions.length > 0) {
      const subVersion = subVersions.find(
        (subversion) => subversion.targetCircuitId === circuitIdToFind
      );
      if (subVersion && circuitValidator[circuitId].unmarshaller) {
        return {
          unmarshaller: circuitValidator[circuitId].unmarshaller,
          opts:
            subVersion.mtLevel || subVersion.mtLevelClaim || subVersion.mtLevelOnChain
              ? {
                  mtLevel: subVersion.mtLevel,
                  mtLevelClaim: subVersion.mtLevelClaim,
                  mtLevelOnChain: subVersion.mtLevelOnChain
                }
              : undefined
        };
      }
    }
  }
};

/**
 * Returns the credential proof type that a circuit is forced to use: Sig V2 circuits always use
 * the signature, MTP V2 circuits the MTP, and V3 circuits whatever the query requests.
 * Returns undefined when the circuit doesn't force one, in which case the MTP is used if the
 * credential has one, and the signature otherwise.
 *
 * @param {string} circuitId - circuit of the proof request
 * @param {{ proofType?: string }} [query] - query of the proof request
 * @returns {ProofType | undefined}
 */
export const getRequiredProofType = (
  circuitId: string,
  query?: { proofType?: string }
): ProofType | undefined => {
  switch (circuitId) {
    case CircuitId.AtomicQuerySigV2:
    case CircuitId.AtomicQuerySigV2OnChain:
      return ProofType.BJJSignature;
    case CircuitId.AtomicQueryMTPV2:
    case CircuitId.AtomicQueryMTPV2OnChain:
      return ProofType.Iden3SparseMerkleTreeProof;
    case CircuitId.AtomicQueryV3:
    case CircuitId.AtomicQueryV3OnChain:
    case CircuitId.AtomicQueryV3Stable:
    case CircuitId.AtomicQueryV3OnChainStable:
      return Object.values(ProofType).find((proofType) => proofType === query?.proofType);
    default:
      return undefined;
  }
};
