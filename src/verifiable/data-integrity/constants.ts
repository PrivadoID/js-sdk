export const IDEN3_JWZ_RDFC_2026 = 'iden3-jwz-rdfc-2026';
export const DATA_INTEGRITY_PROOF_TYPE = 'DataIntegrityProof';
export const IDEN3_JWZ_PROOF_PURPOSE = 'assertionMethod';
export const IDEN3_JWZ_STATE_INFO_FRAGMENT = '#state-info';
export const IDEN3_JWZ_PROOF_VALUE_PREFIX = 'u';

export const IDEN3_JWZ_CIRCUIT_HEADERS: Readonly<Record<string, string>> = {
  'authV3-8-32':
    '{"alg":"groth16","circuitId":"authV3-8-32","crit":["circuitId"],"typ":"application/iden3-zkp-json"}'
};

export const IDEN3_JWZ_MAX_CREATED_AHEAD_SECONDS = 300;
export const IDEN3_JWZ_MAX_ROOT_REPLACED_BEFORE_CREATED_SECONDS = 300;

export const IDEN3_JWZ_PROOF_MEMBERS = [
  'type',
  'cryptosuite',
  'created',
  'expires',
  'verificationMethod',
  'proofPurpose',
  'proofValue'
] as const;

export type Iden3JwzProofOptions = {
  type: typeof DATA_INTEGRITY_PROOF_TYPE;
  cryptosuite: typeof IDEN3_JWZ_RDFC_2026;
  created: string;
  expires: string;
  verificationMethod: string;
  proofPurpose: typeof IDEN3_JWZ_PROOF_PURPOSE;
};

export type Iden3JwzProof = Iden3JwzProofOptions & { proofValue: string };

export type ProofLifetime = { minSeconds: number; maxSeconds: number };
