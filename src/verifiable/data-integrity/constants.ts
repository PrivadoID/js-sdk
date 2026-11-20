export const IDEN3_JWZ_RDFC_2026 = 'iden3-jwz-rdfc-2026';
export const DATA_INTEGRITY_PROOF_TYPE = 'DataIntegrityProof';

export type Iden3JwzProofOptions = {
  type: typeof DATA_INTEGRITY_PROOF_TYPE;
  cryptosuite: typeof IDEN3_JWZ_RDFC_2026;
  created: string;
  expires: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
};

export type Iden3JwzProof = Iden3JwzProofOptions & { proofValue: string };
