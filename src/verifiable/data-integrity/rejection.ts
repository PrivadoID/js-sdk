export const IDEN3_JWZ_PROOF_REASONS = [
  'proof_malformed',
  'proof_expired',
  'document_malformed',
  'proof_hash_mismatch',
  'proof_invalid',
  'proof_signer_mismatch',
  'state_superseded',
  'state_unavailable'
] as const;

export type Iden3JwzProofReason = (typeof IDEN3_JWZ_PROOF_REASONS)[number];

export class Iden3JwzProofRejection extends Error {
  readonly reason: Iden3JwzProofReason;
  readonly detail: string;

  constructor(reason: Iden3JwzProofReason, detail: string) {
    super(`${detail} (${reason})`);
    this.name = 'Iden3JwzProofRejection';
    this.reason = reason;
    this.detail = detail;
  }
}
