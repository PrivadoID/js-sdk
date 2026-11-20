/**
 * State verification options
 */
export type StateVerificationOpts = {
  // acceptedStateTransitionDelay is the period of time in milliseconds that a revoked state remains valid.
  acceptedStateTransitionDelay?: number;
  referenceTime?: Date;
};
