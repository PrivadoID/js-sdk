/**
 * State verification options
 */
export type StateVerificationOpts = {
  // acceptedStateTransitionDelay is the period of time in milliseconds that a revoked state remains valid.
  acceptedStateTransitionDelay?: number;
  // referenceTime is the time that the replaced time of a GIST root is compared with. Default: now.
  referenceTime?: Date;
};
