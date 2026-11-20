import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CircuitId,
  ICredentialWallet,
  IIdentityWallet,
  IStateStorage,
  ProofService,
  RootInfo
} from '../../src';
import { MOCK_STATE_STORAGE } from '../helpers';

const replacedAt = new Date('2026-01-01T00:00:00Z');
const minute = 60 * 1000;
const pubSignals = [
  '19229084873704550357232887142774605442297337229176579229011342091594174977',
  '18002012209647081897381727526816133703517479231060443051372283566974948295823',
  '1243904711429961858774220647610724273798918457991486031567244100767259239747'
];
const gistRoot = BigInt(pubSignals[2]);

const createProofService = (info: Partial<RootInfo>) => {
  const stateStorage = {
    ...MOCK_STATE_STORAGE,
    getGISTRootInfo: async (): Promise<RootInfo> => ({
      root: gistRoot,
      replacedByRoot: 1n,
      createdAtTimestamp: 1n,
      replacedAtTimestamp: BigInt(replacedAt.getTime() / 1000),
      createdAtBlock: 1n,
      replacedAtBlock: 1n,
      ...info
    })
  } as IStateStorage;
  return new ProofService(
    {} as IIdentityWallet,
    {} as ICredentialWallet,
    {} as never,
    stateStorage
  );
};

describe('verifyState with a replaced GIST root', () => {
  const opts = { acceptedStateTransitionDelay: 5 * minute };

  it('accepts the state when the reference time is inside the accepted delay', async () => {
    const referenceTime = new Date(replacedAt.getTime() + 4 * minute);
    const proofService = createProofService({});
    await expect(
      proofService.verifyState(CircuitId.AuthV2, pubSignals, { ...opts, referenceTime })
    ).resolves.toBe(true);
  });

  it('refuses the state when the reference time is outside the accepted delay', async () => {
    const referenceTime = new Date(replacedAt.getTime() + 6 * minute);
    const proofService = createProofService({});
    await expect(
      proofService.verifyState(CircuitId.AuthV2, pubSignals, { ...opts, referenceTime })
    ).rejects.toThrow('global state is outdated');
  });

  describe('without a reference time', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('accepts the state when Date.now is inside the accepted delay', async () => {
      vi.spyOn(Date, 'now').mockReturnValue(replacedAt.getTime() + 4 * minute);
      const proofService = createProofService({});
      await expect(proofService.verifyState(CircuitId.AuthV2, pubSignals, opts)).resolves.toBe(
        true
      );
    });

    it('refuses the state when Date.now is outside the accepted delay', async () => {
      vi.spyOn(Date, 'now').mockReturnValue(replacedAt.getTime() + 6 * minute);
      const proofService = createProofService({});
      await expect(proofService.verifyState(CircuitId.AuthV2, pubSignals, opts)).rejects.toThrow(
        'global state is outdated'
      );
    });
  });

  it('accepts a GIST root that is not replaced when the reference time is old', async () => {
    const proofService = createProofService({ replacedByRoot: 0n, replacedAtTimestamp: 0n });
    await expect(
      proofService.verifyState(CircuitId.AuthV2, pubSignals, {
        ...opts,
        referenceTime: new Date(0)
      })
    ).resolves.toBe(true);
  });
});
