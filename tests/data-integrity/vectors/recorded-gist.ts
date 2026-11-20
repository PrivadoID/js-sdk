import { GistRootReader, RootInfo } from '../../../src';

export type RecordedRoot = {
  root: string;
  replacedByRoot: string;
  createdAtTimestamp: string;
  replacedAtTimestamp: string;
  createdAtBlock: string;
  replacedAtBlock: string;
};

export const recordedGistReader = (gist: RecordedRoot[], asOf: number): GistRootReader => {
  const at = BigInt(asOf);
  return {
    getGISTRootInfo: async (root: bigint): Promise<RootInfo> => {
      const found = gist.find(
        (recorded) => BigInt(recorded.root) === root && BigInt(recorded.createdAtTimestamp) <= at
      );
      if (!found) {
        throw new Error('Root does not exist');
      }
      const replacedAt = BigInt(found.replacedAtTimestamp);
      const replaced = replacedAt !== 0n && replacedAt <= at;
      return {
        root,
        replacedByRoot: replaced ? BigInt(found.replacedByRoot) : 0n,
        createdAtTimestamp: BigInt(found.createdAtTimestamp),
        replacedAtTimestamp: replaced ? replacedAt : 0n,
        createdAtBlock: BigInt(found.createdAtBlock),
        replacedAtBlock: replaced ? BigInt(found.replacedAtBlock) : 0n
      };
    }
  };
};

export const unavailableGistReader = (): GistRootReader => ({
  getGISTRootInfo: async (): Promise<RootInfo> => {
    throw new Error('connect ECONNREFUSED');
  }
});
