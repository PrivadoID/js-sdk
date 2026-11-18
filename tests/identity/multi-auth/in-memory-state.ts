import { Id } from '@iden3/js-iden3-core';
import { Poseidon } from '@iden3/js-crypto';
import { InMemoryDB, Merkletree, str2Bytes } from '@iden3/js-merkletree';
import { ZKProof } from '@iden3/js-jwz';
import { JsonRpcProvider, Signer } from 'ethers';
import {
  CircuitId,
  IStateStorage,
  IZKProver,
  RootInfo,
  StateInfo,
  StateProof,
  StateTransitionPubSignals,
  UserStateTransitionInfo,
  byteEncoder,
  getIsGenesisStateById
} from '../../../src';

const nowSec = () => BigInt(Math.floor(Date.now() / 1000));

const isEthereumBasedId = (id: Id): boolean => {
  try {
    Id.ethAddressFromId(id);
    return true;
  } catch {
    return false;
  }
};

/**
 * In-memory replacement of the State smart contract for offline tests.
 *
 * Keeps the GIST (id hash -> latest state) as a 64-level SMT, the per-identity state
 * history and the GIST root history, and verifies state transition proofs before
 * accepting them, so authV2 / query proofs are checked against a real global state.
 */
export class InMemoryStateStorage implements IStateStorage {
  private readonly _gist = new Merkletree(new InMemoryDB(str2Bytes('gist')), true, 64);
  private readonly _states = new Map<bigint, StateInfo[]>();
  private readonly _roots = new Map<bigint, RootInfo>();
  private readonly _txs = new Map<string, number>();
  private _block = 0;

  constructor(private readonly _verifier: IZKProver) {}

  async init(): Promise<this> {
    const root = (await this._gist.root()).bigInt();
    this._roots.set(root, this.newRootInfo(root));
    return this;
  }

  async getLatestStateById(id: bigint): Promise<StateInfo> {
    const history = this._states.get(id);
    if (!history?.length) {
      throw new Error('State does not exist');
    }
    return history[history.length - 1];
  }

  async getStateInfoByIdAndState(id: bigint, state: bigint): Promise<StateInfo> {
    const info = this._states.get(id)?.find((s) => s.state === state);
    if (info) {
      return info;
    }
    if (getIsGenesisStateById(Id.fromBigInt(id), state)) {
      return { id, state, replacedByState: 0n, createdAtTimestamp: 0n, replacedAtTimestamp: 0n };
    }
    throw new Error(`State ${state} for identity ${id} is not genesis and not registered`);
  }

  async publishState(proof: ZKProof | undefined): Promise<string> {
    if (!proof) {
      throw new Error('state transition proof is required');
    }
    if (!(await this._verifier.verify(proof, CircuitId.StateTransition))) {
      throw new Error('invalid state transition proof');
    }
    const pub = new StateTransitionPubSignals().pubSignalsUnmarshal(
      byteEncoder.encode(JSON.stringify(proof.pub_signals))
    );
    return this.transit(
      pub.userId.bigInt(),
      pub.oldUserState.bigInt(),
      pub.newUserState.bigInt(),
      pub.isOldStateGenesis
    );
  }

  async publishStateGeneric(_: Signer, info?: UserStateTransitionInfo): Promise<string> {
    if (!info) {
      throw new Error('state transition info is required');
    }
    // method 1: the contract authorizes an Ethereum-based identity by msg.sender == address
    // in the id (the signer is not checked here), so its genesis state is not derived from the id
    return this.transit(
      info.userId.bigInt(),
      info.oldUserState.bigInt(),
      info.newUserState.bigInt(),
      info.isOldStateGenesis,
      isEthereumBasedId
    );
  }

  async getGISTProof(id: bigint): Promise<StateProof> {
    const index = Poseidon.hash([id]);
    const { proof, value } = await this._gist.generateProof(index);
    return {
      root: (await this._gist.root()).bigInt(),
      existence: proof.existence,
      siblings: proof.allSiblings().map((s) => s.bigInt()),
      index,
      value,
      auxExistence: !!proof.nodeAux,
      auxIndex: proof.nodeAux?.key.bigInt() ?? 0n,
      auxValue: proof.nodeAux?.value.bigInt() ?? 0n
    };
  }

  async getGISTRootInfo(root: bigint): Promise<RootInfo> {
    const info = this._roots.get(root);
    if (!info) {
      throw new Error(`GIST root ${root} does not exist`);
    }
    return info;
  }

  /** Minimal provider: enough for TransactionService.getTransactionReceiptAndBlock */
  getRpcProvider(): JsonRpcProvider {
    return {
      getTransactionReceipt: async (hash: string) => {
        const blockNumber = this._txs.get(hash);
        if (blockNumber === undefined) {
          return null;
        }
        return {
          blockNumber,
          getBlock: async () => ({ number: blockNumber, timestamp: Number(nowSec()) })
        };
      }
    } as unknown as JsonRpcProvider;
  }

  private async transit(
    id: bigint,
    oldState: bigint,
    newState: bigint,
    isOldStateGenesis: boolean,
    isGenesis: (id: Id, state: bigint) => boolean = getIsGenesisStateById
  ): Promise<string> {
    const history = this._states.get(id) ?? [];
    const latest = history[history.length - 1];
    if (isOldStateGenesis) {
      if (latest) {
        throw new Error('old state is genesis but identity already exists');
      }
      if (!isGenesis(Id.fromBigInt(id), oldState)) {
        throw new Error('old state is not the genesis state of the identity');
      }
    } else if (latest?.state !== oldState) {
      throw new Error('old state does not match the latest state of the identity');
    }

    const ts = nowSec();
    const block = BigInt(++this._block);
    if (latest) {
      latest.replacedByState = newState;
      latest.replacedAtTimestamp = ts;
      latest.replacedAtBlock = block;
    } else {
      history.push({
        id,
        state: oldState,
        replacedByState: newState,
        createdAtTimestamp: 0n,
        replacedAtTimestamp: ts,
        createdAtBlock: 0n,
        replacedAtBlock: block
      });
    }
    history.push({
      id,
      state: newState,
      replacedByState: 0n,
      createdAtTimestamp: ts,
      replacedAtTimestamp: 0n,
      createdAtBlock: block,
      replacedAtBlock: 0n
    });
    this._states.set(id, history);

    const oldRoot = (await this._gist.root()).bigInt();
    const index = Poseidon.hash([id]);
    if (latest) {
      await this._gist.update(index, newState);
    } else {
      await this._gist.add(index, newState);
    }
    const newRoot = (await this._gist.root()).bigInt();
    const replaced = this._roots.get(oldRoot);
    if (replaced) {
      replaced.replacedByRoot = newRoot;
      replaced.replacedAtTimestamp = ts;
      replaced.replacedAtBlock = block;
    }
    this._roots.set(newRoot, this.newRootInfo(newRoot, ts, block));

    const txId = `0x${block.toString(16).padStart(64, '0')}`;
    this._txs.set(txId, Number(block));
    return txId;
  }

  private newRootInfo(root: bigint, ts = nowSec(), block = 0n): RootInfo {
    return {
      root,
      replacedByRoot: 0n,
      createdAtTimestamp: ts,
      replacedAtTimestamp: 0n,
      createdAtBlock: block,
      replacedAtBlock: 0n
    };
  }
}
