import { ProvingMethodAlg, Token } from '@iden3/js-jwz';
import { CircuitId } from '../../circuits';
import { IProofService } from '../../proof';
import { CircuitLoadMode, ICircuitStorage } from '../../storage';
import { BasicMessage, StateVerificationOpts, ZKPPackerParams } from '../types';
import { DataPrepareHandlerFunc, VerificationHandlerFunc, ZKPPacker } from './zkp';

/** * Default ZKP Packer that loads circuit data from provided circuit storage
 * and uses provided proof service to generate and verify proofs.
 *
 * @public
 * @class DefaultZKPPacker
 */
export class DefaultZKPPacker extends ZKPPacker {
  /**
   * Constructs a new instance of the class.
   *
   * @param circuitStorage - An implementation of the ICircuitStorage interface used to manage circuit data.
   * @param proofService - An implementation of the IProofService interface responsible for generating and verifying proofs.
   * @param opts - Optional state verification options to customize the behavior of the packer.
   */
  constructor(
    private circuitStorage: ICircuitStorage,
    private proofService: IProofService,
    opts?: StateVerificationOpts
  ) {
    super(new Map(), new Map(), { ...opts });
    this.supportedCircuitIds = [CircuitId.AuthV2, CircuitId.AuthV3, CircuitId.AuthV3_8_32];
  }

  /**
   * Packs the given payload using zero-knowledge proof (ZKP) parameters.
   *
   * Loads the circuit data (proving key and wasm) for the specified circuit ID from the circuit storage.
   * If the circuit data is not found, throws an error.
   * Caches the proving parameters for the proving method algorithm if not already cached.
   * Delegates the actual packing to the superclass implementation.
   *
   * @param payload - The data to be packed, as a Uint8Array.
   * @param params - The parameters required for ZKP packing, including the proving method algorithm.
   * @returns A Promise that resolves to the packed payload as a Uint8Array.
   * @throws If the circuit data (proving key or wasm) is not found for the given circuit ID.
   */
  async pack(payload: Uint8Array, params: ZKPPackerParams): Promise<Uint8Array> {
    const provingMethodAlg = params.provingMethodAlg;
    const circuitId = provingMethodAlg.circuitId as CircuitId;
    const provingParamsKey = provingMethodAlg.toString();

    if (!this.provingParamsMap.has(provingParamsKey)) {
      const { provingKey, wasm } = await this.circuitStorage.loadCircuitData(
        circuitId as CircuitId,
        {
          mode: CircuitLoadMode.Proving
        }
      );
      if (!provingKey || !wasm) {
        throw new Error(`circuit data not found for circuit id: ${circuitId}`);
      }
      this.provingParamsMap.set(provingParamsKey, {
        provingKey,
        wasm,
        dataPreparer: new DataPrepareHandlerFunc(
          this.proofService.generateAuthInputs.bind(this.proofService)
        )
      });
    }
    return super.pack(payload, params);
  }

  async verifyToken(token: Token, sender: string, opts?: StateVerificationOpts): Promise<void> {
    await this.loadVerificationParams(token);
    return super.verifyToken(token, sender, opts);
  }

  /**
   * Unpacks a ZKP envelope into a `BasicMessage` by parsing the token, loading the verification key if necessary,
   * and preparing the verification parameters for the proving method algorithm.
   *
   * This method ensures that the verification parameters for the given circuit and algorithm are loaded and cached.
   * If the verification key is not found for the specified circuit, an error is thrown.
   *
   * @param envelope - The serialized ZKP envelope as a `Uint8Array`.
   * @returns A promise that resolves to a `BasicMessage` extracted from the envelope.
   * @throws If the verification key for the specified circuit ID cannot be found.
   */
  async unpack(envelope: Uint8Array): Promise<BasicMessage> {
    const token = await this.parseToken(envelope);
    const provingMethodAlg = await this.loadVerificationParams(token);
    return super.unpackMessage(token, provingMethodAlg);
  }

  protected async loadVerificationParams(token: Token): Promise<ProvingMethodAlg> {
    const circuitId = token.circuitId as CircuitId;

    const provingMethodAlg = new ProvingMethodAlg(token.alg, circuitId);

    if (!this.verificationParamsMap.has(provingMethodAlg.toString())) {
      const { verificationKey } = await this.circuitStorage.loadCircuitData(circuitId, {
        mode: CircuitLoadMode.Verification
      });

      if (!verificationKey) {
        throw new Error(`verification key not found for circuit id: ${circuitId}`);
      }

      this.verificationParamsMap.set(provingMethodAlg.toString(), {
        key: verificationKey,
        verificationFn: new VerificationHandlerFunc(
          this.proofService.verifyState.bind(this.proofService)
        )
      });
    }

    return provingMethodAlg;
  }
}
