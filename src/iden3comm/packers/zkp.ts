import {
  StateVerificationOpts,
  AuthDataPrepareFunc,
  BasicMessage,
  IPacker,
  ProvingParams,
  StateVerificationFunc,
  VerificationParams,
  ZKPPackerParams
} from '../types';
import { Token, Header, ProvingMethodAlg, proving } from '@iden3/js-jwz';
import { AuthV2PubSignals, AuthV3PubSignals, CircuitId } from '../../circuits/index';
import { BytesHelper, DID } from '@iden3/js-iden3-core';
import {
  ErrNoProvingMethodAlg,
  ErrPackedWithUnsupportedCircuit,
  ErrProofIsInvalid,
  ErrSenderNotUsedTokenCreation,
  ErrStateVerificationFailed,
  ErrUnknownCircuitID
} from '../errors';
import { AcceptJwzAlgorithms, MediaType, ProtocolVersion } from '../constants';
import { byteDecoder, byteEncoder } from '../../utils';
import { DEFAULT_AUTH_VERIFY_DELAY } from '../constants';
import { parseAcceptProfile } from '../utils';

const { getProvingMethod } = proving;

/**
 * Handler to
 *
 * @public
 * @class DataPrepareHandlerFunc
 */
export class DataPrepareHandlerFunc {
  /**
   * Creates an instance of DataPrepareHandlerFunc.
   * @param {AuthDataPrepareFunc} dataPrepareFunc - function that produces marshaled inputs for auth circuits
   */
  constructor(public readonly dataPrepareFunc: AuthDataPrepareFunc) {}

  /**
   *
   *
   * @param {Uint8Array} hash - challenge that will be signed
   * @param {DID} did - did of identity that will prepare inputs
   * @param {CircuitId} circuitId - circuit id
   * @returns `Promise<Uint8Array>`
   */
  prepare(hash: Uint8Array, did: DID, circuitId: CircuitId): Promise<Uint8Array> {
    return this.dataPrepareFunc(hash, did, circuitId);
  }
}

/**
 * Handler to verify public signals of authorization circuits
 *
 * @public
 * @class VerificationHandlerFunc
 */
export class VerificationHandlerFunc {
  /**
   * Creates an instance of VerificationHandlerFunc.
   * @param {StateVerificationFunc} stateVerificationFunc - state verification function
   */
  constructor(public readonly stateVerificationFunc: StateVerificationFunc) {}

  /**
   *
   *
   * @param {string} id  - id of circuit
   * @param {Array<string>} pubSignals - signals that must contain user id and state
   * @returns `Promise<boolean>`
   */
  verify(id: string, pubSignals: Array<string>, opts?: StateVerificationOpts): Promise<boolean> {
    return this.stateVerificationFunc(id, pubSignals, opts);
  }
}

/**
 * Packer that can pack message to JWZ token,
 * and unpack and validate JWZ envelope
 * @public
 * @class ZKPPacker
 * @implements implements IPacker interface
 */
export class ZKPPacker implements IPacker {
  private readonly supportedProtocolVersions = [ProtocolVersion.V1];
  private readonly supportedAlgorithms = [AcceptJwzAlgorithms.Groth16];
  protected supportedCircuitIds: string[];
  /**
   * Creates an instance of ZKPPacker.
   * @param {Map<string, ProvingParams>} provingParamsMap - string is derived by JSON.parse(ProvingMethodAlg)
   * @param {Map<string, VerificationParams>} verificationParamsMap - string is derived by JSON.parse(ProvingMethodAlg)
   */
  constructor(
    public readonly provingParamsMap: Map<string, ProvingParams>,
    public readonly verificationParamsMap: Map<string, VerificationParams>,
    private readonly _opts: StateVerificationOpts = {
      acceptedStateTransitionDelay: DEFAULT_AUTH_VERIFY_DELAY
    }
  ) {
    const supportedProvers = Array.from(this.provingParamsMap.keys()).map(
      (alg) => alg.split(':')[1]
    );

    const supportedVerifiers = Array.from(this.verificationParamsMap.keys()).map(
      (alg) => alg.split(':')[1]
    );
    this.supportedCircuitIds = [...new Set([...supportedProvers, ...supportedVerifiers])];
  }

  /**
   * Packs a basic message using the specified parameters.
   * @param msg - The basic message to pack.
   * @param param - The parameters for the ZKPPacker.
   * @returns A promise that resolves to a Uint8Array representing the packed message.
   */
  packMessage(msg: BasicMessage, param: ZKPPackerParams): Promise<Uint8Array> {
    return this.pack(byteEncoder.encode(JSON.stringify(msg)), param as ZKPPackerParams);
  }

  /**
   * creates JSON Web Zeroknowledge token
   *
   * @param {Uint8Array} payload - serialized message
   * @param {ZKPPackerParams} params - sender id and proving alg are required
   * @returns `Promise<Uint8Array>`
   */
  async pack(payload: Uint8Array, params: ZKPPackerParams): Promise<Uint8Array> {
    const provingMethod = await getProvingMethod(params.provingMethodAlg);
    const provingParams = this.provingParamsMap.get(params.provingMethodAlg.toString());

    if (!provingParams) {
      throw new Error(ErrNoProvingMethodAlg);
    }

    const token = new Token(
      provingMethod,
      byteDecoder.decode(payload),
      (hash: Uint8Array, circuitId: string) => {
        return provingParams?.dataPreparer?.prepare(hash, params.senderDID, circuitId as CircuitId);
      }
    );
    token.setHeader(Header.Type, MediaType.ZKPMessage);
    const tokenStr = await token.prove(provingParams.provingKey, provingParams.wasm);
    return byteEncoder.encode(tokenStr);
  }

  protected async verifyTokenProof(
    token: Token,
    provingMethodAlg: ProvingMethodAlg,
    opts?: StateVerificationOpts
  ): Promise<void> {
    const verificationParams = this.verificationParamsMap.get(provingMethodAlg.toString());
    if (!verificationParams?.key) {
      throw new Error(ErrPackedWithUnsupportedCircuit);
    }
    const isValid = await token.verify(verificationParams?.key);
    if (!isValid) {
      throw new Error(ErrProofIsInvalid);
    }

    const verificationResult = await verificationParams?.verificationFn?.verify(
      token.circuitId,
      token.zkProof.pub_signals,
      { ...this._opts, ...opts }
    );

    if (!verificationResult) {
      throw new Error(ErrStateVerificationFailed);
    }
  }

  protected async unpackMessage(
    token: Token,
    provingMethodAlg: ProvingMethodAlg
  ): Promise<BasicMessage> {
    await this.verifyTokenProof(token, provingMethodAlg);

    const message = JSON.parse(token.getPayload());

    // should throw if error
    await verifySender(token, message.from);

    return message;
  }

  async verifyToken(token: Token, sender: string, opts?: StateVerificationOpts): Promise<void> {
    await this.verifyTokenProof(token, new ProvingMethodAlg(token.alg, token.circuitId), opts);
    await verifySender(token, sender);
  }

  protected parseToken(msg: Uint8Array): Promise<Token> {
    return Token.parse(byteDecoder.decode(msg));
  }

  /**
   * validate envelope which is jwz token
   *
   * @param {Uint8Array} envelope
   * @returns `Promise<BasicMessage>`
   */
  async unpack(envelope: Uint8Array): Promise<BasicMessage> {
    const token = await this.parseToken(envelope);
    const provingMethodAlg = new ProvingMethodAlg(token.alg, token.circuitId);
    return this.unpackMessage(token, provingMethodAlg);
  }

  mediaType(): MediaType {
    return MediaType.ZKPMessage;
  }

  /** {@inheritDoc IPacker.getSupportedProfiles} */
  getSupportedProfiles(): string[] {
    return this.supportedProtocolVersions.map(
      (v) =>
        `${v};env=${this.mediaType()};alg=${this.supportedAlgorithms.join(
          ','
        )};circuitIds=${this.supportedCircuitIds.join(',')}`
    );
  }

  /** {@inheritDoc IPacker.isProfileSupported} */
  isProfileSupported(profile: string) {
    const { protocolVersion, env, circuits, alg } = parseAcceptProfile(profile);

    if (!this.supportedProtocolVersions.includes(protocolVersion)) {
      return false;
    }

    if (env !== this.mediaType()) {
      return false;
    }

    const supportedCircuitIds = this.supportedCircuitIds;
    const circuitIdSupported =
      !circuits?.length || circuits.some((c) => supportedCircuitIds.includes(c));

    const supportedAlgArr = this.supportedAlgorithms;
    const algSupported =
      !alg?.length || alg.some((a) => supportedAlgArr.includes(a as AcceptJwzAlgorithms));
    return algSupported && circuitIdSupported;
  }
}

const verifySender = async (token: Token, from?: string): Promise<void> => {
  switch (token.circuitId) {
    case CircuitId.AuthV2:
    case CircuitId.AuthV3_8_32:
    case CircuitId.AuthV3:
      {
        if (!from) {
          throw new Error(ErrSenderNotUsedTokenCreation);
        }
        const authSignals = (
          token.circuitId === CircuitId.AuthV2 ? new AuthV2PubSignals() : new AuthV3PubSignals()
        ).pubSignalsUnmarshal(byteEncoder.encode(JSON.stringify(token.zkProof.pub_signals)));
        const did = DID.parseFromId(authSignals.userID);

        const msgHash = await token.getMessageHash();
        const challenge = BytesHelper.bytesToInt(msgHash.reverse());

        if (challenge !== authSignals.challenge) {
          throw new Error(ErrSenderNotUsedTokenCreation);
        }

        if (from !== did.string()) {
          throw new Error(ErrSenderNotUsedTokenCreation);
        }
      }
      break;
    default:
      throw new Error(ErrUnknownCircuitID);
  }
};
