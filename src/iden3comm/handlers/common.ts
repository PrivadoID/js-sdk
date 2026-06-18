import { getRandomBytes } from '@iden3/js-crypto';
import {
  AcceptProfile,
  AuthMethod,
  AuthProof,
  BasicMessage,
  IPackageManager,
  JsonDocumentObject,
  JWSPackerParams,
  PackerParams,
  ZeroKnowledgeProofAuthResponse,
  ZeroKnowledgeProofQuery,
  ZeroKnowledgeProofRequest,
  ZeroKnowledgeProofResponse,
  ZKPPackerParams
} from '../types';
import { mergeObjects } from '../../utils';
import { RevocationStatus, VerifiableConstants, W3CCredential } from '../../verifiable';
import { DID, getUnixTimestamp } from '@iden3/js-iden3-core';
import { IProofService } from '../../proof';
import { CircuitId } from '../../circuits';
import {
  AcceptJwsAlgorithms,
  defaultAcceptProfile,
  MediaType,
  ProtocolVersion
} from '../constants';
import { ethers, Signer } from 'ethers';
import { packZkpProof, prepareZkpProof } from '../../storage/blockchain/common';
import { ProvingMethodAlg } from '@iden3/js-jwz';
import { defaultProvingMethodAlg } from './message-handler';
import { JWEPackerParams } from '../packers';
import { parseAcceptProfile } from '../utils';

/**
 * Union type for handler packer parameters.
 */
export type HandlerPackerParams =
  | JWSPackerParams
  | JWEPackerParams
  | ZKPPackerParams
  | PackerParams;

/**
 * Groups the ZeroKnowledgeProofRequest objects based on their groupId.
 * Returns a Map where the key is the groupId and the value is an object containing the query and linkNonce.
 *
 * @param requestScope - An array of ZeroKnowledgeProofRequest objects.
 * @returns A Map<number, { query: ZeroKnowledgeProofQuery; linkNonce: number }> representing the grouped queries.
 */
export const getGroupedQueries = (
  requestScope: ZeroKnowledgeProofRequest[]
): Map<number, { query: ZeroKnowledgeProofQuery; linkNonce: number }> =>
  requestScope.reduce((acc, proofReq) => {
    const query = proofReq.query;
    if (!query) {
      return acc;
    }
    const groupId = query.groupId as number | undefined;
    if (!groupId) {
      return acc;
    }

    const existedData = acc.get(groupId);
    if (!existedData) {
      const seed = getRandomBytes(12);
      const dataView = new DataView(seed.buffer);
      const linkNonce = dataView.getUint32(0);
      acc.set(groupId, { query, linkNonce });
      return acc;
    }

    const credentialSubject = mergeObjects(
      existedData.query.credentialSubject as JsonDocumentObject,
      query.credentialSubject as JsonDocumentObject
    );

    acc.set(groupId, {
      ...existedData,
      query: {
        skipClaimRevocationCheck:
          existedData.query.skipClaimRevocationCheck || query.skipClaimRevocationCheck,
        ...existedData.query,
        credentialSubject
      }
    });

    return acc;
  }, new Map<number, { query: ZeroKnowledgeProofQuery; linkNonce: number }>());

/**
 * A credential explicitly provided for a proof request, bypassing credential lookup.
 * @public
 */
export type ProofRequestCredential = {
  credential: W3CCredential;
  linkNonce?: bigint;
};

/**
 * Processes zero knowledge proof requests.
 *
 * @param to - The identifier of the recipient.
 * @param requests - An array of zero knowledge proof requests.
 * @param from - The identifier of the sender.
 * @param proofService - The proof service.
 * @param opts - Additional options for processing the requests.
 * @returns A promise that resolves to an array of zero knowledge proof responses.
 */
export const processZeroKnowledgeProofRequests = async (
  to: DID,
  requests: ZeroKnowledgeProofRequest[] | undefined,
  from: DID | undefined,
  proofService: IProofService,
  opts: {
    mediaType?: MediaType;
    packerOptions?: JWSPackerParams;
    supportedCircuits: CircuitId[];
    ethSigner?: Signer;
    challenge?: bigint;
    bypassProofsCache?: boolean;
    allowExpiredCredentials?: boolean;
    credentials?: Map<string, ProofRequestCredential>;
  }
): Promise<ZeroKnowledgeProofResponse[]> => {
  const requestScope = requests ?? [];

  const combinedQueries = getGroupedQueries(requestScope);

  const groupedCredentialsCache = new Map<
    number,
    { cred: W3CCredential; revStatus?: RevocationStatus }
  >();

  const zkpResponses = [];

  for (const proofReq of requestScope) {
    let zkpRes: ZeroKnowledgeProofResponse;
    try {
      const isCircuitSupported = opts.supportedCircuits.includes(proofReq.circuitId as CircuitId);
      if (!isCircuitSupported) {
        if (proofReq.optional) {
          // eslint-disable-next-line no-console
          console.log(
            `Circuit ${proofReq.circuitId} is not supported, skipping optional proof request`
          );
          continue;
        }
        throw new Error(`Circuit ${proofReq.circuitId} is not allowed`);
      }

      const query = proofReq.query;

      const providedCredential = opts.credentials?.get(proofReq.id.toString());
      if (providedCredential) {
        zkpRes = await proofService.generateProof(proofReq, to, {
          verifierDid: from,
          challenge: opts.challenge,
          skipRevocation: Boolean(query?.skipClaimRevocationCheck),
          credential: providedCredential.credential,
          linkNonce: providedCredential.linkNonce,
          bypassCache: opts.bypassProofsCache,
          allowExpiredCredentials: opts.allowExpiredCredentials
        });
        zkpResponses.push(zkpRes);
        continue;
      }

      const groupId = query?.groupId as number | undefined;
      const combinedQueryData = combinedQueries.get(groupId as number);

      if (groupId) {
        if (!combinedQueryData) {
          throw new Error(`Invalid group id ${query?.groupId}`);
        }
        const combinedQuery = combinedQueryData.query;

        if (!groupedCredentialsCache.has(groupId)) {
          const credWithRevStatus = await proofService.findCredentialByProofQuery(
            to,
            combinedQueryData.query
          );
          if (!credWithRevStatus.cred) {
            if (proofReq.optional) {
              // eslint-disable-next-line no-console
              console.log(`No credential found for optional proof request, skipping`);
              continue;
            }
            throw new Error(
              VerifiableConstants.ERRORS.PROOF_SERVICE_NO_CREDENTIAL_FOR_QUERY +
                `${JSON.stringify(combinedQuery)}`
            );
          }

          groupedCredentialsCache.set(groupId, credWithRevStatus);
        }
      }

      const credWithRevStatus = groupedCredentialsCache.get(groupId as number);
      zkpRes = await proofService.generateProof(proofReq, to, {
        verifierDid: from,
        challenge: opts.challenge,
        skipRevocation: Boolean(query?.skipClaimRevocationCheck),
        credential: credWithRevStatus?.cred,
        credentialRevocationStatus: credWithRevStatus?.revStatus,
        linkNonce: combinedQueryData?.linkNonce ? BigInt(combinedQueryData.linkNonce) : undefined,
        bypassCache: opts.bypassProofsCache,
        allowExpiredCredentials: opts.allowExpiredCredentials
      });
    } catch (error: unknown) {
      const expectedErrors = [
        VerifiableConstants.ERRORS.PROOF_SERVICE_NO_CREDENTIAL_FOR_IDENTITY_OR_PROFILE,
        VerifiableConstants.ERRORS.ID_WALLET_NO_CREDENTIAL_SATISFIED_QUERY,
        VerifiableConstants.ERRORS.CREDENTIAL_WALLET_ALL_CREDENTIALS_ARE_REVOKED,
        VerifiableConstants.ERRORS.PROOF_SERVICE_CREDENTIAL_IS_EXPIRED
      ];
      // handle only expected errors for optional proof requests when credential is not found, revoked, or expired - otherwise throw
      if (
        error instanceof Error &&
        (expectedErrors.includes(error.message) ||
          error.message.includes(
            VerifiableConstants.ERRORS.PROOF_SERVICE_NO_CREDENTIAL_FOR_QUERY
          )) &&
        proofReq.optional
      ) {
        // eslint-disable-next-line no-console
        console.log(`Error in optional proof request: ${error.message}, skipping`);
        continue;
      }
      throw error;
    }

    zkpResponses.push(zkpRes);
  }

  return zkpResponses;
};

/**
 * Processes auth proof requests.
 *
 * @param to - The identifier of the recipient.
 * @param proofService - The proof service.
 * @param opts - Additional options for processing the requests.
 * @returns A promise that resolves to an auth proof response.
 */
export const processProofAuth = async (
  to: DID,
  proofService: IProofService,
  opts: {
    supportedCircuits: CircuitId[];
    acceptProfile?: AcceptProfile;
    senderAddress: string;
    zkpResponses: ZeroKnowledgeProofResponse[];
  }
): Promise<{ authProof: AuthProof }> => {
  if (!opts.acceptProfile) {
    opts.acceptProfile = defaultAcceptProfile;
  }

  switch (opts.acceptProfile.env) {
    case MediaType.PlainMessage: // if it's plain message, we assume it's embedded auth, so we don't need to generate any proof, just return auth method
      return {
        authProof: {
          authMethod: AuthMethod.EMBEDDED_AUTH
        }
      };
    case MediaType.ZKPMessage:
      if (!opts.acceptProfile.circuits) {
        throw new Error('Circuit not specified in accept profile');
      }

      for (const circuitId of opts.acceptProfile.circuits) {
        if (!opts.supportedCircuits.includes(circuitId as unknown as CircuitId)) {
          throw new Error(`Circuit ${circuitId} is not supported`);
        }
        if (!opts.senderAddress) {
          throw new Error('Sender address is not provided');
        }
        const challengeAuth = calcChallengeAuth(opts.senderAddress, opts.zkpResponses);

        const zkpRes: ZeroKnowledgeProofAuthResponse = await proofService.generateAuthProof(
          circuitId as unknown as CircuitId,
          to,
          { challenge: challengeAuth }
        );
        return {
          authProof: {
            authMethod: circuitId as string as AuthMethod,
            zkp: zkpRes
          }
        };
      }
      throw new Error(`Auth method is not supported`);
    case MediaType.SignedMessage:
      if (!opts.acceptProfile.alg || opts.acceptProfile.alg.length === 0) {
        throw new Error('Algorithm not specified');
      }
      if (opts.acceptProfile.alg[0] === AcceptJwsAlgorithms.ES256KR) {
        return {
          authProof: {
            authMethod: AuthMethod.ETH_IDENTITY,
            userDid: to
          }
        };
      }
      throw new Error(`Algorithm ${opts.acceptProfile.alg[0]} not supported`);
    default:
      throw new Error('Accept env not supported');
  }
};

/**
 * Processes a ZeroKnowledgeProofResponse object and prepares it for further use.
 * @param zkProof - The ZeroKnowledgeProofResponse object containing the proof data.
 * @returns An object containing the requestId, zkProofEncoded, and metadata.
 */
export const processProofResponse = (zkProof: ZeroKnowledgeProofResponse) => {
  const requestId = zkProof.id;
  const inputs = zkProof.pub_signals;
  const emptyBytes = '0x';

  if (inputs.length === 0) {
    return { requestId, zkProofEncoded: emptyBytes, metadata: emptyBytes };
  }

  const preparedZkpProof = prepareZkpProof(zkProof.proof);
  const zkProofEncoded = packZkpProof(
    inputs,
    preparedZkpProof.a,
    preparedZkpProof.b,
    preparedZkpProof.c
  );

  const metadata = ethers.AbiCoder.defaultAbiCoder().encode(['string'], [zkProof.circuitId]);

  return { requestId, zkProofEncoded, metadata };
};

/**
 * Calculates the challenge authentication authV2, authV3, authV3-8-32 value.
 * @param senderAddress - The address of the sender.
 * @param zkpResponses - An array of ZeroKnowledgeProofResponse objects.
 * @returns A bigint representing the challenge authentication value.
 */
export const calcChallengeAuth = (
  senderAddress: string,
  zkpResponses: ZeroKnowledgeProofResponse[]
): bigint => {
  const responses = zkpResponses.map((zkpResponse) => {
    const response = processProofResponse(zkpResponse);
    return {
      requestId: response.requestId,
      proof: response.zkProofEncoded,
      metadata: response.metadata
    };
  });

  return (
    BigInt(
      ethers.keccak256(
        new ethers.AbiCoder().encode(
          ['address', '(uint256 requestId,bytes proof,bytes metadata)[]'],
          [senderAddress, responses]
        )
      )
    ) & BigInt('0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
  );
};

/**
 * Packs metadata into a string format suitable for encoding in a transaction.
 * @param metas - An array of objects containing key-value pairs to be packed.
 * @returns A string representing the packed metadata.
 */
export const packMetadatas = (
  metas: {
    key: string;
    value: Uint8Array;
  }[]
): string => {
  return new ethers.AbiCoder().encode(['tuple(' + 'string key,' + 'bytes value' + ')[]'], [metas]);
};

/**
 * Verifies that the expires_time field of a message is not in the past. Throws an error if it is.
 *
 * @param message - Basic message to verify.
 */
export const verifyExpiresTime = (message: BasicMessage) => {
  if (message?.expires_time && message.expires_time < getUnixTimestamp(new Date())) {
    throw new Error('Message expired');
  }
};

/**
 * Initializes default packer options based on the media type and provided options.
 * @param mediaType - The media type of the message.
 * @param packerOptions - Optional packer parameters.
 * @param opts - Additional options including proving method algorithm and sender DID.
 * @returns PackerParams
 */
export const initDefaultPackerOptions = (
  mediaType: MediaType,
  packerOptions?: HandlerPackerParams,
  opts?: {
    provingMethodAlg?: ProvingMethodAlg;
    senderDID?: DID;
  }
): PackerParams => {
  if (mediaType === MediaType.SignedMessage || mediaType === MediaType.EncryptedMessage) {
    if (!packerOptions) {
      throw new Error(`packer options are required for ${mediaType}`);
    }
    return packerOptions;
  }

  if (mediaType === MediaType.PlainMessage) {
    return {};
  }

  if (mediaType === MediaType.ZKPMessage) {
    const zkpPackerParams = {
      provingMethodAlg:
        packerOptions?.provingMethodAlg || opts?.provingMethodAlg || defaultProvingMethodAlg,
      senderDID: packerOptions?.senderDID || opts?.senderDID
    };
    if (!zkpPackerParams.senderDID) {
      throw new Error('senderDID is required for ZKPMessage');
    }
    return zkpPackerParams;
  }
  throw new Error(`unsupported media type ${mediaType}`);
};

/**
 * Selects the first supported profile from the provided list of profiles based on the response type and packer manager capabilities.
 *
 * @param responseType
 * @param packerMgr
 * @param profile
 * @returns AcceptProfile
 */

export const getFirstSupportedProfile = (
  responseType: string,
  packerMgr: IPackageManager,
  profile?: string[] | undefined
): AcceptProfile => {
  if (profile?.length) {
    for (const acceptProfileString of profile) {
      // 1. check protocol version
      const acceptProfile = parseAcceptProfile(acceptProfileString);
      const responseTypeVersion = Number(responseType.split('/').at(-2));
      if (
        acceptProfile.protocolVersion !== ProtocolVersion.V1 ||
        (acceptProfile.protocolVersion === ProtocolVersion.V1 &&
          (responseTypeVersion < 1 || responseTypeVersion >= 2))
      ) {
        continue;
      }
      // 2. check packer support
      if (packerMgr.isProfileSupported(acceptProfile.env, acceptProfileString)) {
        return acceptProfile;
      }
    }
  }

  // if we don't have supported profiles, we use default
  return defaultAcceptProfile;
};
