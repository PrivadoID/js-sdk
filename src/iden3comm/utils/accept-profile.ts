import { proving, ProvingMethodAlg } from '@iden3/js-jwz';
import {
  MediaType,
  ProtocolVersion,
  AcceptAuthCircuits,
  AcceptJwzAlgorithms,
  AcceptJwsAlgorithms,
  AcceptJweKEKAlgorithms
} from '../constants';
import { AcceptProfile, IPackageManager } from '../types';

/**
 * Default proving method algorithm for ZKP messages
 */
export const defaultProvingMethodAlg = proving.provingMethodGroth16AuthV2Instance.methodAlg;

function isProtocolVersion(value: string): boolean {
  return Object.values(ProtocolVersion).includes(value as ProtocolVersion);
}

function isMediaType(value: string): boolean {
  return Object.values(MediaType).includes(value as MediaType);
}

function isAcceptAuthCircuits(value: string): boolean {
  return Object.values(AcceptAuthCircuits).includes(value as AcceptAuthCircuits);
}

function isAcceptJwsAlgorithms(value: string): boolean {
  return Object.values(AcceptJwsAlgorithms).includes(value as AcceptJwsAlgorithms);
}

function isAcceptJwzAlgorithms(value: string): boolean {
  return Object.values(AcceptJwzAlgorithms).includes(value as AcceptJwzAlgorithms);
}

export const buildAcceptFromProvingMethodAlg = (provingMethodAlg: ProvingMethodAlg): string => {
  const [alg, circuitId] = provingMethodAlg.toString().split(':');
  return `${ProtocolVersion.V1};env=${MediaType.ZKPMessage};circuitId=${circuitId};alg=${alg}`;
};

export const acceptHasProvingMethodAlg = (
  accept: string[],
  provingMethodAlg: ProvingMethodAlg
): boolean => {
  const [provingAlg, provingCircuitId] = provingMethodAlg.toString().split(':');
  for (const profile of accept) {
    const { env, circuits, alg } = parseAcceptProfile(profile);
    if (
      env === MediaType.ZKPMessage &&
      circuits?.includes(provingCircuitId as AcceptAuthCircuits) &&
      (!alg || (alg as unknown as AcceptJwzAlgorithms)?.includes(provingAlg as AcceptJwzAlgorithms))
    ) {
      return true;
    }
  }
  return false;
};

function isAcceptJweAlgorithms(value: string): boolean {
  return Object.values(AcceptJweKEKAlgorithms).includes(value as AcceptJweKEKAlgorithms);
}

export const buildAccept = (profiles: AcceptProfile[]): string[] => {
  const result = [];
  for (const profile of profiles) {
    let accept = `${profile.protocolVersion};env=${profile.env}`;
    if (profile.circuits?.length) {
      accept += `;circuitId=${profile.circuits.join(',')}`;
    }
    if (profile.alg?.length) {
      accept += `;alg=${profile.alg.join(',')}`;
    }
    result.push(accept);
  }

  return result;
};

export const parseAcceptProfile = (profile: string): AcceptProfile => {
  const params = profile.split(';');

  if (params.length < 2) {
    throw new Error('Invalid accept profile');
  }
  const protocolVersion = params[0].trim() as ProtocolVersion;
  if (!isProtocolVersion(protocolVersion)) {
    throw new Error(`Protocol version '${protocolVersion}' not supported`);
  }

  const envParam = params[1].split('=');
  if (envParam.length !== 2) {
    throw new Error(`Invalid accept profile 'env' parameter`);
  }
  const env = params[1].split('=')[1].trim() as MediaType;
  if (!isMediaType(env)) {
    throw new Error(`Envelop '${env}' not supported`);
  }

  const circuitsIndex = params.findIndex((i: string) => i.includes('circuitId='));
  if (env !== MediaType.ZKPMessage && circuitsIndex > 0) {
    throw new Error(`Circuits not supported for env '${env}'`);
  }

  let circuits: AcceptAuthCircuits[] | undefined = undefined;
  if (circuitsIndex > 0) {
    circuits = params[circuitsIndex]
      .split('=')[1]
      .split(',')
      .map((i) => i.trim())
      .map((i) => {
        if (!isAcceptAuthCircuits(i)) {
          throw new Error(`Circuit '${i}' not supported`);
        }
        return i as AcceptAuthCircuits;
      });
  }

  const algIndex = params.findIndex((i: string) => i.includes('alg='));

  if (algIndex === -1) {
    return {
      protocolVersion,
      env,
      circuits,
      alg: undefined
    };
  }

  const algValues = params[algIndex]
    .split('=')[1]
    .split(',')
    .map((i) => i.trim());

  let alg: AcceptJwsAlgorithms[] | AcceptJwzAlgorithms[] | AcceptJweKEKAlgorithms[] = [];

  switch (env) {
    case MediaType.ZKPMessage:
      alg = algValues.map((i) => {
        if (!isAcceptJwzAlgorithms(i)) {
          throw new Error(`Algorithm '${i}' not supported for '${env}'`);
        }
        return i as AcceptJwzAlgorithms;
      });
      break;
    case MediaType.SignedMessage:
      alg = algValues.map((i) => {
        if (!isAcceptJwsAlgorithms(i)) {
          throw new Error(`Algorithm '${i}' not supported for '${env}'`);
        }
        return i as AcceptJwsAlgorithms;
      });
      break;
    case MediaType.EncryptedMessage:
      alg = algValues.map((i) => {
        if (!isAcceptJweAlgorithms(i)) {
          throw new Error(`Algorithm '${i}' not supported for '${env}'`);
        }
        return i as AcceptJweKEKAlgorithms;
      });
      break;
    default:
      throw new Error(`Algorithms not supported for '${env}'`);
  }

  return {
    protocolVersion,
    env,
    circuits,
    alg
  };
};

export const getDefaultZKProvingMethodAlg = (
  packerMgr: IPackageManager,
  preferredAuthProvingMethod?: ProvingMethodAlg,
  accept?: string[]
): ProvingMethodAlg => {
  // if no accept is given, return default
  if (!accept?.length) {
    return defaultProvingMethodAlg;
  }

  const preferredOrder = [
    proving.provingMethodGroth16AuthV3_8_32Instance.methodAlg,
    proving.provingMethodGroth16AuthV3Instance.methodAlg
  ];
  if (preferredAuthProvingMethod) {
    const idx = preferredOrder.indexOf(preferredAuthProvingMethod);
    if (idx !== -1) {
      preferredOrder.splice(idx, 1);
    }
    preferredOrder.unshift(preferredAuthProvingMethod);
  }

  for (const methodAlg of preferredOrder) {
    if (
      packerMgr.isProfileSupported(
        MediaType.ZKPMessage,
        buildAcceptFromProvingMethodAlg(methodAlg)
      ) &&
      acceptHasProvingMethodAlg(accept, methodAlg)
    ) {
      return methodAlg;
    }
  }

  return defaultProvingMethodAlg;
};
