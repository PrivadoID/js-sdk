import { DID, DidMethod, getChainId } from '@iden3/js-iden3-core';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { Token } from '@iden3/js-jwz';
import { AuthV3PubSignals } from '../../circuits/auth-v3';
import { JsonDocumentObject } from '../../iden3comm';
import { isRootDoesNotExistError } from '../../storage/blockchain/errors';
import { RootInfo } from '../../storage/entities/state';
import { IStateStorage } from '../../storage/interfaces/state';
import { byteEncoder } from '../../utils';
import { VerifiableConstants } from '../constants';
import { IDEN3_JWZ_MAX_ROOT_REPLACED_BEFORE_CREATED_SECONDS, ProofLifetime } from './constants';
import { Iden3JwzProofRejection } from './rejection';
import { computeIden3JwzPayload } from './canonical';
import {
  checkProofDates,
  checkProofShape,
  checkZkProofForm,
  circuitIdOfHeader,
  decodeProofValue,
  equalBytes,
  malformed
} from './proof-form';

export type GistRootReader = Pick<IStateStorage, 'getGISTRootInfo'>;

export type VerifyIden3JwzProofOptions = {
  signer: string;
  now: Date;
  lifetime: ProofLifetime;
  documentLoader: DocumentLoader;
  networks: readonly string[];
  gistRootReader: GistRootReader;
  verificationKeys: Readonly<Record<string, Uint8Array>>;
  allowUnsignedEmptyArrays?: boolean;
  precheck?: (
    unsecured: JsonDocumentObject,
    proofConfiguration: JsonDocumentObject
  ) => void | Promise<void>;
};

const errorText = (err: unknown): string => {
  if (err instanceof Error) {
    return err.message;
  }
  try {
    return String(err);
  } catch {
    return 'an error without text';
  }
};

const checkVerificationInputs = ({ now, lifetime }: VerifyIden3JwzProofOptions): void => {
  if (!Number.isFinite(now.getTime())) {
    throw new TypeError('now must be a valid date');
  }
  const { minSeconds, maxSeconds } = lifetime;
  if (!Number.isFinite(minSeconds) || !Number.isFinite(maxSeconds) || minSeconds > maxSeconds) {
    throw new TypeError(
      'lifetime must have finite minSeconds and maxSeconds, with minSeconds <= maxSeconds'
    );
  }
};

const isRootMissingError = (err: unknown): boolean => {
  if (errorText(err).includes(VerifiableConstants.ERRORS.ROOT_DOES_NOT_EXIST)) {
    return true;
  }
  try {
    return isRootDoesNotExistError(err);
  } catch {
    return false;
  }
};

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const withoutMember = <T extends Record<string, unknown>>(object: T, name: string): T =>
  Object.fromEntries(Object.entries(object).filter(([member]) => member !== name)) as T;

const verifyZkProof = async (
  compact: string,
  key: Uint8Array | undefined
): Promise<AuthV3PubSignals> => {
  let token: Token;
  try {
    token = await Token.parse(compact);
    if (key === undefined || !(await token.verify(key))) {
      throw new Error('the groth16 proof is not valid');
    }
  } catch (err) {
    throw new Iden3JwzProofRejection(
      'proof_invalid',
      `the JWZ proof does not verify: ${errorText(err)}`
    );
  }
  try {
    return new AuthV3PubSignals().pubSignalsUnmarshal(
      byteEncoder.encode(JSON.stringify(token.zkProof.pub_signals))
    );
  } catch {
    throw new Iden3JwzProofRejection('proof_invalid', 'the JWZ public signals cannot be read');
  }
};

const iden3Signer = (signer: string): { id: bigint; network: string } | null => {
  try {
    const did = DID.parse(signer);
    if (did.method !== DidMethod.Iden3) {
      return null;
    }
    const id = DID.idFromDID(did);
    if (DID.parseFromId(id).string() !== signer) {
      return null;
    }
    const blockchain = DID.blockchainFromId(id);
    const network = DID.networkIdFromId(id);
    const chainId = network === '' ? 0 : getChainId(blockchain, network);
    if (!Number.isInteger(chainId) || chainId <= 0) {
      return null;
    }
    return { id: id.bigInt(), network: `${blockchain}:${network}` };
  } catch {
    return null;
  }
};

const checkGistRoot = async (
  options: VerifyIden3JwzProofOptions,
  network: string,
  signals: AuthV3PubSignals,
  created: number
): Promise<void> => {
  if (!options.networks.includes(network)) {
    throw new Iden3JwzProofRejection('proof_invalid', `the network ${network} is not accepted`);
  }
  const root = signals.GISTRoot.bigInt();
  let info: RootInfo;
  try {
    info = await options.gistRootReader.getGISTRootInfo(root, signals.userID.bigInt());
  } catch (err) {
    const text = errorText(err);
    if (isRootMissingError(err)) {
      throw new Iden3JwzProofRejection('proof_invalid', `the GIST root is not known: ${text}`);
    }
    throw new Iden3JwzProofRejection('state_unavailable', `the State cannot be read: ${text}`);
  }
  if (info.root !== root) {
    throw new Iden3JwzProofRejection('proof_invalid', 'the State answered for another GIST root');
  }
  if (info.replacedByRoot === 0n) {
    return;
  }
  if (info.replacedAtTimestamp === 0n) {
    throw new Iden3JwzProofRejection('proof_invalid', 'the GIST root replacement time is unknown');
  }
  if (
    info.replacedAtTimestamp < BigInt(created - IDEN3_JWZ_MAX_ROOT_REPLACED_BEFORE_CREATED_SECONDS)
  ) {
    throw new Iden3JwzProofRejection(
      'state_superseded',
      "the GIST root was replaced too long before the proof's created"
    );
  }
};

export const verifyIden3JwzProof = async (
  secured: JsonDocumentObject,
  options: VerifyIden3JwzProofOptions
): Promise<{ created: Date; expires: Date }> => {
  checkVerificationInputs(options);
  const now = Math.floor(options.now.getTime() / 1000);
  const proof = Object.hasOwn(secured, 'proof') ? secured.proof : undefined;
  if (!isPlainObject(proof)) {
    throw malformed('the document must have one proof object');
  }
  checkProofShape(proof, options.signer);
  const { created, expires } = checkProofDates(proof, now, options.lifetime);
  const { compact, segments } = decodeProofValue(proof.proofValue as string);
  const circuitId = circuitIdOfHeader(segments[0]);

  const unsecured = withoutMember(secured, 'proof');
  const proofOptions = withoutMember(proof, 'proofValue');
  let payload: string;
  try {
    await options.precheck?.(unsecured, { ...proofOptions, '@context': unsecured['@context'] });
    payload = await computeIden3JwzPayload(unsecured, proofOptions, {
      documentLoader: options.documentLoader,
      allowUnsignedEmptyArrays: options.allowUnsignedEmptyArrays
    });
  } catch (err) {
    throw new Iden3JwzProofRejection(
      'document_malformed',
      `the document cannot be canonicalized: ${errorText(err)}`
    );
  }
  if (!equalBytes(segments[1], byteEncoder.encode(payload))) {
    throw new Iden3JwzProofRejection(
      'proof_hash_mismatch',
      'the JWZ payload is not the hash of this document and its proof options'
    );
  }

  checkZkProofForm(segments[2]);
  const signals = await verifyZkProof(compact, options.verificationKeys[circuitId]);
  const signer = iden3Signer(options.signer);
  if (signer === null || signals.userID.bigInt() !== signer.id) {
    throw new Iden3JwzProofRejection(
      'proof_signer_mismatch',
      `the JWZ was not made by ${options.signer}`
    );
  }
  await checkGistRoot(options, signer.network, signals, created);
  return { created: new Date(created * 1000), expires: new Date(expires * 1000) };
};
