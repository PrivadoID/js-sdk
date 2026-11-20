import { Token } from '@iden3/js-jwz';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { IPackageManager, JsonDocumentObject, ZKPPacker } from '../../iden3comm';
import { DEFAULT_AUTH_VERIFY_DELAY, MediaType } from '../../iden3comm/constants';
import { base64UrlToBytes, byteDecoder, byteEncoder, bytesToBase64url } from '../../utils';
import { DATA_INTEGRITY_PROOF_TYPE, IDEN3_JWZ_RDFC_2026 } from './constants';
import { computeIden3JwzPayload } from './canonical';
import { proofValueFromCompactJwz } from './create';

export type VerifyIden3JwzProofOptions = {
  signer: string;
  packageManager: IPackageManager;
  maxProofLifetime: number;
  now?: Date;
  documentLoader?: DocumentLoader;
};

const requireMember = (proof: JsonDocumentObject, name: string, expected: string): void => {
  if (proof[name] !== expected) {
    throw new Error(`the proof ${name} must be ${expected}`);
  }
};

const DATE_TIME_FORM = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const requireDate = (proof: JsonDocumentObject, name: string): Date => {
  const value = proof[name];
  if (typeof value !== 'string' || !DATE_TIME_FORM.test(value)) {
    throw new Error(`the proof ${name} must have the form YYYY-MM-DDThh:mm:ssZ`);
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`the proof ${name} must be a valid date`);
  }
  return date;
};

export const verifyIden3JwzProof = async (
  secured: JsonDocumentObject,
  {
    signer,
    packageManager,
    maxProofLifetime,
    now = new Date(),
    documentLoader
  }: VerifyIden3JwzProofOptions
): Promise<void> => {
  const { proof, ...document } = secured;
  if (typeof proof !== 'object' || proof === null || Array.isArray(proof)) {
    throw new Error('the document must have one proof object');
  }
  requireMember(proof, 'type', DATA_INTEGRITY_PROOF_TYPE);
  requireMember(proof, 'cryptosuite', IDEN3_JWZ_RDFC_2026);
  requireMember(proof, 'proofPurpose', 'assertionMethod');
  requireMember(proof, 'verificationMethod', `${signer}#state-info`);
  const created = requireDate(proof, 'created');
  const expires = requireDate(proof, 'expires');
  if (!(expires.getTime() > created.getTime())) {
    throw new Error('the proof expires must be later than created');
  }
  if (!(expires.getTime() - created.getTime() <= maxProofLifetime)) {
    throw new Error('the proof lifetime is longer than maxProofLifetime');
  }
  if (!(created.getTime() <= now.getTime() + DEFAULT_AUTH_VERIFY_DELAY)) {
    throw new Error('the proof is created too far ahead of now');
  }
  if (!(now.getTime() < expires.getTime())) {
    throw new Error('the proof is expired');
  }
  const { proofValue } = proof;
  if (typeof proofValue !== 'string' || !proofValue.startsWith('u')) {
    throw new Error('the proofValue must start with u');
  }
  const compactJwz = byteDecoder.decode(base64UrlToBytes(proofValue.slice(1)));
  const token = await Token.parse(compactJwz);
  if (proofValueFromCompactJwz(compactJwz) !== proofValue) {
    throw new Error('the proofValue is not canonical');
  }
  const payload = await computeIden3JwzPayload(document, proof, documentLoader);
  const [header, payloadSegment] = compactJwz.split('.');
  if (payload !== token.getPayload()) {
    throw new Error('the JWZ payload is not the payload of the document and the proof options');
  }
  if (header !== bytesToBase64url(byteEncoder.encode(token.serializeHeaders()))) {
    throw new Error('the JWZ header segment is not canonical');
  }
  if (payloadSegment !== bytesToBase64url(byteEncoder.encode(payload))) {
    throw new Error('the JWZ payload segment is not canonical');
  }
  const packer = packageManager.packers.get(MediaType.ZKPMessage);
  if (!(packer instanceof ZKPPacker)) {
    throw new Error('the package manager must have a ZKP packer');
  }
  await packer.verifyToken(token, signer, {
    referenceTime: created,
    acceptedStateTransitionDelay: DEFAULT_AUTH_VERIFY_DELAY
  });
};
