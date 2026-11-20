import { base64url } from 'rfc4648';
import { byteDecoder, byteEncoder } from '../../utils';
import {
  DATA_INTEGRITY_PROOF_TYPE,
  IDEN3_JWZ_CIRCUIT_HEADERS,
  IDEN3_JWZ_MAX_CREATED_AHEAD_SECONDS,
  IDEN3_JWZ_PROOF_MEMBERS,
  IDEN3_JWZ_PROOF_PURPOSE,
  IDEN3_JWZ_PROOF_VALUE_PREFIX,
  IDEN3_JWZ_RDFC_2026,
  IDEN3_JWZ_STATE_INFO_FRAGMENT,
  ProofLifetime
} from './constants';
import { Iden3JwzProofRejection } from './rejection';
import { parseIden3JwzDate } from './dates';
import { parseStrictJsonObject } from './strict-json';

export type JwzSegments = [Uint8Array, Uint8Array, Uint8Array];

const BN254_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const AUTH_V3_PUBLIC_SIGNALS = 3;
const DECIMAL_FIELD_ELEMENT = /^(0|[1-9][0-9]*)$/;
const BASE64URL_ALPHABET = /^[A-Za-z0-9_-]*$/;

export const malformed = (detail: string): Iden3JwzProofRejection =>
  new Iden3JwzProofRejection('proof_malformed', detail);

export const equalBytes = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length && left.every((byte, index) => byte === right[index]);

export const checkProofShape = (proof: Record<string, unknown>, signer: string): void => {
  for (const member of IDEN3_JWZ_PROOF_MEMBERS) {
    if (!Object.hasOwn(proof, member) || typeof proof[member] !== 'string') {
      throw malformed(`the proof's ${member} must be a string`);
    }
  }
  if (Object.keys(proof).length !== IDEN3_JWZ_PROOF_MEMBERS.length) {
    throw malformed(`the proof must have exactly ${IDEN3_JWZ_PROOF_MEMBERS.join(', ')}`);
  }
  if (proof.type !== DATA_INTEGRITY_PROOF_TYPE || proof.cryptosuite !== IDEN3_JWZ_RDFC_2026) {
    throw malformed(`the proof must be a ${DATA_INTEGRITY_PROOF_TYPE} of ${IDEN3_JWZ_RDFC_2026}`);
  }
  const verificationMethod = signer + IDEN3_JWZ_STATE_INFO_FRAGMENT;
  if (
    proof.verificationMethod !== verificationMethod ||
    proof.proofPurpose !== IDEN3_JWZ_PROOF_PURPOSE
  ) {
    throw malformed(`the proof must be an ${IDEN3_JWZ_PROOF_PURPOSE} by ${verificationMethod}`);
  }
  const proofValue = proof.proofValue as string;
  if (proofValue.length < 2 || !proofValue.startsWith(IDEN3_JWZ_PROOF_VALUE_PREFIX)) {
    throw malformed(`the proofValue must be multibase base64url (${IDEN3_JWZ_PROOF_VALUE_PREFIX})`);
  }
};

export const checkProofDates = (
  proof: Record<string, unknown>,
  now: number,
  lifetime: ProofLifetime
): { created: number; expires: number } => {
  const created = parseIden3JwzDate(proof.created as string);
  const expires = parseIden3JwzDate(proof.expires as string);
  if (created === null || expires === null) {
    throw malformed("the proof's created and expires must be dates YYYY-MM-DDThh:mm:ssZ");
  }
  if (created > now + IDEN3_JWZ_MAX_CREATED_AHEAD_SECONDS) {
    throw malformed("the proof's created is too far ahead of the verifier's clock");
  }
  const seconds = expires - created;
  if (seconds < lifetime.minSeconds || seconds > lifetime.maxSeconds) {
    throw malformed(
      `the proof's expires must be ${lifetime.minSeconds} s to ${lifetime.maxSeconds} s after its created`
    );
  }
  if (now >= expires) {
    throw new Iden3JwzProofRejection('proof_expired', 'the proof has expired');
  }
  return { created, expires };
};

const parseCanonicalBase64url = (text: string): Uint8Array | null => {
  if (!BASE64URL_ALPHABET.test(text)) {
    return null;
  }
  try {
    const bytes = base64url.parse(text, { loose: true });
    return base64url.stringify(bytes, { pad: false }) === text ? bytes : null;
  } catch {
    return null;
  }
};

export const decodeProofValue = (
  proofValue: string
): { compact: string; segments: JwzSegments } => {
  const bytes = parseCanonicalBase64url(proofValue.slice(IDEN3_JWZ_PROOF_VALUE_PREFIX.length));
  if (bytes === null) {
    throw malformed('the proofValue must be canonical base64url without padding');
  }
  if (bytes.some((byte) => byte >= 0x80)) {
    throw malformed('the compact JWZ must be ASCII');
  }
  const compact = byteDecoder.decode(bytes);
  const parts = compact.split('.');
  if (parts.length !== 3) {
    throw malformed('the compact JWZ must have exactly three segments');
  }
  const segments = parts.map((part) => {
    const segment = parseCanonicalBase64url(part);
    if (segment === null || segment.length === 0) {
      throw malformed('each JWZ segment must be non-empty canonical base64url without padding');
    }
    return segment;
  });
  return { compact, segments: segments as JwzSegments };
};

export const circuitIdOfHeader = (segment: Uint8Array): string => {
  const circuitId = Object.keys(IDEN3_JWZ_CIRCUIT_HEADERS).find((id) =>
    equalBytes(segment, byteEncoder.encode(IDEN3_JWZ_CIRCUIT_HEADERS[id]))
  );
  if (circuitId === undefined) {
    throw malformed('the JWZ header is not exactly the header of an allowed circuit');
  }
  return circuitId;
};

export const checkZkProofForm = (segment: Uint8Array): void => {
  let zkProof: Record<string, unknown>;
  try {
    zkProof = parseStrictJsonObject(segment);
  } catch {
    throw malformed('the JWZ proof must be a strict JSON object');
  }
  if (
    Object.keys(zkProof).length !== 2 ||
    !Object.hasOwn(zkProof, 'proof') ||
    !Object.hasOwn(zkProof, 'pub_signals')
  ) {
    throw malformed('the JWZ proof must have exactly proof and pub_signals');
  }
  const signals = zkProof.pub_signals;
  if (
    !Array.isArray(signals) ||
    signals.length !== AUTH_V3_PUBLIC_SIGNALS ||
    !signals.every((signal) => typeof signal === 'string')
  ) {
    throw malformed(`the JWZ pub_signals must be ${AUTH_V3_PUBLIC_SIGNALS} strings`);
  }
  for (const signal of signals as string[]) {
    if (!DECIMAL_FIELD_ELEMENT.test(signal) || BigInt(signal) >= BN254_FIELD_MODULUS) {
      throw malformed('each JWZ public signal must be a decimal field element');
    }
  }
};
