import { DID } from '@iden3/js-iden3-core';
import { proving } from '@iden3/js-jwz';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { base64url } from 'rfc4648';
import { IPackageManager, JsonDocumentObject, PROTOCOL_CONSTANTS } from '../../iden3comm';
import { byteEncoder } from '../../utils';
import {
  DATA_INTEGRITY_PROOF_TYPE,
  IDEN3_JWZ_CIRCUIT_HEADERS,
  IDEN3_JWZ_PROOF_PURPOSE,
  IDEN3_JWZ_PROOF_VALUE_PREFIX,
  IDEN3_JWZ_RDFC_2026,
  IDEN3_JWZ_STATE_INFO_FRAGMENT,
  Iden3JwzProof,
  Iden3JwzProofOptions
} from './constants';
import { formatIden3JwzDate } from './dates';
import { computeIden3JwzPayload } from './canonical';

const wholeSeconds = (date: Date): number => Math.floor(date.getTime() / 1000);

export const iden3JwzProofOptions = (
  signer: DID | string,
  created: Date,
  expires: Date
): Iden3JwzProofOptions => {
  const createdSeconds = wholeSeconds(created);
  const expiresSeconds = wholeSeconds(expires);
  if (expiresSeconds <= createdSeconds) {
    throw new Error('expires must be later than created');
  }
  const signerDid = typeof signer === 'string' ? signer : signer.string();
  return {
    type: DATA_INTEGRITY_PROOF_TYPE,
    cryptosuite: IDEN3_JWZ_RDFC_2026,
    created: formatIden3JwzDate(createdSeconds),
    expires: formatIden3JwzDate(expiresSeconds),
    verificationMethod: `${signerDid}${IDEN3_JWZ_STATE_INFO_FRAGMENT}`,
    proofPurpose: IDEN3_JWZ_PROOF_PURPOSE
  };
};

export const proofValueFromCompactJwz = (compactJwz: string): string =>
  `${IDEN3_JWZ_PROOF_VALUE_PREFIX}${base64url.stringify(byteEncoder.encode(compactJwz), {
    pad: false
  })}`;

export type CreateIden3JwzProofOptions = {
  signer: DID;
  created: Date;
  expires: Date;
  packageManager: IPackageManager;
  documentLoader: DocumentLoader;
  allowUnsignedEmptyArrays?: boolean;
};

export const createIden3JwzProof = async (
  document: JsonDocumentObject,
  options: CreateIden3JwzProofOptions
): Promise<Iden3JwzProof> => {
  const proofOptions = iden3JwzProofOptions(options.signer, options.created, options.expires);
  const payload = await computeIden3JwzPayload(document, proofOptions, {
    documentLoader: options.documentLoader,
    allowUnsignedEmptyArrays: options.allowUnsignedEmptyArrays
  });
  const packed = await options.packageManager.pack(
    PROTOCOL_CONSTANTS.MediaType.ZKPMessage,
    byteEncoder.encode(payload),
    {
      senderDID: options.signer,
      provingMethodAlg: proving.provingMethodGroth16AuthV3_8_32Instance.methodAlg
    }
  );
  const compact = new TextDecoder().decode(packed);
  const [header, jwzPayload] = compact.split('.');
  const expectedHeader = base64url.stringify(
    byteEncoder.encode(IDEN3_JWZ_CIRCUIT_HEADERS['authV3-8-32']),
    { pad: false }
  );
  if (header !== expectedHeader) {
    throw new Error('the JWZ header is not the exact header of authV3-8-32');
  }
  if (jwzPayload !== base64url.stringify(byteEncoder.encode(payload), { pad: false })) {
    throw new Error('the JWZ payload is not the computed payload');
  }
  return { ...proofOptions, proofValue: proofValueFromCompactJwz(compact) };
};
