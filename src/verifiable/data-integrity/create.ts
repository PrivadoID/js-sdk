import { DID } from '@iden3/js-iden3-core';
import { ProvingMethodAlg, proving } from '@iden3/js-jwz';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { IPackageManager, JsonDocumentObject } from '../../iden3comm';
import { MediaType } from '../../iden3comm/constants';
import { byteDecoder, byteEncoder, bytesToBase64url } from '../../utils';
import {
  DATA_INTEGRITY_PROOF_TYPE,
  IDEN3_JWZ_RDFC_2026,
  Iden3JwzProof,
  Iden3JwzProofOptions
} from './constants';
import { computeIden3JwzPayload } from './canonical';

const toDateTime = (date: Date): string => date.toISOString().replace(/\.\d+Z$/, 'Z');

export const iden3JwzProofOptions = (
  signer: DID | string,
  created: Date,
  expires: Date
): Iden3JwzProofOptions => {
  if (Number.isNaN(created.getTime()) || Number.isNaN(expires.getTime())) {
    throw new Error('created and expires must be valid dates');
  }
  if (Math.floor(expires.getTime() / 1000) <= Math.floor(created.getTime() / 1000)) {
    throw new Error('expires must be later than created');
  }
  return {
    type: DATA_INTEGRITY_PROOF_TYPE,
    cryptosuite: IDEN3_JWZ_RDFC_2026,
    created: toDateTime(created),
    expires: toDateTime(expires),
    verificationMethod: `${typeof signer === 'string' ? signer : signer.string()}#state-info`,
    proofPurpose: 'assertionMethod'
  };
};

export const proofValueFromCompactJwz = (compactJwz: string): string =>
  `u${bytesToBase64url(byteEncoder.encode(compactJwz))}`;

export type CreateIden3JwzProofOptions = {
  signer: DID;
  created: Date;
  expires: Date;
  packageManager: IPackageManager;
  provingMethodAlg?: ProvingMethodAlg;
  documentLoader?: DocumentLoader;
};

export const createIden3JwzProof = async (
  document: JsonDocumentObject,
  options: CreateIden3JwzProofOptions
): Promise<Iden3JwzProof> => {
  const proofOptions = iden3JwzProofOptions(options.signer, options.created, options.expires);
  const payload = await computeIden3JwzPayload(document, proofOptions, options.documentLoader);
  const packed = await options.packageManager.pack(
    MediaType.ZKPMessage,
    byteEncoder.encode(payload),
    {
      senderDID: options.signer,
      provingMethodAlg:
        options.provingMethodAlg ?? proving.provingMethodGroth16AuthV3_8_32Instance.methodAlg
    }
  );
  return { ...proofOptions, proofValue: proofValueFromCompactJwz(byteDecoder.decode(packed)) };
};
