import * as utils from "@noble/curves/abstract/utils";
import { auxDataHasher } from "./hasher";

/**
 * Compute v0 AuxData given a nonce and referrer-id.
 *
 * This is defined as 'sha256(tag || tag || version0 || nonce || referrer-id)'
 * where 'tag' is 'sha256("LombardDepositAux")', version0 is the byte 0x0,
 * nonce is an unsigned 32-bit integer encoded in 4 big-endian bytes, and
 * referrer-id is an arbitrary array that can be up to 256 bytes.
 *
 * @param { number } nonce A 32-bit unsigned integer nonce value.
 * @param { Uint8Array | string } referrerId An arbitrary value up to 256 bytes.
 * @return { Uint8Array } The aux-data hash value.
 */
export function computeAuxDataV0(
  nonce: number,
  referrerId: Uint8Array | string,
): Uint8Array {
  if (referrerId.length > 256) {
    throw new Error("ReferrerId must be less than 256 bytes");
  }

  // compute 4 big-endian nonce bytes
  const nonceBytes = utils.numberToBytesBE(BigInt(nonce), 4);

  // sha256(tag || tag || 0x00 || 4 nonce bytes || referrer-id)
  return auxDataHasher()
    .update(new Uint8Array([0x00]))
    .update(nonceBytes)
    .update(referrerId)
    .digest();
}
