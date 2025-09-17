import { sha256 } from "@noble/hashes/sha256";
import type { Hash } from "@noble/hashes/utils";

// NOTE: we use `any` here because @noble/hashes v1.4.0
// forgot to export the SHA256 type. And we do the silly
// thing wehere we wrap the disable around the doc comment
// because eslint and prettier are garbage software.

const DEPOSIT_AUX_TAG = "LombardDepositAux";
const DEPOSIT_ADDR_TAG = "LombardDepositAddr";
const SEGWIT_TWEAK_TAG = "SegwitTweak";

/**
 * Construct a tagged hasher in the style of BIP341 for a supplied tag string.
 *
 * For a given tag, the BIP341 tagged hasher is defined as:
 *
 *     tagBytes := sha256(tag)
 *     taggedHasher(data) := sha256(tagBytes || tagBytes || data)
 *
 * where `||` represents concatenation and `data` is arbitrary input data.
 *
 * This function returns a hasher instance with `tagBytes` fed into it
 * (twice, as specified!) already.
 *
 * @param { string } tag The tag to apply to this hasher.
 * @return { Hash } A hasher instance with the specified tag applied.
 */
function taggedHasher(
  tag: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Hash<any> {
  // compute the tag bytes as defined in BIP341
  const tagBytes = sha256(tag);

  // create a new hasher, then hash the tag bytes twice
  const hasher = sha256.create().update(tagBytes).update(tagBytes);

  return hasher;
}

/**
 * Construct a tagged hasher for computing Lombard auxiliary data.
 *
 * @return { Hash } A hasher instance with the tag applied.
 */
export function auxDataHasher() {
  return taggedHasher(DEPOSIT_AUX_TAG);
}

/**
 * Construct a tagged hasher for computing the Lombard deposit data
 * tweaking input.
 *
 * @return { Hash } A hasher instance with the tag applied.
 */
export function depositHasher() {
  return taggedHasher(DEPOSIT_ADDR_TAG);
}

/**
 * Construct a tagged hasher for computing a tweaked segwit address.
 *
 * @return { Hash } A hasher instance with the tag applied.
 */
export function segwitTweakHasher() {
  return taggedHasher(SEGWIT_TWEAK_TAG);
}
