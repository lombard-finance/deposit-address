import { secp256k1 } from "@noble/curves/secp256k1";
import { segwitTweakHasher } from "./hasher";
import type { Hex } from "./deposit_addr";

/**
 * Compute a tweak and apply it to the specified public key. The tweak value
 * supplied to this function must be exactly 32 bytes long.
 *
 * The tweak hash is computed as sha256(tag || tag || pk_bytes || tweak), where
 * 'tag' is sha256("SegwitTweakTag"), 'pk_bytes' is the 33-byte compressed SEC1
 * serialization of the public key, and 'tweak' is the 32-byte array supplied
 * as an argument.
 *
 * The tweak hash is converted to a secp256k1 scalar t, and the tweaked public
 * key is computed as 'PK + t * G', where 'G' is the canonical generator.
 *
 * @param { Hex } pk The public key to tweak.
 * @param { Uint8Array } tweak The 32-byte tweak value.
 * @return { Uint8Array } The tweaked publick ye as compressed SEC1 bytes.
 */
export function tweakPublicKey(pk: Hex, tweak: Uint8Array): Uint8Array {
  const tweakScalar = computeTweakValue(pk, tweak);
  return tweakWithScalar(pk, tweakScalar);
}

/**
 * Tweak the provided public key with the provided scalar.
 *
 * @param { Hex } pk The public key to tweak, as either compressed or uncompressed SEC1 bytes or hex string.
 * @param { bigint } tweak The tweak to apply.
 * @return { Uint8Array } The tweaked public key as compressed SEC1 bytes.
 */
function tweakWithScalar(pk: Hex, tweak: bigint): Uint8Array {
  // tweak * G
  const tweakPoint = secp256k1.ProjectivePoint.BASE.multiply(tweak);

  // PK
  const pubKey = secp256k1.ProjectivePoint.fromHex(pk);

  // PK + tweak * G
  const tweakedPubKey = pubKey.add(tweakPoint);

  // return compressed key
  const COMPRESSED = true;
  return tweakedPubKey.toRawBytes(COMPRESSED);
}

/**
 * Compute the tweak scalar for a given public key from a byte string.
 *
 * NOTE: the length of `tweak` must be exactly 32 bytes, and should be
 * the output of a collision-resistant hash function.
 *
 * @param { HEX } pk The public key to which the tweak will be applied, as * either compressed or uncompressed SEC1 bytes or hex string.
 * @param { Uint8Array } tweak The 32-byte input to the tweak computation.
 * @return { bigint } The tweak scalar.
 */
function computeTweakValue(pk: Hex, tweak: Uint8Array): bigint {
  if (tweak.length != 32) {
    throw new Error("`tweak` value must have length exactly 32");
  }

  // compute the SEC1 compressed public key
  const COMPRESSED = true;
  const pk_bytes = secp256k1.ProjectivePoint.fromHex(pk).toRawBytes(COMPRESSED);
  if (pk_bytes.length != 33) {
    throw new Error(
      "Expected `pk_bytes` to be 33 bytes, got a different length. This should not happen.",
    );
  }

  //     hash := sha256(tag || tag || pk_bytes || tweak)
  // segwitTweakHasher returns a hasher instance with `tag || tag` already processed
  const hashOut = segwitTweakHasher().update(pk_bytes).update(tweak).digest();

  // convert hash to a scalar by interpreting as a big-endian integer. This
  // will error if `hashOut` is an integer bigger than the order of secp256k1,
  // which happens with probability roughly 2^-128 (i.e., it will never happen).
  return secp256k1.utils.normPrivateKeyToScalar(hashOut);
}
