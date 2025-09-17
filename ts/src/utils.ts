import type { Hex } from "./deposit_addr";
import * as utils from "@noble/curves/abstract/utils";

/**
 * Convert a value of type 'Hex' into a byte array.
 *
 * @param { Hex } hex The value to convert.
 * @return { Uint8Array } The result of conversion.
 */
export function hexToBytes(hex: Hex): Uint8Array {
  if (hex instanceof Uint8Array) {
    return hex;
  }

  if (typeof hex === "string") {
    hex = hex.slice(0, 2) === "0x" ? hex.slice(2) : hex;
    return utils.hexToBytes(hex);
  }

  throw new Error(
    "Expected string or Uint8Array, got something else. This should not happen.",
  );
}
