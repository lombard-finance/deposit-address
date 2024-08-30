import { depositHasher } from "./hasher";
import { tweakPublicKey } from "./segwit_tweak";
import { hexToBytes } from "./utils";
import type { Network } from "bitcoinjs-lib";
import { networks, payments } from "bitcoinjs-lib";

/**
 * Compute the segwit public key to be used for an EVM deposit. Returns the
 * 33-byte compressed SEC1 serialization of the public key.
 *
 * @param { Hex } pk The public key to be tweaked, in SEC1 (compressed or uncompressed) format.
 * @param { Hex } lbtcContract The LBTC contract address on the target chain.
 * @param { Hex } wallet The EVM wallet that will receive the minted LBTC.
 * @param { HEX } chainId A 32-byte big-endian encoding of the target chain's chain-id.
 * @param { Hex } auxData A 32-byte auxiliary data array encoding chain-agnostic information.
 * @return { Uint8Array } The SEC1 compressed serialization of the tweaked public key.
 */
export function evmDepositSegwitPubkey(
  pk: Hex,
  lbtcContract: Hex,
  wallet: Hex,
  chainId: Hex,
  auxData: Hex,
): Uint8Array {
  const tweakBytes = evmDepositTweak(lbtcContract, wallet, chainId, auxData);
  return tweakPublicKey(pk, tweakBytes);
}

/**
 * Compute the segwit deposit address to be used for an EVM deposit.
 *
 * @param { Hex } pk The public key to be tweaked, in SEC1 (compressed or uncompressed) format.
 * @param { Hex } lbtcContract The LBTC contract address on the target chain.
 * @param { Hex } wallet The EVM wallet that will receive the minted LBTC.
 * @param { HEX } chainId A 32-byte big-endian encoding of the target chain's chain-id.
 * @param { Hex } auxData A 32-byte auxiliary data array encoding chain-agnostic information.
 * @param { Network | undefined } network The Bitcoin network for which to generate an address. If `unefined`, mainnet is assumed.
 * @return { string } The segwit address corresponding to the tweaked key.
 */
export function evmDepositSegwitAddr(
  pk: Hex,
  lbtcContract: Hex,
  wallet: Hex,
  chainId: Hex,
  auxData: Hex,
  network: Network,
): string {
  const tweakedPk = evmDepositSegwitPubkey(
    pk,
    lbtcContract,
    wallet,
    chainId,
    auxData,
  );
  const { address } = payments.p2wpkh({
    pubkey: Buffer.from(tweakedPk),
    network: network === undefined ? networks.bitcoin : network,
  });
  if (address === undefined) {
    throw new Error("Unable to compute segwit address.");
  }
  return address;
}

/**
 * A hex string or byte buffer, as defined in the @noble/secp256k1 library
 */
export type Hex = string | Uint8Array;

/**
 * Compute the tweak bytes for an EVM deposit address.
 *
 * This is defined as
 *
 *     sha256(tag || tag || auxData || evmTag || chainId || lbtcAddress || walletAddress)
 *
 * where 'tag' is 'sha256("LombardDepositAddr")', 'auxData' is a 32-byte value
 * encoding chain-agnostic data, 'evmTag' is the byte '0x00', 'chainId' is a
 * 32-byte value, and 'lbtcAddress' and 'walletAddress' are 20-byte EVM addresses
 * representing, respectively, the LBTC address on the target chain and the
 * wallet address to which LBTC will be minted.
 *
 * @param { Hex } lbtcContract The LBTC contract address on the target chain.
 * @param { Hex } wallet The EVM wallet that will receive the minted LBTC.
 * @param { HEX } chainId A 32-byte big-endian encoding of the target chain's chain-id.
 * @param { Hex } auxData A 32-byte auxiliary data array encoding chain-agnostic information.
 * @return { Uint8Array } The tweak hash for the specified values.
 */
export function evmDepositTweak(
  lbtcContract: Hex,
  wallet: Hex,
  chainId: Hex,
  auxData: Hex,
): Uint8Array {
  lbtcContract = hexToBytes(lbtcContract);
  wallet = hexToBytes(wallet);
  chainId = hexToBytes(chainId);
  auxData = hexToBytes(auxData);

  if (lbtcContract.length != 20) {
    throw new Error("lbtcContract must be 20 bytes.");
  }
  if (wallet.length != 20) {
    throw new Error("wallet must be 20 bytes.");
  }
  if (auxData.length != 32) {
    throw new Error("auxData must be 32 bytes.");
  }
  if (chainId.length != 32) {
    throw new Error("chainId must be 32 bytes.");
  }

  // sha256(tag || tag || auxData || 0x00 || chain-id || lbtcContract || wallet)
  return depositHasher()
    .update(auxData)
    .update(new Uint8Array([0x00])) // EVM tag is a single 0 byte
    .update(chainId)
    .update(lbtcContract)
    .update(wallet)
    .digest();
}
