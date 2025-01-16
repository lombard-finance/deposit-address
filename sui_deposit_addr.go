package deposit_address

import (
	"github.com/btcsuite/btcd/chaincfg"
)

const SuiAddressLength int = 32

type SuiAddress [SuiAddressLength]byte

// SetBytes sets the address to the value of b.
// If b is larger than len(a), b is cropped from the left.
func (a SuiAddress) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-SuiAddressLength:]
	}
	copy(a[SuiAddressLength-len(b):], b)
}

// BytesToSuiAddress returns Address with value b.
// If b is larger than `SuiAddressLength`, b is cropped from the left.
func BytesToSuiAddress(b []byte) SuiAddress {
	var a SuiAddress
	a.SetBytes(b)
	return a
}

// SuiDepositTweak Compute the tweak bytes for a Sui deposit address.
//
// This is defined as
//
//	taggedHash( AuxData || SuiTag || ChainId || LBTCAddress || WalletAddress )
//
// where 'taggedHash' is a sha256 instance as returned by 'depositHasher()',
// 'SuiTag' is 0x01, 'ChainId' is the lombard chain identifier and it is serialized as 32 big-endian
// bytes, LBTCAddress is the LBTC on-chain object, WalletAddress is the Sui addres to receive
// LBTC after deposit, and AuxData is a 32-byte value encoding chain-agnostic auxiliary data.
func SuiDepositTweak(lbtcContract, wallet SuiAddress, chainId, auxData []byte) ([]byte, error) {
	return depositTweak(EcosystemTagSui, lbtcContract[:], wallet[:], chainId, auxData)
}

// SuiDepositSegwitPubkey Compute the segwit public key to be used for a Sui deposit.
//
// - 'pk' is the base (untweaked) public key to tweak
// - 'lbtcContract' is the Sui address of the destination LBTC on-chain object
// - 'wallet' is the Sui address that will claim this deposit
// - 'chainId' is the chain id for the target chain as defined in the Lombard documentation
func SuiDepositSegwitPubkey(pk *PublicKey, lbtcContract, wallet SuiAddress, chainId, auxData []byte) (*PublicKey, error) {
	return depositSegwitPubkey(EcosystemTagSui, pk, lbtcContract[:], wallet[:], chainId, auxData)
}

// SuiDepositSegwitAddr Compute the segwit deposit address to be used for a deposit.
// See SuiDepositSegwitPubkey doc for argument descriptions.
func SuiDepositSegwitAddr(pk *PublicKey, bridge, wallet SuiAddress, chainId, auxData []byte, net *chaincfg.Params) (string, error) {
	return depositSegwitAddr(EcosystemTagSui, pk, bridge[:], wallet[:], chainId, auxData, net)
}
