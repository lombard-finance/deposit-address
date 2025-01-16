package deposit_address

import (
	"github.com/btcsuite/btcd/chaincfg"
	eth "github.com/ethereum/go-ethereum/common"
)

// EvmDepositTweak Compute the tweak bytes for an EVM deposit address.
//
// This is defined as
//
//	taggedHash( AuxData || EvmTag || ChainId || LBTCAddress || WalletAddress )
//
// where 'taggedHash' is a sha256 instance as returned by 'depositHasher()',
// 'EvmTag' is defined above, 'ChainId' is serialized as 32 big-endian bytes,
// LBTCAddress and WalletAddress are 20-byte EVM addresses, and AuxData is a
// 32-byte value encoding chain-agnostic auxiliary data.
func EvmDepositTweak(lbtcContract, wallet eth.Address, chainId, auxData []byte) ([]byte, error) {
	return depositTweak(EcosystemTagEvm, lbtcContract.Bytes(), wallet.Bytes(), chainId, auxData)
}

// EvmDepositSegwitPubkey Compute the segwit public key to be used for an EVM deposit.
//
// - 'pk' is the base (untweaked) public key to tweak
// - 'lbtcContract' is the EVM address of the destination LBTC contract
// - 'wallet' is the EVM address that will claim this deposit
// - 'chainId' is the chain id for the target chain as defined in the Lombard documentation
func EvmDepositSegwitPubkey(pk *PublicKey, lbtcContract, wallet Address, chainId, auxData []byte) (*PublicKey, error) {
	return depositSegwitPubkey(EcosystemTagEvm, pk, lbtcContract.Bytes(), wallet.Bytes(), chainId, auxData)
}

// EvmDepositSegwitAddr Compute the segwit deposit address to be used for an EVM deposit.
// See EvmDepositSegwitPubkey doc for argument descriptions.
func EvmDepositSegwitAddr(pk *PublicKey, bridge, wallet Address, chainId, auxData []byte, net *chaincfg.Params) (string, error) {
	return depositSegwitAddr(EcosystemTagEvm, pk, bridge.Bytes(), wallet.Bytes(), chainId, auxData, net)
}
