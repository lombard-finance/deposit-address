package deposit_address

import (
	"crypto/sha256"
	"hash"

	"github.com/btcsuite/btcd/chaincfg"
	eth "github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

type Address = eth.Address
type Sha256 = hash.Hash

// Chain type tags
//
// These tags are used to distinguish deposit addresses for different chain types
const (
	ChainIdSize int   = 32
	EvmTag      uint8 = 0
	// TODO define more chain-type identifiers
)

const (
	DepositAddrTag = "LombardDepositAddr"
)

// Create a tagged hasher used to compute Lombard deposit addresses
//
// Returns a hasher that has been initialized with 'tag || tag', where
// 'tag' is sha256(DepositAddrTag)
func depositHasher() Sha256 {
	h := sha256.New()

	// compute the tag
	h.Write([]byte(DepositAddrTag))
	tag := h.Sum(nil)

	// initialize the hasher with the tag
	h.Reset()
	h.Write(tag)
	h.Write(tag)

	return h
}

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
func EvmDepositTweak(lbtcContract, wallet Address, chainId, auxData []byte) ([]byte, error) {
	if len(auxData) != AuxDataSize {
		return nil, errors.Errorf("wrong size for auxData (got %v, want %v)", len(auxData), AuxDataSize)
	}
	if len(chainId) != ChainIdSize {
		return nil, errors.Errorf("wrong size for chainId (got %v, want %v)", len(chainId), ChainIdSize)
	}

	h := depositHasher()

	// aux data (32 bytes)
	h.Write(auxData[:])

	// EVM tag (1 byte)
	h.Write([]byte{EvmTag})

	// EVM chain-id (32 bytes)
	// we zero-pad if `chainId` is less than 32 bytes and error if it is more.
	h.Write(chainId[:])

	// LBTC contract address (20 bytes)
	h.Write(lbtcContract.Bytes())

	// Destination wallet address (20 bytes)
	h.Write(wallet.Bytes())

	return h.Sum(nil), nil
}

// EvmDepositSegwitPubkey Compute the segwit public key to be used for an EVM deposit.
//
// - 'pk' is the base (untweaked) public key to tweak
// - 'lbtcContract' is the EVM address of the destination LBTC bridge contract
// - 'wallet' is the EVM address that will claim this deposit
// - 'chainId' is the chain id for the target EVM chain
func EvmDepositSegwitPubkey(pk *PublicKey, lbtcContract, wallet Address, chainId, auxData []byte) (*PublicKey, error) {
	// compute tweak bytes
	tweakBytes, err := EvmDepositTweak(lbtcContract, wallet, chainId, auxData)
	if err != nil {
		return nil, err
	}

	return TweakPublicKey(pk, tweakBytes)
}

// EvmDepositSegwitAddr Compute the segwit deposit address to be used for an EVM deposit.
// See EvmDepositSegwitPubkey doc for argument descriptions.
func EvmDepositSegwitAddr(pk *PublicKey, bridge, wallet Address, chainId, auxData []byte, net *chaincfg.Params) (string, error) {
	// compute the pubkey
	tpk, err := EvmDepositSegwitPubkey(pk, bridge, wallet, chainId, auxData)
	if err != nil {
		return "", err
	}

	return PubkeyToSegwitAddr(tpk, net)
}
