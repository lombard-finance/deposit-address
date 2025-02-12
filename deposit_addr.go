package deposit_address

import (
	"crypto/sha256"
	"hash"

	"github.com/btcsuite/btcd/chaincfg"
	eth "github.com/ethereum/go-ethereum/common"
	"github.com/lombard-finance/chain/chainid"
	"github.com/pkg/errors"
)

type Address = eth.Address
type Sha256 = hash.Hash

const (
	DepositAddrTag     = "LombardDepositAddr"
	DeprecatedChainTag = byte(0)
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

// DepositTweak Compute the tweak bytes for a deposit address.
//
// This is generally defined as
//
//	taggedHash( AuxData || ChainId || LBTCAddress || WalletAddress )
//
// where 'taggedHash' is a sha256 instance as returned by 'depositHasher()', 'ChainId' is a 32 bytes
// big-endian identifier of the chain, LBTCAddress and WalletAddress are byte arrays representing
// the respective addresses on the selected chain, and AuxData is a 32-byte value encoding
// chain-agnostic auxiliary data.
func DepositTweak(lbtcContract, wallet []byte, chainId chainid.LChainId, auxData []byte) ([]byte, error) {
	if len(auxData) != AuxDataSize {
		return nil, errors.Errorf("wrong size for auxData (got %v, want %v)", len(auxData), AuxDataSize)
	}

	h := depositHasher()

	// aux data (32 bytes)
	h.Write(auxData[:])

	// 1 byte tag previously used to select chain, now deprecated and constant
	// for backward compatibility
	h.Write([]byte{DeprecatedChainTag})

	// chain-id (32 bytes) as defined by Lombard documentation
	h.Write(chainId.Bytes())

	// LBTC contract address
	h.Write(lbtcContract)

	// Destination wallet address
	h.Write(wallet)

	return h.Sum(nil), nil
}

// DepositSegwitPubkey Compute the segwit public key to be used for a deposit.
//
// - 'pk' is the base (untweaked) public key to tweak
// - 'lbtcContract' is the address of the LBTC contract or object on the destination chain
// - 'wallet' is the address that will claim the deposit on the destination chain
// - 'chainId' is the chain id for the target chain as defined in the Lombard documentation
func DepositSegwitPubkey(pk *PublicKey, lbtcContract, wallet []byte, chainId chainid.LChainId, auxData []byte) (*PublicKey, error) {
	// compute tweak bytes
	tweakBytes, err := DepositTweak(lbtcContract, wallet, chainId, auxData)
	if err != nil {
		return nil, err
	}

	return TweakPublicKey(pk, tweakBytes)
}

// DepositSegwitAddr Compute the segwit deposit address to be used for a deposit on the specified chain.
// See depositSegwitPubkey doc for argument descriptions.
func DepositSegwitAddr(pk *PublicKey, bridge, wallet []byte, chainId chainid.LChainId, auxData []byte, net *chaincfg.Params) (string, error) {
	// compute the pubkey
	tpk, err := DepositSegwitPubkey(pk, bridge, wallet, chainId, auxData)
	if err != nil {
		return "", err
	}

	return PubkeyToSegwitAddr(tpk, net)
}
