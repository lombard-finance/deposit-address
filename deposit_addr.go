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

// depositTweak Compute the tweak bytes for a deposit address.
//
// This is generally defined as
//
//	taggedHash( AuxData || EcosystemTag || ChainId || LBTCAddress || WalletAddress )
//
// where 'taggedHash' is a sha256 instance as returned by 'depositHasher()',
// 'EcosystemTag' is defined in the dedicated file as a type, 'ChainId' is serialized as 32
// big-endian bytes, LBTCAddress and WalletAddress are byte arrays representing the respective addresses
// on the selected chain, and AuxData is a 32-byte value encoding chain-agnostic auxiliary data.
func depositTweak(eTag EcosystemTag, lbtcContract, wallet, chainId, auxData []byte) ([]byte, error) {
	if len(auxData) != AuxDataSize {
		return nil, errors.Errorf("wrong size for auxData (got %v, want %v)", len(auxData), AuxDataSize)
	}
	if len(chainId) != ChainIdSize {
		return nil, errors.Errorf("wrong size for chainId (got %v, want %v)", len(chainId), ChainIdSize)
	}

	h := depositHasher()

	// aux data (32 bytes)
	h.Write(auxData[:])

	// ecosystem tag (1 byte)
	h.Write([]byte{eTag})

	// chain-id (32 bytes) as defined by Lombard documentation
	// we zero-pad if `chainId` is less than 32 bytes and error if it is more.
	h.Write(chainId[:])

	// LBTC contract address
	h.Write(lbtcContract)

	// Destination wallet address
	h.Write(wallet)

	return h.Sum(nil), nil
}

// depositSegwitPubkey Compute the segwit public key to be used for a deposit.
//
// - 'eTag' is the ecosystem tag to select the
// - 'pk' is the base (untweaked) public key to tweak
// - 'lbtcContract' is the address of the LBTC contract or object on the destination chain
// - 'wallet' is the address that will claim the deposit on the destination chain
// - 'chainId' is the chain id for the target chain as defined in the Lombard documentation
func depositSegwitPubkey(eTag EcosystemTag, pk *PublicKey, lbtcContract, wallet, chainId, auxData []byte) (*PublicKey, error) {
	// compute tweak bytes
	tweakBytes, err := depositTweak(eTag, lbtcContract, wallet, chainId, auxData)
	if err != nil {
		return nil, err
	}

	return TweakPublicKey(pk, tweakBytes)
}

// depositSegwitAddr Compute the segwit deposit address to be used for a deposit on the specified chain.
// See depositSegwitPubkey doc for argument descriptions.
func depositSegwitAddr(eTag EcosystemTag, pk *PublicKey, bridge, wallet, chainId, auxData []byte, net *chaincfg.Params) (string, error) {
	// compute the pubkey
	tpk, err := depositSegwitPubkey(eTag, pk, bridge, wallet, chainId, auxData)
	if err != nil {
		return "", err
	}

	return PubkeyToSegwitAddr(tpk, net)
}
