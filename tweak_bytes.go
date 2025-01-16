package deposit_address

import (
	eth "github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

type BlockchainType string

const (
	BlockchainTypeEvm BlockchainType = "evm"
	BlockchainTypeSui BlockchainType = "sui"
	ChainIdSize       int            = 32
)

// CalcTweakBytes Compute the tweakBytes for a given request, dispatching on `blockchainType`
func CalcTweakBytes(
	blockchainType BlockchainType,
	chainId [ChainIdSize]byte,
	toAddress, lbtcAddress, auxData []byte,
) ([]byte, error) {

	switch blockchainType {
	case BlockchainTypeEvm:
		// evm chain uses 20-byte address
		if len(lbtcAddress) != eth.AddressLength {
			return nil, errors.Errorf("bad LbtcAddress (got %d bytes, expected %d)", len(lbtcAddress), eth.AddressLength)
		}

		lbtcAddr := eth.BytesToAddress(lbtcAddress)
		if len(toAddress) != eth.AddressLength {
			return nil, errors.Errorf("bad ToAddress (got %d bytes, expected %d)", len(toAddress), eth.AddressLength)
		}

		depositAddr := eth.BytesToAddress(toAddress)
		return EvmDepositTweak(lbtcAddr, depositAddr, chainId[:], auxData)
	case BlockchainTypeSui:
		if len(lbtcAddress) != SuiAddressLength {
			return nil, errors.Errorf("bad LbtcAddress (got %d bytes, expected %d)", len(lbtcAddress), SuiAddressLength)
		}

		if len(toAddress) != SuiAddressLength {
			return nil, errors.Errorf("bad ToAddress (got %d bytes, expected %d)", len(toAddress), SuiAddressLength)
		}

		return SuiDepositTweak(BytesToSuiAddress(lbtcAddress), BytesToSuiAddress(toAddress), chainId[:], auxData)
	default:
		return nil, errors.Errorf("unsupported blockchain type: %s", blockchainType)
	}
}
