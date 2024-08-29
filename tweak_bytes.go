package deposit_address

import (
	eth "github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

type BlockchainType string

const (
	BlockchainTypeEvm BlockchainType = "evm"
)

// CalcTweakBytes Compute the tweakBytes for a given request, dispatching on `blockchainType`
func CalcTweakBytes(
	blockchainType BlockchainType,
	chainId [32]byte,
	toAddress, lbtcAddress, auxData []byte,
) ([]byte, error) {

	switch blockchainType {
	case BlockchainTypeEvm:
		// evm chain uses 20-byte address
		if len(lbtcAddress) != 20 {
			return nil, errors.Errorf("bad LbtcAddress (got %d bytes, expected 20)", len(lbtcAddress))
		}

		lbtcAddr := eth.BytesToAddress(lbtcAddress)
		if len(toAddress) != 20 {
			return nil, errors.Errorf("bad ToAddress (got %d bytes, expected 20)", len(toAddress))
		}

		depositAddr := eth.BytesToAddress(toAddress)
		return EvmDepositTweak(lbtcAddr, depositAddr, chainId[:], auxData)
	default:
		return nil, errors.Errorf("unsupported blockchain type: %s", blockchainType)
	}
}
