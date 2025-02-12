package deposit_address

import (
	eth "github.com/ethereum/go-ethereum/common"
	"github.com/lombard-finance/chain/chainid"
	"github.com/pkg/errors"
)

const SuiAddressLength = 32

// CalcTweakBytes Compute the tweakBytes for a given request, dispatching on `blockchainType`
func CalcTweakBytes(
	chainId chainid.LChainId,
	toAddress, lbtcAddress, auxData []byte,
) ([]byte, error) {

	switch chainId.(type) {
	case chainid.EVMLChainId:
		if len(lbtcAddress) != eth.AddressLength {
			return nil, errors.Errorf("bad LbtcAddress (got %d bytes, expected %d)", len(lbtcAddress), eth.AddressLength)
		}
		if len(toAddress) != eth.AddressLength {
			return nil, errors.Errorf("bad ToAddress (got %d bytes, expected %d)", len(toAddress), eth.AddressLength)
		}
		return DepositTweak(lbtcAddress, toAddress, chainId, auxData)
	case chainid.SuiLChainId:
		if len(lbtcAddress) != SuiAddressLength {
			return nil, errors.Errorf("bad LbtcAddress (got %d bytes, expected %d)", len(lbtcAddress), SuiAddressLength)
		}
		if len(toAddress) != SuiAddressLength {
			return nil, errors.Errorf("bad ToAddress (got %d bytes, expected %d)", len(toAddress), SuiAddressLength)
		}
		return DepositTweak(lbtcAddress, toAddress, chainId, auxData)
	default:
		return nil, errors.Errorf("unsupported blockchain type: %s", chainId.Ecosystem().String())
	}
}
