package deposit_address

import (
	"github.com/lombard-finance/chain/address"
	"github.com/lombard-finance/chain/chainid"
	"github.com/pkg/errors"
)

// CalcTweakBytes Compute the tweakBytes for a given request, dispatching on `blockchainType`
func CalcTweakBytes(
	chainId chainid.LChainId,
	toAddress, lbtcAddress address.Address,
	auxData []byte,
) ([]byte, error) {
	if chainId.Ecosystem() != toAddress.Ecosystem() {
		return nil, errors.Errorf(
			"ecosystem mismatch between chain (%s) and to address (%s:%s)",
			chainId.Ecosystem().String(),
			toAddress.Ecosystem().String(),
			toAddress.String(),
		)
	}
	if chainId.Ecosystem() != lbtcAddress.Ecosystem() {
		return nil, errors.Errorf(
			"ecosystem mismatch between chain (%s) and LBTC address (%s:%s)",
			chainId.Ecosystem().String(),
			lbtcAddress.Ecosystem().String(),
			lbtcAddress.String(),
		)
	}
	return DepositTweak(lbtcAddress, toAddress, chainId, auxData)
}
