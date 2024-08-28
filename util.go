package deposit_address

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func PubkeyToSegwitAddr(pk *PublicKey, net *chaincfg.Params) (string, error) {
	// compute the p2wpkh (segwit) address for this pubkey
	pkH160 := btcutil.Hash160(pk.SerializeCompressed())
	pkAddr, err := btcutil.NewAddressWitnessPubKeyHash(pkH160, net)
	if err != nil {
		return "", err
	}
	return pkAddr.EncodeAddress(), nil
}
