package tweaker

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	depositaddr "github.com/lombard-finance/deposit-address"
	"github.com/pkg/errors"
)

type Tweaker struct {
	PublicKey *secp256k1.PublicKey
}

func NewTweaker(
	publicKey []byte,
) (*Tweaker, error) {
	parsedPublicKey, err := secp256k1.ParsePubKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &Tweaker{PublicKey: parsedPublicKey}, nil
}

// DerivePubkey Derive a new deposit public key from a 32-byte tweak and return the PubKey
func (d *Tweaker) DerivePubkey(tweakBytes []byte) (*secp256k1.PublicKey, error) {
	return depositaddr.TweakPublicKey(d.PublicKey, tweakBytes)
}

// DeriveSegwit Derive a new deposit public key from a 32-byte tweak, then build a
// `KeyWithDestination` value from it
func (d *Tweaker) DeriveSegwit(tweakBytes []byte, net *chaincfg.Params) (address btcutil.Address, tweakedPublicKey *secp256k1.PublicKey, err error) {
	tweakedPublicKey, err = d.DerivePubkey(tweakBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tweaking Tweaker public key")
	}

	tweakedAddr, err := depositaddr.PubkeyToSegwitAddr(tweakedPublicKey, net)
	if err != nil {
		return nil, nil, errors.Wrap(err, "computing tweaked address")
	}

	address, _ = btcutil.DecodeAddress(tweakedAddr, net)

	return address, tweakedPublicKey, nil
}
