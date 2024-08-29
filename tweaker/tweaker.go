package tweaker

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	depositaddr "github.com/lombard-finance/deposit-address"
	"github.com/pkg/errors"
)

type Tweaker struct {
	publicKey *secp256k1.PublicKey
}

func NewTweaker(
	publicKey []byte,
) (*Tweaker, error) {
	parsedPublicKey, err := secp256k1.ParsePubKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &Tweaker{publicKey: parsedPublicKey}, nil
}

// DerivePubkey Derive a new deposit public key from a 32-byte tweak and return the PubKey
func (t *Tweaker) DerivePubkey(tweakBytes []byte) (*secp256k1.PublicKey, error) {
	return depositaddr.TweakPublicKey(t.publicKey, tweakBytes)
}

// DeriveSegwit Derive a new deposit public key from a 32-byte tweak, then build a
// `KeyWithDestination` value from it
func (t *Tweaker) DeriveSegwit(tweakBytes []byte, net *chaincfg.Params) (address btcutil.Address, tweakedPublicKey *secp256k1.PublicKey, err error) {
	tweakedPublicKey, err = t.DerivePubkey(tweakBytes)
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

func (t *Tweaker) GetPublicKey() *secp256k1.PublicKey {
	return t.publicKey
}
