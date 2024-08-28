package deposit_address

import (
	"crypto/sha256"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/pkg/errors"
)

type PublicKey = secp256k1.PublicKey
type ModNScalar = secp256k1.ModNScalar
type JacobianPoint = secp256k1.JacobianPoint

const (
	AuxDataSize    = 32
	TweakSize      = 32
	SegwitTweakTag = "SegwitTweak"
)

// TweakPublicKey Computes a tweak and applies it to the specified public key. The tweak
// slice supplied to this function must be exactly 32 bytes long.
//
// The tweak hash is computed as sha256(tag || tag || pk || tweak) where
// 'tag' is sha256(SegwitTweakTag), 'pk' is the 33-byte compressed SEC1
// serialization of the public key, and 'tweak' is the supplied byte slice.
//
// The tweak hash is converted to a secp256k1 scalar t, and the tweaked
// public key is computed as PK + t * G, where G is the canonical generator.
func TweakPublicKey(pk *PublicKey, tweak []byte) (*PublicKey, error) {
	tweakScalar, err := computeTweakValue(pk, tweak)
	if err != nil {
		return nil, err
	}

	res := tweakWithScalar(pk, tweakScalar)
	return res, nil
}

// compute a tweaked public key as PK + tweak * G, for G the generator
func tweakWithScalar(pk *PublicKey, tweak *ModNScalar) *PublicKey {
	var tweakPoint, pkJacobian, sumJacobian JacobianPoint

	// tweak * G
	secp256k1.ScalarBaseMultNonConst(tweak, &tweakPoint)

	// PK + tweak * G
	pk.AsJacobian(&pkJacobian)
	secp256k1.AddNonConst(&tweakPoint, &pkJacobian, &sumJacobian)

	// convert to PublicKey
	sumJacobian.ToAffine()
	return secp256k1.NewPublicKey(&sumJacobian.X, &sumJacobian.Y)
}

// compute the tweak scalar for a given public key from a byte string
// Note: the length of the tweak must be exactly 32 bytes
func computeTweakValue(pk *PublicKey, tweak []byte) (*ModNScalar, error) {
	if len(tweak) != TweakSize {
		return nil, errors.Errorf("wrong size for tweak (got %v, want %v)", len(tweak), TweakSize)
	}

	if pk == nil {
		return nil, errors.New("nil public key")
	}

	h := sha256.New()

	// first, compute the tag bytes, sha256(SegwitTweakTag)
	h.Write([]byte(SegwitTweakTag))
	tag := h.Sum(nil)

	// now compute sha256(tag || tag || pk || tweak)
	h.Reset()
	h.Write(tag)
	h.Write(tag)
	h.Write(pk.SerializeCompressed())
	h.Write(tweak)
	tweakBytes := h.Sum(nil)

	// convert to ModNScalar
	var result ModNScalar
	overflowed := result.SetByteSlice(tweakBytes)
	if overflowed {
		// this happens with probability 2^-128. in other words, it will never happen
		return nil, errors.Errorf("tweak value resulted in overflow")
	}

	return &result, nil
}
