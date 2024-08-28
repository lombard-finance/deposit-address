package deposit_address

import (
	"crypto/sha256"
	"encoding/binary"
	"github.com/pkg/errors"
)

const (
	DepositAuxTag     = "LombardDepositAux"
	DepositAuxV0      = uint8(0)
	MaxReferralIdSize = 256
)

// GetDepositAuxTagBytes Compute the aux tag bytes.
func GetDepositAuxTagBytes() [32]byte {
	return sha256.Sum256([]byte(DepositAuxTag))
}

// Create a tagged hasher used to compute Lombard deposit auxdata
//
// Returns a hasher that has been initialized with 'tag || tag', where
// 'tag' is sha256(DepositAuxTag)
func auxDepositHasher() Sha256 {
	// compute the tag
	tag := GetDepositAuxTagBytes()

	// initialize the hasher with the tag
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])

	return h
}

// ComputeAuxDataV0 Compute v0 AuxData given a ReferrerId
//
// This is defined as
//
//	taggedHash( Version0 || Nonce || ReferrerId )
//
// where 'taggedHash' is a sha256 instance as returned by 'auxDepositHasher()',
// 'Version0' is the byte 0x00, nonce, and 'ReferrerId' is an arbitrary 16 bytes array.
func ComputeAuxDataV0(nonce uint32, referrerId []byte) ([]byte, error) {
	if len(referrerId) > MaxReferralIdSize {
		return nil, errors.Errorf("wrong size for referrerId (got %v, want not greater than %v)", len(referrerId), MaxReferralIdSize)
	}

	nonceBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nonceBytes, nonce)

	h := auxDepositHasher()

	// Version0
	_, err := h.Write([]byte{DepositAuxV0})
	if err != nil {
		return nil, errors.Errorf("write version %x", []byte{DepositAuxV0})
	}
	_, err = h.Write(nonceBytes)
	if err != nil {
		return nil, errors.Errorf("write nonce %x", nonceBytes)
	}
	_, err = h.Write(referrerId)
	if err != nil {
		return nil, errors.Errorf("write referrerId %x", referrerId)
	}

	return h.Sum(nil), nil
}
