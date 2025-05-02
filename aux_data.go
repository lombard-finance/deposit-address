package deposit_address

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/pkg/errors"
)

const (
	DepositAuxTag     = "LombardDepositAux"
	MaxReferralIdSize = 256
)

type DepositAuxVersion uint8

const (
	DepositAuxV0 = DepositAuxVersion(0)
	DepositAuxV1 = DepositAuxVersion(1)
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

// ComputeAuxData Compute the AuxData.
//
// This is defined as
//
//	taggedHash( Version || Nonce || ReferrerId )
//
// where:
// - 'taggedHash' is a sha256 instance as returned by 'auxDepositHasher()'
// - 'Version' is a byte useful if different deposit versions should refer to different deposit addresses
// - 'nonce' allows to generate different deposit addresses given same inputs
// - 'ReferrerId' is an arbitrary 16 bytes array for application usage
func ComputeAuxData(nonce uint32, referrerId []byte, version DepositAuxVersion) ([]byte, error) {
	if len(referrerId) > MaxReferralIdSize {
		return nil, errors.Errorf("wrong size for referrerId (got %v, want not greater than %v)", len(referrerId), MaxReferralIdSize)
	}

	nonceBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nonceBytes, nonce)

	h := auxDepositHasher()

	_, err := h.Write([]byte{byte(version)})
	if err != nil {
		return nil, errors.Errorf("write version %x", []byte{byte(version)})
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

// ComputeAuxDataV0 Compute the AuxData with version 0
func ComputeAuxDataV0(nonce uint32, referrerId []byte) ([]byte, error) {
	return ComputeAuxData(nonce, referrerId, DepositAuxV0)
}
