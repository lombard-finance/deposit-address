package deposit_address

import "fmt"

const ChainIdSize = 32

type ChainIdEcosystem uint8

const (
	ChainIdEcosystemEVM ChainIdEcosystem = iota
	ChainIdEcosystemSui
)

func (c ChainIdEcosystem) String() string {
	switch c {
	case ChainIdEcosystemEVM:
		return "evm"
	case ChainIdEcosystemSui:
		return "sui"
	default:
		return fmt.Sprintf("unsupported(%d)", c)
	}
}

// Chain Id according to the Lombard documentation
type ChainId [ChainIdSize]byte

func (c ChainId) Bytes() []byte {
	return c[:]
}

func (c ChainId) Ecosystem() ChainIdEcosystem {
	return ChainIdEcosystem(c[0])
}
