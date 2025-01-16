package deposit_address

type EcosystemTag = uint8

// Ecosystem type tags
//
// These tags are used to distinguish deposit addresses for different chain types
const (
	EcosystemTagEvm EcosystemTag = 0
	EcosystemTagSui EcosystemTag = 1
	// here more chain-type identifiers when supported
)
