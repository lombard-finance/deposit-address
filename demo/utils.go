package demo

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type AddressType string

const (
	Unknown AddressType = "Unknown"
	Taproot AddressType = "Taproot"
	SegWit  AddressType = "Segwit"
)

func InitConfig() {
	// Get the directory of the current file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("No caller information")
	}

	// Go up two directories from the current file location
	currentDir := filepath.Dir(filename)
	projectRoot := filepath.Join(currentDir, "..")
	configPath := filepath.Join(projectRoot, "config.yaml")

	// For debugging
	fmt.Printf("Looking for config at: %s\n", configPath)

	viper.SetConfigFile(configPath)

	// Set default values before reading the config file
	viper.SetDefault("demo.challenge", "LOMBARD PROOF OF OWNERSHIP")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	// Print which config file was used (for debugging)
	fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
}

func CheckAddressTypes(addresses []string) (AddressType, error) {
	if len(addresses) == 0 {
		return Unknown, fmt.Errorf("empty address list")
	}

	// Get type of first address as reference
	expectedType := GetAddressType(addresses[0])
	if expectedType == Unknown {
		return Unknown, fmt.Errorf("invalid address format: %s", addresses[0])
	}

	// Check all other addresses match the same type
	for i, addr := range addresses[1:] {
		currentType := GetAddressType(addr)
		if currentType == Unknown {
			return Unknown, fmt.Errorf("invalid address format at index %d: %s", i+1, addr)
		}
		if currentType != expectedType {
			return Unknown, fmt.Errorf("address type mismatch: expected %s, got %s at index %d: %s",
				expectedType, currentType, i+1, addr)
		}
	}

	return expectedType, nil
}

func GetAddressType(address string) AddressType {
	if isTaproot(address) {
		return Taproot
	}

	if isSegWit(address) {
		return SegWit
	}

	return Unknown
}

func isTaproot(address string) bool {
	return strings.HasPrefix(address, "bc1p") || strings.HasPrefix(address, "tb1p")
}

func isSegWit(address string) bool {
	return (strings.HasPrefix(address, "bc1") || strings.HasPrefix(address, "tb1")) &&
		!strings.HasPrefix(address, "bc1p") && !strings.HasPrefix(address, "tb1p")
}

func CheckNetworkParams(addresses []string) (*chaincfg.Params, error) {
	if len(addresses) == 0 {
		return nil, fmt.Errorf("empty address list")
	}

	// Get network of first address as reference
	expectedNet, err := GetNetworkParams(addresses[0])
	if err != nil || expectedNet == nil {
		return nil, fmt.Errorf("invalid address network: %s", addresses[0])
	}

	// Check all other addresses match the same network
	for i, addr := range addresses[1:] {
		currentNet, err := GetNetworkParams(addr)
		if err == nil || currentNet == nil {
			return nil, fmt.Errorf("invalid address network at index %d: %s", i+1, addr)
		}
		if currentNet != expectedNet {
			return nil, fmt.Errorf("address network mismatch: expected %v, got %v at index %d: %s",
				expectedNet, currentNet, i+1, addr)
		}
	}

	return expectedNet, nil
}

func GetNetworkParams(address string) (*chaincfg.Params, error) {
	// Check for mainnet prefix (bc1)
	if strings.HasPrefix(address, "bc1") {
		return &chaincfg.MainNetParams, nil
	}

	// Check for testnet/signet prefix (tb1)
	if strings.HasPrefix(address, "tb1") {
		return &chaincfg.SigNetParams, nil
	}

	return nil, errors.Errorf("unsupported address format: %s", address)
}
