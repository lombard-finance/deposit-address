package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	deposit_address "github.com/lombard-finance/deposit-address"
	utils "github.com/lombard-finance/deposit-address/demo"
	"github.com/spf13/viper"
)

// In top level project folder, run `go run demo/cmd/derive/main.go`.
func main() {
	// Initialize configuration
	utils.InitConfig()

	// Read value from config.yaml file
	// This is the public key for the base deposit key on Cubist
	basePubKey := viper.GetString("demo.public-key")
	if basePubKey == "" {
		fmt.Println("Missing `demo.public-key`")
		return
	}

	// Get this from the API instead of this example file, e.g.
	// https://mainnet.prod.lombard.finance/api/v1/address?to_address=0x57F9672bA603251C9C03B36cabdBBcA7Ca8Cfcf4&to_blockchain=DESTINATION_BLOCKCHAIN_ETHEREUM&limit=1&offset=0&asc=false&referralId=lombard
	data, err := os.ReadFile("./demo/cmd/derive/example.json")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	var addressList utils.AddressList
	err = json.Unmarshal(data, &addressList)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}

	for _, addr := range addressList.Addresses {
		// get this from config
		params := &chaincfg.MainNetParams

		// wallet address on destination chain
		walletAddr := common.HexToAddress(addr.DepositMetadata.ToAddress)

		auxData, err := deposit_address.ComputeAuxDataV0(addr.DepositMetadata.Nonce, []byte(addr.DepositMetadata.Referral))
		if err != nil {
			fmt.Println("Error computing aux data:", err)
			return
		}

		// parse public key of base deposit key
		pkBytes, err := hex.DecodeString(strings.TrimPrefix(basePubKey, "0x"))
		if err != nil {
			fmt.Println("Decoding public key hex:", err)
			return
		}

		pk, err := secp256k1.ParsePubKey(pkBytes)
		if err != nil {
			fmt.Println("Error decoding SEC1 encoded pubkey:", err)
			return
		}

		if addr.DepositMetadata.ToBlockchain == "DESTINATION_BLOCKCHAIN_ETHEREUM" {
			// for ethereum mainnet, LBTC contract address is 0x8236a87084f8B84306f72007F36F2618A5634494. get this from config.
			lbtcContractAddrEthMainnet := [20]byte{0x82, 0x36, 0xa8, 0x70, 0x84, 0xf8, 0xB8, 0x43, 0x06, 0xf7, 0x20, 0x07, 0xF3, 0x6F, 0x26, 0x18, 0xA5, 0x63, 0x44, 0x94}
			lbtcContractAddr := common.BytesToAddress(lbtcContractAddrEthMainnet[:20])

			// for ethereum mainnet, chain id is 1. get this from config.
			chainId := [32]byte{}
			chainId[31] = 1

			// derive the address
			derivedAddr, err := deposit_address.EvmDepositSegwitAddr(pk, lbtcContractAddr, walletAddr, chainId[:], auxData[:], params)
			if err != nil {
				fmt.Println("Error tweaking address:", err)
				return
			}

			fmt.Println("Address:", derivedAddr)

			if addr.BTCAddress != derivedAddr {
				fmt.Printf("Derived address (%s) doesn't match expected (%s)", derivedAddr, addr.BTCAddress)
			} else {
				fmt.Println("Addresses match")
			}
		}
	}

}
