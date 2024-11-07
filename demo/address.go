package demo

type Address struct {
	BTCAddress      string          `json:"btc_address"`
	Type            string          `json:"type"`
	DepositMetadata DepositMetadata `json:"deposit_metadata"`
	CreatedAt       string          `json:"created_at"`
}

type DepositMetadata struct {
	ToAddress    string `json:"to_address"`
	ToBlockchain string `json:"to_blockchain"`
	Referral     string `json:"referral"`
	Nonce        uint32 `json:"nonce"`
}

type AddressList struct {
	Addresses []Address `json:"addresses"`
}
