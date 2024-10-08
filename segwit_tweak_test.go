package deposit_address

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// known-answer test values generated from reference rust impl
var rustKatValues = []string{
	"0313774466ebbc111274dab2b4d1b6eac4f6f3a111db73fa4ff3eac66c20169a23",
	"02aa2d51f3f3e92626aa5bfd141d974096fd58925b06473e9bb4260852edfbfa46",
	"0341d9fbd191a43122c386d1c9991062de44c0c8847490fb7bb9a17b44b507aede",
	"0334492cdac9bcb31bb27cc6dc9ce70ff5b52ac5b78d4589f751469559bfa5ec4a",
	"036cd9a04d82139aa35a0c36da34241aab6aca9003f12db084a8b5717731e9847d",
	"02f5780553af7712e3b24e6ccdcf0e077f8c30a779e0d81d9ec0be09fe631921ea",
	"039c19dee46fa2365da29e77a94b33ead07a7db3300c348c7bfa82fd89ba989ad3",
	"03db022c98985fc32421e1cf05bcc644d6cc0af8abbc4b0446fe78842f94c680ee",
	"027a90040d3e6088fc6562321c9b0650dabdff0ef4381a4eacdeca73ffc3764e01",
	"0228393ede642522aa0ca3152e132c185dda0571d4576258cd5129ad26fb24cea8",
	"0276bf1e4207c9b491255a841cd94314c991379f699d4844e6827ee92bbe91355a",
	"03ceb6f23756f1cfdf4283da15829b42aef941362f2fe675d9806b836f43ec6cef",
	"03ef806e702b73b466e55d624a58dcde90389d19b07cb1c8093b6c8ad32ea56ef5",
	"025a6550a5f897e3bc2d2c0a890f56c1ab01ff9f020f3766cb451f62089c9e32c2",
	"03e6efdb95f08c94175120f2c6d788675ac86bf993c214ecd3de335600dad1be41",
	"028cacea94118112577050bfe99bb868bc9d2016bebce460fac2c1a8e824fd67bf",
	"029ffc284aeb58088c699c15355285ef69b0e9682d4345db84d75626d279a5a8cd",
	"02840cdcadd09695927aea95da4c61af3861f805ef8d9e6242c952284ec6f05684",
	"02c1f4816c3485cf79e9aeb4ea4dc44d104880c0a4df6e599d81ca59fc8d1449b6",
	"029077f3d1c9aeb621cfb3fef8e18231e9f2e73f9af2ce2cc2ab9dbab18264bb09",
	"037cfb969efeca8eb8200f67c416cb00aaf50294c3692e262a411770018ff1a91a",
	"02e2a3ef2fc61ece6e5bc7e4a35e6420e39af1d834c3fe3227b6a95e3621a09819",
	"031b71237447276eb44ea8042d57e466187f513b32003b0aa01c483d7181e08c20",
	"0340b92b55beefeacb7ffd4158c640ba65a9a3c392ac71d0878e89952bf5bdfad4",
	"0363dd621a75295c3a94914edcc5ad92246ef07871ee1775adafbf0f9a263209be",
	"022fbc138f112f0c09c548840268588b899e1541f7e353f31c83df96ef71105646",
	"02438d1c97aba03f083fbb9aa2968ab21b32b9765cb3aebd8f4307a85a0c1d0fb4",
	"032d74810eb759fd94c67728d7cd604358f534a8e1e618859f83505040f1028f2b",
	"03dae9b02ffcd698ddc2105d06d738a88ac1ce53a63cee57a499ef855234447ac6",
	"03d5efdf20f0172f45dbeb84c6217bc2834a2b3b012dd681f3fc54e89d15269279",
	"036b9e2411128b4d7bad762484f0612be54ef9a20806358cd218cb066be4747022",
	"03e918aaa0de64b97974e3d644911d445fc4d0a9970130ec2d31a2170975e02d20",
}

func TestSegwitTweakRustKat(t *testing.T) {
	hashVal := sha256.Sum256([]byte("segwit_tweak_test_rs"))
	pk := secp256k1.PrivKeyFromBytes(hashVal[:]).PubKey()

	for _, xpkString := range rustKatValues {
		hashVal = sha256.Sum256(hashVal[:])

		tpk, err := TweakPublicKey(pk, hashVal[:])
		if err != nil {
			panic(fmt.Sprintf("failed to tweak public key: %v", err))
		}

		xpkBytes, err := hex.DecodeString(xpkString)
		if err != nil {
			panic(fmt.Sprintf("failed to decode pk hex: %v", err))
		}

		xpk, err := secp256k1.ParsePubKey(xpkBytes)
		if err != nil {
			panic(fmt.Sprintf("failed to parse pk: %v", err))
		}

		if !tpk.IsEqual(xpk) {
			panic(fmt.Sprintf("expected tpk == xpk:\n%v\n%v", tpk, xpk))
		}
	}
}
