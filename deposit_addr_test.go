package deposit_address

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lombard-finance/ledger-utils/address"
	"github.com/lombard-finance/ledger-utils/chainid"
	"github.com/stretchr/testify/require"

	"github.com/btcsuite/btcd/chaincfg"
)

type TestVal struct {
	pubKey      string
	segwitAddr  string
	tweakString string
}

// known-answer test values generated from reference rust impl
var rustEthTweakKatValues = []TestVal{
	{
		tweakString: "16fd25f94eb4f407ceef1c5f07085c6b157dc77edfce320a14037807004913fd",
		pubKey:      "02cd8d971536d4dc336efdddcaab05c1342f0c503abb4b3203c99c8a8b673e3b52",
		segwitAddr:  "tb1qxhyzcnf9dmpy4tdd6av9an8xa49g6sqnrjr29m",
	},
	{
		tweakString: "359133a06072e4f525eff163f47e92033ee2035bb071244b6f5239942df94142",
		pubKey:      "037f2ce3ae0dfe10cd70fe53f0242eebffc48eb1ce51db8a4a1666431f4147290d",
		segwitAddr:  "tb1qun448c6tw64ljdqs5chcywh7c29ev73u74ee2s",
	},
	{
		tweakString: "c7b2b3bcd871c0417ba1d2fd3e4d41c6464e82db155b483efa023bd6a4d343b3",
		pubKey:      "034834c293e3ae90ff8ceb2aa884a9f949a798da7f1415c0d41699c6f08103bcb7",
		segwitAddr:  "tb1qf70dvyyq9d9x3qlkr26epl5zm34gku2qm9cxq5",
	},
	{
		tweakString: "c578601ffa301acc6ac8d0b5a32e797623bcc6098ab4363486026e7daa8ec473",
		pubKey:      "03bcb3a6c4c00981c8dae95e67fdeb3721a5ee7672783dbb13b5831e33d40fd524",
		segwitAddr:  "tb1qv5a4fkh8ufqqnxslrtz7stt50hrh84a3ha3fva",
	},
	{
		tweakString: "a3c3c72799a9148d3798b9ff134831ae08888bf4a7ef7d88c72097aee9d35a0d",
		pubKey:      "030bc391ddd78147a9f069af05ef71647a85c35eb6c2e6ee4e933623c0d6ad3160",
		segwitAddr:  "tb1qh5nv88kddquhupa6spfm864mdhxt8rrs99dpu6",
	},
	{
		tweakString: "8b6e3a1fa936b9190d2094cddc0caf26dc577be0f4f75484d4d5a6235bfe8fdb",
		pubKey:      "039bad36b6f29fbfb6a46dc3fa1695e53a6ef9960f7802e8084a528564cca709c8",
		segwitAddr:  "tb1qeujwdg26zms3lapgg5m4g8s9sgvflgaj43gjzm",
	},
	{
		tweakString: "e3903dc3ff7344ccd5a06078a71a1f6b365651d131c554c95fedf10dccb0e93f",
		pubKey:      "0336d3853f7b513f5e783f00387ff94c64082bcca1fc25b68d0b963c17a5f56362",
		segwitAddr:  "tb1q580pyet4ek0yd2y096plyxyzresv9utywcvkdp",
	},
	{
		tweakString: "065cb13c23b6f8469c235ea60541561fb44bf13b75c46eff62ab4f2729fb9956",
		pubKey:      "02e7fa2290bb5b0d642bafed713d124f680a2a9182633a7a61ffb440eb0ce15e34",
		segwitAddr:  "tb1qy8tz84x4n2qqrm04m3psmcwat9kwdv4sd53kyv",
	},
	{
		tweakString: "e8c9e0c8c9a16da2acda3364a81c845ae9f9f87083d0b0218cb250a724930854",
		pubKey:      "027e20d881f94b9ba64064ed81a491ab33614d4e0356c9f6fef33f45f7482d743f",
		segwitAddr:  "tb1qvynkdf92t59lmngq6kkwpt9dsgnnh49tzep6rz",
	},
	{
		tweakString: "305a5fb5a7324fea78a595fbd041695feb9676f3aa9f6ffdcb268ef0f5f71959",
		pubKey:      "035603de18a9c9c62cce92b31f24412c008415b75569ed0ad68dfce55247d7b092",
		segwitAddr:  "tb1qp24g3xvqv9sdt5nznuqk4u8hqttrrankvgascu",
	},
	{
		tweakString: "7edf70126127993f3912e609dd5b3e81e113c8aa62bc4dc8d7db125e494ab6bf",
		pubKey:      "03ae588f09bb6568e2c002a5d49851a7d20335d25a2cdbc58aad12ea88c7769b33",
		segwitAddr:  "tb1qf20tftwlcyygvrk3gw25kst2z45ftr5xa6gqqg",
	},
	{
		tweakString: "a8073004759b5e027e52ad17290168c26660918931ad8acdd5aaafc032d97fd3",
		pubKey:      "028fcd2d00f62dda38404212daf120fe835719e540a560779eac1e8120fdfbdcc8",
		segwitAddr:  "tb1q5a0zgg78s56c79s9yer4vazx63e7zxdwrhzwyt",
	},
	{
		tweakString: "4ed8439c6fe8d2cd89ffb83a027710a9dd963a934f6dd24aa56f32a1a9da958a",
		pubKey:      "025d4e841f368130c78c2b370b1af0e5762dea1c53e21e586ff3f473805f7276db",
		segwitAddr:  "tb1qk80wz7tdvhhyd4xs2lu07ysrzpmpyszn2uq4w4",
	},
	{
		tweakString: "6c7b9b57948419cd433229c63fa3163b4125e5825318a79f1a483aeef3d86f3d",
		pubKey:      "03b4b808d1ccc58de31c8557f3fc0787b94d7bf374b55c8f1b01b831f33f797810",
		segwitAddr:  "tb1qjcx79ntqtmjfprfnl2gprg838wvs596qk97vuy",
	},
	{
		tweakString: "db7344b2ffe7015430e480ca4745ab98a62bfd8070491f044269c813fc6fee37",
		pubKey:      "0387de240a0c712bb2e8d0e877b860ce057d76eb34bd4384e502891de97beec44a",
		segwitAddr:  "tb1q6pv5dpt6dx6srx7txmlwcwh92t35ltj40d66c0",
	},
	{
		tweakString: "e46b947c9e14dc243e667ef5ba330e40cdd54c7ded382c165136cf64bcaa0d4e",
		pubKey:      "026a4e0421e767d425cf0ce4ed3b61dca32299bdff6aca040f18a66120f542aaaf",
		segwitAddr:  "tb1qa62qqwjw26z6cczfd0fl8pqmpspfczn45nvj75",
	},
	{
		tweakString: "aad0237ca3f4b1ec94250c36e76389b607d8ecb881b673d9f9333161ce3183db",
		pubKey:      "034b40bb45e69f60a7b8bfacf146cbda4c7486291c879a98dbcf9af865e52b0181",
		segwitAddr:  "tb1qmefthv9e5w55awmxmjuvjquslehatt50y03vjj",
	},
	{
		tweakString: "0a9cfbea89076b9153da68662a62a0bdfe7ad411dbfdbcf55ec9f6f6d1fd0134",
		pubKey:      "03c788e8e516b6048387fb3315994ccc763e3215cd053dc59f2e0cb9f64ce14ff9",
		segwitAddr:  "tb1qzteu7h8gen7t0pse05pu7kumyw3mmfl9a876ay",
	},
	{
		tweakString: "e687da4d3891ed9852b4bf9e567c107cfd7d197c11bc1a44606ae220af4b0b20",
		pubKey:      "037357ab03a0d7dbda364c397ec36d38c5c3a0f7bef21bdcfb80890c92f0779db7",
		segwitAddr:  "tb1qj2zenn43kxn7zpvufc4hteccyzr46dq6nyhuhh",
	},
	{
		tweakString: "3eadcd7b105537962d082dabb247d73c7f18b49221a71aa0eb3a8107dc1cab78",
		pubKey:      "02f8f6fa742fe0f0b3801b2ced9fd9a79137d0554514c71b056b8d83c999dddfb5",
		segwitAddr:  "tb1qjs32z30t9zdkud9h6ne5uxh804ekrk47knylc7",
	},
	{
		tweakString: "8ca348e0af9a71bc682f3f2355302d70033a778f58855dff5cb5190703a62e99",
		pubKey:      "0262d98ffbfedda13d7ffefa946ded1f4ed544b683836a1901540f0b45f979bfa5",
		segwitAddr:  "tb1q30fjhj3dzp3u5vvccavufvt76hmyxjce7y9cj2",
	},
	{
		tweakString: "85eb79313a9fbe2e067e710661238c273673dd91f62be333e4786a5689b4a271",
		pubKey:      "03c24c10356ee2d395d9807276005d829109f3478bc8a6511579259b02fe9f0c36",
		segwitAddr:  "tb1qq9kalx5m45ry0z05l4wa7f34s5x82w2hpy6x3n",
	},
	{
		tweakString: "becd43442fbd7ff734da4ee2b418c31f17c9c79f5398d11f9dc3369b7fab45b8",
		pubKey:      "039c1c63eedac75cd9b86df25fc0d94cbf29acb2cb72f366b81c4f14555c7c8a5f",
		segwitAddr:  "tb1qppkcmqmv2dsx4kaa0lzsta2la6y7qlayk0vpgm",
	},
	{
		tweakString: "9a5d9fc22cbea30e29f996a2bafdd74b1c637e6a607a9442b0fac1aad2143ad6",
		pubKey:      "026ff6569d1ea1cc239c4f84b9e5f6279cdbf6cbd1471b388df2e9e766bd53aa01",
		segwitAddr:  "tb1qvj0fxqmh0t2zskednxwhlet357nnu9lmtcn8n8",
	},
	{
		tweakString: "b4635a14aa40694637dafcdae020432ff268868254d135dac2db78793eb0a083",
		pubKey:      "03415f3c3710189fd8a92f8a10570452089959e208589c575653f7d8f3af70d457",
		segwitAddr:  "tb1q708zsjthamr9grzpg59h4pf64k63awzqhttpfn",
	},
	{
		tweakString: "cee36d950e4a2b724c39b4fe67dc04be61647af6aa6f2bf8a9569c61b40d8803",
		pubKey:      "0356c00235375a5c8cd902c4628ee0c2df1ed8bd2cff43dafda7d41c5e5a32c440",
		segwitAddr:  "tb1q0jnvv0efpmphzavj2w9zc4hd3qwlqfe573jn6a",
	},
	{
		tweakString: "4c4136356ccf5182d85c53a3f519a15c04b7a00f5607d5fd5fc0a298dd6771eb",
		pubKey:      "02b47e4e900a20d2d2f65e3b86d7616ea09d70bf60378cc0b27b4769ec4ae0db55",
		segwitAddr:  "tb1qyfk87n9nt7ala7tnjxmmdrgy7rqakzvuw4aa5e",
	},
	{
		tweakString: "a8671387b61ed8ca10a4b6f6e0cf573c5f1820768378cb6e517af3ac001897d3",
		pubKey:      "026db79a85735651d9bbf530d6852fac3b8814315df697426696aa9dca8b7a98ab",
		segwitAddr:  "tb1q2zljyqu5d6lzuhrup3kz52lxk2x698wlat3g4v",
	},
	{
		tweakString: "d1764a9353759fcfbd1284ceb5120967f5c3aa78d34301a926603d9a3f6ccb24",
		pubKey:      "03d4ab8a7f436e2b80659208c42f652b19ccb76bf02cc00c925774c6888a7fd254",
		segwitAddr:  "tb1q5e0h08lsvqwmh925vevgch0lavkxczx245xxkf",
	},
	{
		tweakString: "e2dd77486fa8087c3f536703da3f9522b8e2db328c8fae695ca7444430bf653f",
		pubKey:      "03ecd54bf7581564dbed1378912f387505af2b3309bd49c70effe976503461d8d2",
		segwitAddr:  "tb1qvu7scxe5z9qcg482nzxmu6jngpvf9kkj43el3p",
	},
	{
		tweakString: "733aac68c054d2c21abdca898c30baa149cbb9249a29aa954169f2839b20a6ad",
		pubKey:      "03c622c7011e5658bbe63788ea15f5a6c3362e9e39b907b1fb45d3381d0ed2ba5f",
		segwitAddr:  "tb1qpc8tqf45ah9yj7lk07zc00vq8slyt555dacwef",
	},
	{
		tweakString: "012dbe4fee8b56e88763210edfec846b698ca5e5ddecf88fee37fb130238663d",
		pubKey:      "0300bbc97d0aa5fe7cf3afddd965b92364c56105bdd16b60934fbf5313bcad668b",
		segwitAddr:  "tb1q60082d7q8dvvt9dfk04wx93uk29q3kld5f9er8",
	},
}

func TestEthTweakValueRustKat(t *testing.T) {
	hashVal := sha256.Sum256([]byte("segwit_lombard_tweak_test_rs"))
	pk := secp256k1.PrivKeyFromBytes(hashVal[:]).PubKey()
	params := &chaincfg.SigNetParams

	for _, knownAnswer := range rustEthTweakKatValues {
		v1 := sha256.Sum256(hashVal[:])
		v2 := sha256.Sum256(v1[:])
		v3 := sha256.Sum256(v2[:])
		v4 := sha256.Sum256(v3[:])
		hashVal = v4

		lbtcContract, err := address.NewEvmAddress(v1[:20])
		require.NoError(t, err, "error in test configuration for lbtc contract")
		wallet, err := address.NewEvmAddress(v2[:20])
		require.NoError(t, err, "error in test configuration for wallet")
		chainIdU64 := binary.BigEndian.Uint64(v3[:8])
		var chainIdBytes [32]byte
		binary.BigEndian.PutUint64(chainIdBytes[24:], chainIdU64)
		chainId, _ := chainid.NewLChainId(chainIdBytes[:])
		auxData := v4

		// check tweak result
		tweak, err := DepositTweak(lbtcContract, wallet, chainId, auxData[:])
		if err != nil {
			panic(fmt.Sprintf("error computing deposit tweak: %v", err))
		}
		tweakString := hex.EncodeToString(tweak)

		// check deposit pubkey result
		tpk, err := DepositSegwitPubkey(pk, lbtcContract, wallet, chainId, auxData[:])
		if err != nil {
			panic(fmt.Sprintf("error tweaking pubkey: %v", err))
		}
		tpkString := hex.EncodeToString(tpk.SerializeCompressed())

		// check segwit address
		segwitAddr, err := DepositSegwitAddr(pk, lbtcContract, wallet, chainId, auxData[:], params)
		if err != nil {
			panic(fmt.Sprintf("error tweaking addr: %v", err))
		}

		/*
		   // To generate KATs for use in Rust, uncomment this code
		   fmt.Printf("    (hex!(\"%s\"), hex!(\"%s\"), \"%s\"),\n", tweakString, tpkString, segwitAddr);
		*/

		if tweakString != knownAnswer.tweakString {
			panic(fmt.Sprintf("tweak mismatch:\n%v\n%v", tweakString, knownAnswer.tweakString))
		}
		if tpkString != knownAnswer.pubKey {
			panic(fmt.Sprintf("pk mismatch:\n%v\n%v", tpkString, knownAnswer.pubKey))
		}
		if segwitAddr != knownAnswer.segwitAddr {
			panic(fmt.Sprintf("addr mismatch:\n%v\n%v", segwitAddr, knownAnswer.segwitAddr))
		}
	}
}

var referenceValues = []struct {
	testLabel          string
	rootDepositKey     string
	nonce              uint32
	referrerId         string
	version            DepositAuxVersion
	auxData            string
	tokenAddress       string
	wallet             string
	chainId            string
	expectedTweak      string
	expectedPubkey     string
	expectedSegwitAddr string
	btcParams          chaincfg.Params
}{
	{
		testLabel:          "Sui Testnet - 1",
		rootDepositKey:     "044bf624ac0ef1d9f7ed5ea11d6decbd91d88abc0c898e40fcbf96cae2e062363fe48862e4615ce9dde9b814a0d6b83fd47695e3946be4911665464dc99e80f89d",
		auxData:            "2137aefeb756a435f07fceff39a061bd2a062b617bd8857e9c32b44ef2596bc8", // ComputeAuxDataV0(0, [32]byte{0...})
		tokenAddress:       "54945cd3d15c0012d35a92ed6f1f373157216fc6bdc5bd79b03ee86da3ca455b",
		wallet:             "0d3c73069aef96e8a1d209e2c96ddefc4b911d025932e414db201be70f0ae15e",
		chainId:            "010000000000000000000000000000000000000000000000000000004c78adac",
		expectedTweak:      "c5f14fe401d015c4ea34632e6d775b751e1925fe718e6b339d2a74689b3a0609",
		expectedPubkey:     "02a2188a8c2449e16c3f50aab677c8be90916a7c7e6ab25a88222fc846257c28fb",
		expectedSegwitAddr: "tb1q9sjdz0vpnsshhule5kkxvfggvq8lznpck4tay0",
		btcParams:          chaincfg.SigNetParams,
	},
	{
		testLabel:          "Sui Testnet - 2",
		rootDepositKey:     "044bf624ac0ef1d9f7ed5ea11d6decbd91d88abc0c898e40fcbf96cae2e062363fe48862e4615ce9dde9b814a0d6b83fd47695e3946be4911665464dc99e80f89d",
		auxData:            "2137aefeb756a435f07fceff39a061bd2a062b617bd8857e9c32b44ef2596bc8", // ComputeAuxDataV0(0, [32]byte{0...})
		tokenAddress:       "54945cd3d15c0012d35a92ed6f1f373157216fc6bdc5bd79b03ee86da3ca455b",
		wallet:             "5e9ae2ae1c76cb14be16cd2d521f8200c95cc94ab30947c61ade11a0a6439d28",
		chainId:            "010000000000000000000000000000000000000000000000000000004c78adac",
		expectedTweak:      "a6d4eb9bcfa5c683513b06fd531184792767f5355402ce23c6dab417696f6392",
		expectedPubkey:     "0393e2e2e1acc9a702d8b62e990ed9eff4e36589c6cd44e48101a2d3c3c58d5abb",
		expectedSegwitAddr: "tb1q8uwc6au5765r9jttj949dg6f2qzcqt58svy8c0",
		btcParams:          chaincfg.SigNetParams,
	},
	{
		testLabel:          "Sui Mainnet - 1",
		rootDepositKey:     "044bf624ac0ef1d9f7ed5ea11d6decbd91d88abc0c898e40fcbf96cae2e062363fe48862e4615ce9dde9b814a0d6b83fd47695e3946be4911665464dc99e80f89d",
		auxData:            "2137aefeb756a435f07fceff39a061bd2a062b617bd8857e9c32b44ef2596bc8", // ComputeAuxDataV0(0, [32]byte{0...})
		tokenAddress:       "54945cd3d15c0012d35a92ed6f1f373157216fc6bdc5bd79b03ee86da3ca455b",
		wallet:             "0d3c73069aef96e8a1d209e2c96ddefc4b911d025932e414db201be70f0ae15e",
		chainId:            "0100000000000000000000000000000000000000000000000000000035834a8a",
		expectedTweak:      "35b7205e7d5f1b077091f3164e5daed121f4bb27799c57d9acd976a4044a18bd",
		expectedPubkey:     "02744518bc0dafc22c494f7dc9ec780fa6d9ae53d3be720ee003f672edfba1063b",
		expectedSegwitAddr: "bc1qk5xk9gfr5r8l57ma2euyyvc8h7kc9etlfz2w98",
		btcParams:          chaincfg.MainNetParams,
	},
	{
		testLabel:          "Sui Mainnet - 2",
		rootDepositKey:     "044bf624ac0ef1d9f7ed5ea11d6decbd91d88abc0c898e40fcbf96cae2e062363fe48862e4615ce9dde9b814a0d6b83fd47695e3946be4911665464dc99e80f89d",
		auxData:            "2137aefeb756a435f07fceff39a061bd2a062b617bd8857e9c32b44ef2596bc8", // ComputeAuxDataV0(0, [32]byte{0...})
		tokenAddress:       "54945cd3d15c0012d35a92ed6f1f373157216fc6bdc5bd79b03ee86da3ca455b",
		wallet:             "5e9ae2ae1c76cb14be16cd2d521f8200c95cc94ab30947c61ade11a0a6439d28",
		chainId:            "0100000000000000000000000000000000000000000000000000000035834a8a",
		expectedTweak:      "e454f631af7c2f235c372be61a63c58a1b94832e0240cf1a06b9e657df5d9c13",
		expectedPubkey:     "034a915f6ac8d6c6920a754392338aa2f41a4070d30564d6af3749d80a9b58eb81",
		expectedSegwitAddr: "bc1qagvmd7y5x5hkkn6avva5mv0thhlnn6ktuh5ppd",
		btcParams:          chaincfg.MainNetParams,
	},
	{
		testLabel:          "Ledger Testnet - 1",
		rootDepositKey:     "045615e9748b945bad807b56d3a723578673d08566a4818510c0ba2123317414f8068660c0398d4ecb7b02c805af42ce77bb700f18c92142ed2559abdeab1deb5a",
		nonce:              0,
		referrerId:         "lombard",
		version:            DepositAuxV1,
		tokenAddress:       "5151091366ea9acf52a9fad76381919247819fdfe4dda9730aa9afa6b2bc7cbd",
		wallet:             "D865FB715717C78FB8A2C6799E5A2721024671C3",
		chainId:            "033bc7baf196ce32b8b9200518df11c35bad882fc6e3b6f45b4a8885f4c1281b",
		expectedTweak:      "00dc5925d8374d97cfc5caddc7c930d408f33bf9f4a550ac342099da5187a4af",
		expectedPubkey:     "02e037d5422512cafbd477855e22bb0289aaebb5fe5f384e4edc9c1cdb8b1e5da3",
		expectedSegwitAddr: "tb1q72ehg29wfgehd5xk25l3e03kry9yagsn5xk645",
		btcParams:          chaincfg.SigNetParams,
	},
	{
		testLabel:          "Ledger Mainnet - Cosmos Multisig",
		rootDepositKey:     "043dcf7a68429b23a0396ca61c1ab243ccbbcc629ff04c59394458d6db5dd2bb159e0b7a71ef07247b59a0a21b1f1eaee61a40064ade423e926f38550065a43587",
		nonce:              0,
		referrerId:         "lombard",
		version:            DepositAuxV1,
		tokenAddress:       "5151091366ea9acf52a9fad76381919247819fdfe4dda9730aa9afa6b2bc7cbd",
		wallet:             "96E2A17ABD4F10664EE33EFF6F626E2F8D61B690",
		chainId:            "0387b25e8e61f2ce4838b04795b231f09ee73ffd391da018bef4bc5c4975897b",
		expectedTweak:      "ff6c39409858d8bda496c42db4e5325ebe9b3b76fa22e547d9c8d74cf3b87f9d",
		expectedPubkey:     "038e635efba8e5fbda3ec9df3aa28c334c050738a4722b2b57e8af308dc7766038",
		expectedSegwitAddr: "bc1q5mksvezlep82tur6sdd2skjlcxykcl9nz2gzk8",
		btcParams:          chaincfg.MainNetParams,
	},
	{
		testLabel:          "Ledger Mainnet - Ethereum v0 staked",
		rootDepositKey:     "043dcf7a68429b23a0396ca61c1ab243ccbbcc629ff04c59394458d6db5dd2bb159e0b7a71ef07247b59a0a21b1f1eaee61a40064ade423e926f38550065a43587",
		nonce:              0,
		referrerId:         "lombard",
		version:            DepositAuxV0,
		tokenAddress:       "8236a87084f8B84306f72007F36F2618A5634494",
		wallet:             "7751D9405B4b0dC5432372CF244bB47BC7bEAbF2",
		chainId:            "0000000000000000000000000000000000000000000000000000000000000001",
		expectedTweak:      "d722abac4a03b736f42b9ff32e32eb4d086369f4b21d0470bd184f36a120615f",
		expectedPubkey:     "0297b1ce555a2e5d780c912b7ab65ad3e2dad982e3cb5e76a183ec2ef2bd04059c",
		expectedSegwitAddr: "bc1qxht6dml9j0k7e372heua2dtxjzk0wqwvy4lr9a",
		btcParams:          chaincfg.MainNetParams,
	},
	{
		testLabel:          "Ledger Mainnet - Katana v1 staked",
		rootDepositKey:     "043dcf7a68429b23a0396ca61c1ab243ccbbcc629ff04c59394458d6db5dd2bb159e0b7a71ef07247b59a0a21b1f1eaee61a40064ade423e926f38550065a43587",
		nonce:              0,
		referrerId:         "lombard",
		version:            DepositAuxV1,
		tokenAddress:       "ecAc9C5F704e954931349Da37F60E39f515c11c1",
		wallet:             "7751D9405B4b0dC5432372CF244bB47BC7bEAbF2",
		chainId:            "00000000000000000000000000000000000000000000000000000000000b67d2",
		expectedTweak:      "eed5f0ff77926382ea5330f987b82adbfeaf9acbb168ad55cc46cd34c88874e6",
		expectedPubkey:     "02d5f04a1a4ac115952b1e888d6c7b5841a91eae70d63e69f2b207519ef5cc2103",
		expectedSegwitAddr: "bc1qnpx6pluyufnkxjjt7u3k8ysmmmqg2xhuq92pdn",
		btcParams:          chaincfg.MainNetParams,
	},
	{
		testLabel:          "Ledger Mainnet - Katana v1 native",
		rootDepositKey:     "043dcf7a68429b23a0396ca61c1ab243ccbbcc629ff04c59394458d6db5dd2bb159e0b7a71ef07247b59a0a21b1f1eaee61a40064ade423e926f38550065a43587",
		nonce:              0,
		referrerId:         "lombard",
		version:            DepositAuxV1,
		tokenAddress:       "B0F70C0bD6FD87dbEb7C10dC692a2a6106817072",
		wallet:             "7751D9405B4b0dC5432372CF244bB47BC7bEAbF2",
		chainId:            "00000000000000000000000000000000000000000000000000000000000b67d2",
		expectedTweak:      "39424b5edae5eb87b83e8ff05537bb1d202e5ed5da2b82e5dd4138f8ec56dcc1",
		expectedPubkey:     "02c3e1c93693c319eb0a1961832d218b4c673d5e30c49553f0bd0cf5686d8f00a6",
		expectedSegwitAddr: "bc1q3dnkyx6nemcmqt2ghln8sls56gkznklkclwhun",
		btcParams:          chaincfg.MainNetParams,
	},
}

func TestWithReferenceValues(t *testing.T) {
	for _, rf := range referenceValues {
		t.Run(rf.testLabel, func(t *testing.T) {
			chainId, err := chainid.NewLChainIdFromHex(rf.chainId)
			require.NoError(t, err)
			lbtcContract, err := address.NewAddressFromHex(rf.tokenAddress, chainId.Ecosystem())
			require.NoError(t, err)
			wallet, err := address.NewAddressFromHex(rf.wallet, chainId.Ecosystem())
			require.NoError(t, err)

			pkHex, err := hex.DecodeString(rf.rootDepositKey)
			require.NoError(t, err)
			pk, err := secp256k1.ParsePubKey(pkHex)
			require.NoError(t, err)

			var auxData []byte
			if rf.auxData != "" {
				expectedAuxDataBytes, err := hex.DecodeString(rf.auxData)
				require.NoError(t, err, "error decoding aux data")
				auxData = expectedAuxDataBytes
			} else {
				expectedAuxDataBytes, err := ComputeAuxData(rf.nonce, []byte(rf.referrerId), rf.version)
				require.NoError(t, err, "error computing aux data")
				auxData = expectedAuxDataBytes
			}

			// check tweak result
			tweak, err := DepositTweak(lbtcContract, wallet, chainId, auxData)
			require.NoError(t, err, "error on deposit tweak calculation")
			require.Equal(t, rf.expectedTweak, hex.EncodeToString(tweak), "tweak mismatch")

			// check deposit pubkey result
			tpk, err := DepositSegwitPubkey(pk, lbtcContract, wallet, chainId, auxData)
			require.NoError(t, err, "error tweaking the public key")
			require.Equal(t, rf.expectedPubkey, hex.EncodeToString(tpk.SerializeCompressed()), "pubkey mismatch")

			// check segwit address
			segwitAddr, err := DepositSegwitAddr(pk, lbtcContract, wallet, chainId, auxData, &rf.btcParams)
			require.NoError(t, err, "error deriving address")
			require.Equal(t, rf.expectedSegwitAddr, segwitAddr, "segwit address mismatch")
		})
	}
}
