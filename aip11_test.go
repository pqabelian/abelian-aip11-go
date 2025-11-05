package aip11_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	aip11 "github.com/pqabelian/abelian-aip11-go"
	"github.com/pqabelian/abelian-aip11-go/wordlists"
	"github.com/stretchr/testify/assert"
)

// Main functions Examples and Tests

func ExampleSampleEntropySeed() {
	entropySeed, _ := aip11.SampleEntropySeed()
	fmt.Println(len(entropySeed))
	// Output: 32
}

func TestSampleEntropySeed(t *testing.T) {
	entropySeed, err := aip11.SampleEntropySeed()
	assert.NoError(t, err, "Entropy seed should be sampled correctly")
	assert.Equal(t, 32, len(entropySeed), "Entropy seed length should be 32")
}

func ExampleEntropySeedToMnemonic() {
	entropySeed, _ := aip11.SampleEntropySeed()
	mnemonic, _ := aip11.EntropySeedToMnemonic(entropySeed, wordlists.English)
	fmt.Println(len(mnemonic))
	// Output: 24
}

func TestEntropySeedToMnemonic(t *testing.T) {
	vectors := getAIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			mnemonic, err := aip11.EntropySeedToMnemonic(entropySeed, wordlists.English)
			assert.NoError(t, err, "Mnemonic should be generated correctly")
			assert.Equal(t, v.mnemonic, strings.Join(mnemonic, " "), "Mnemonic should be the same")
		})
	}
}

func ExampleMnemonicToEntropySeed() {
	entropySeed, _ := aip11.SampleEntropySeed()
	mnemonic, _ := aip11.EntropySeedToMnemonic(entropySeed, wordlists.English)
	entropySeed2, _ := aip11.MnemonicToEntropySeed(mnemonic, wordlists.English)
	fmt.Println(len(entropySeed2))
	// Output: 32
}

func TestMnemonicToEntropySeed(t *testing.T) {
	vectors := getAIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			entropySeed2, err := aip11.MnemonicToEntropySeed([]string(strings.Split(v.mnemonic, " ")), wordlists.English)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			assert.Equal(t, entropySeed, entropySeed2, "Entropy seed should be the same")
		})
	}
}

func ExampleEntropySeedToMasterSeed() {
	entropySeed, _ := aip11.SampleEntropySeed()
	masterSeed, _ := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
	fmt.Println(len(masterSeed))
	// Output: 64
}

func TestEntropySeedToMasterSeed(t *testing.T) {
	vectors := getAIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			masterSeed, err := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
			assert.NoError(t, err, "Master seed should be generated correctly")
			assert.Equal(t, v.masterSeed, hex.EncodeToString(masterSeed), "Master seed should be the same")
		})
	}
}

func ExampleMasterSeedToAccountRootSeeds() {
	entropySeed, _ := aip11.SampleEntropySeed()
	masterSeed, _ := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
	accountRootSeeds, _ := aip11.MasterSeedToAccountRootSeeds(masterSeed)
	fmt.Println(len(accountRootSeeds))
	for _, seed := range accountRootSeeds {
		fmt.Println(len(seed))
	}
	// Output: 5
	// 64
	// 64
	// 64
	// 64
	// 64
}

func TestMasterSeedToAccountRootSeeds(t *testing.T) {
	vectors := getAIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			masterSeed, err := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
			assert.NoError(t, err, "Master seed should be generated correctly")
			accountRootSeeds, err := aip11.MasterSeedToAccountRootSeeds(masterSeed)
			assert.NoError(t, err, "Account root seeds should be generated correctly")
			assert.Equal(t, v.rootSeeds.coinSpKeyRootSeed, hex.EncodeToString(accountRootSeeds[0]), "Coin SP key root seed should be the same")
			assert.Equal(t, v.rootSeeds.coinSnKeyRootSeed, hex.EncodeToString(accountRootSeeds[1]), "Coin SN key root seed should be the same")
			assert.Equal(t, v.rootSeeds.coinDetectorRootKey, hex.EncodeToString(accountRootSeeds[2]), "Coin detector root key should be the same")
			assert.Equal(t, v.rootSeeds.coinVKRootSeed, hex.EncodeToString(accountRootSeeds[3]), "Coin VK root seed should be the same")
			assert.Equal(t, v.rootSeeds.coinVKeyRootSeedAut, hex.EncodeToString(accountRootSeeds[4]), "Coin VK root seed aut should be the same")

			publicRandRootSeed, err := aip11.MasterSeedToAccountPublicRandRootSeed(masterSeed)
			assert.NoError(t, err, "Public rand root seed should be generated correctly")
			assert.Equal(t, v.publicRandRootSeed, hex.EncodeToString(publicRandRootSeed), "Public rand root seed should be the same")

			for _, publicRand := range v.publicRands {
				publicRandResult, err := aip11.DerivePublicRand(publicRandRootSeed, publicRand.seqNo)
				assert.NoError(t, err, "Public rand should be generated correctly")
				assert.Equal(t, publicRand.expected, hex.EncodeToString(publicRandResult), "Public rand should be the same")
			}
		})
	}
}

func ExampleMasterSeedToAccountPublicRandRootSeed() {
	entropySeed, _ := aip11.SampleEntropySeed()
	masterSeed, _ := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
	publicRandRootSeed, _ := aip11.MasterSeedToAccountPublicRandRootSeed(masterSeed)
	fmt.Println(len(publicRandRootSeed))
	// Output: 64
}

func TestMasterSeedToAccountPublicRandRootSeed(t *testing.T) {
	vectors := getAIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			masterSeed, err := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
			assert.NoError(t, err, "Master seed should be generated correctly")
			publicRandRootSeed, err := aip11.MasterSeedToAccountPublicRandRootSeed(masterSeed)
			assert.NoError(t, err, "Public rand root seed should be generated correctly")
			assert.Equal(t, v.publicRandRootSeed, hex.EncodeToString(publicRandRootSeed), "Public rand root seed should be the same")
		})
	}
}

func ExampleDerivePublicRand() {
	entropySeed, _ := aip11.SampleEntropySeed()
	masterSeed, _ := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
	publicRandRootSeed, _ := aip11.MasterSeedToAccountPublicRandRootSeed(masterSeed)

	for i := 1; i <= 5; i++ {
		publicRand, _ := aip11.DerivePublicRand(publicRandRootSeed, uint32(i))
		fmt.Println(len(publicRand))
	}
	// Output: 64
	// 64
	// 64
	// 64
	// 64
}

func TestDerivePublicRand(t *testing.T) {
	vectors := getAIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			masterSeed, err := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
			assert.NoError(t, err, "Master seed should be generated correctly")
			publicRandRootSeed, err := aip11.MasterSeedToAccountPublicRandRootSeed(masterSeed)
			assert.NoError(t, err, "Public rand root seed should be generated correctly")
			for _, publicRand := range v.publicRands {
				publicRandResult, err := aip11.DerivePublicRand(publicRandRootSeed, publicRand.seqNo)
				assert.NoError(t, err, "Public rand should be generated correctly")
				assert.Equal(t, publicRand.expected, hex.EncodeToString(publicRandResult), "Public rand should be the same")
			}
		})
	}
}

type rootSeeds struct {
	coinSpKeyRootSeed   string
	coinSnKeyRootSeed   string
	coinDetectorRootKey string
	coinVKRootSeed      string
	coinVKeyRootSeedAut string
}

type publicRand struct {
	seqNo    uint32
	expected string
}

type aip11Vector struct {
	entropySeed        string
	mnemonic           string
	masterSeed         string
	rootSeeds          rootSeeds
	publicRandRootSeed string
	publicRands        []publicRand
}

func getAIP11Vector() []aip11Vector {
	return []aip11Vector{
		{
			entropySeed: "0182bd0265054bb872a69678465fd218116901e6da9c6dbd722f65fb7bc18fdc",
			mnemonic:    "account bicycle dog skate feed switch skin spot joke cream virus coral bird liberty opinion fatal horror twist mesh slogan response this disorder miracle",
			masterSeed:  "4f9045c1d0def3806c8944efb34b85526c63732c262ef4edf88948e356ed405ac500113725f4d799efd120893b8cd1ffbe80ef780b165169e1b2a7da8db54621",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "bf0933e63d540fe6ca0ab133143d2a96d853203d3d332db22f153f93d3a75621e70481878408795d143f0112e908a8d9990e2191f152336eb32d1ec2f9a40bda",
				coinSnKeyRootSeed:   "b1ebc633a935289425b96ce9d746eb1db77e0a695b17e707c2bac6250507c1db688ca2787e9175f907f350d7ed5d2372759708de7a267fa76fdbfaf3d9a66f1d",
				coinDetectorRootKey: "4edffe95c1b6f4a9f9b7ed8d23121d49bdde839e681b333df781f0332a37a2fc8322e5151fdc66df636c6deda0faf23c5d42aede1e75360695190c936f04d0ec",
				coinVKRootSeed:      "46f0de692307076dadbe4beabdd1bd0b93328e352ff29ec4f707a570888a6d1a31be95ae456d3d1cbdb8ce5914f286293b4f431c60694bc8bb3bcf4ea4f3767a",
				coinVKeyRootSeedAut: "2676aecb64de4d828c860328411d180b07f643a34e37230a7e1625bf7f81f0993e327ec2d8307c0f8fe1940bca8be9e3a6656a48eef6625294b96b47ec5be016",
			},
			publicRandRootSeed: "9736259703c7fca47fa91b97577b8d8c0b8a053b52f56dc81b1fc6b94aa83b412d2a40eb7f76f2a00600b4ccdedb080be7b1864a584bfaaebbb7d258656add5f",
			publicRands: []publicRand{
				{seqNo: 0, expected: "2c3175e544f0689d6656e6eb7bde3fbf087c8daecf90d8c034ca2dbcbb2acb04078eb88d3e1aea4d062bd892f2dc52d706b1a68e8d45fd8448d5bd21bf2868b0"},
				{seqNo: 1, expected: "ee7f1639bc8b213d42079449bf29ccd011ee567ec13ece10ae336a7d1f1a15c004ab766c4a19a04eacc644fb602d3172a2038493162273023586967b02d7fe2a"},
				{seqNo: 2, expected: "e79258b7f0fe49df8fa6076d607d1243a6794a83c60b03041fe1fd25bea8ae644cc04a64e0d641e0ec10e5fb29d62f8c38daba0d0d1ff3d2ada254f2d1c7ac57"},
				{seqNo: 3, expected: "1f44d2590d2503037da3ebcec5d3ceeaf570607fca3c64b05725b5f5f9d6168d6c6545fb3a9a96ad6da32fc89350a98128b7fca2752d63feacf678e1038dfbe7"},
				{seqNo: 4, expected: "77beafc39cf1b7525656c764b5bc6b0212fbdd49120cd78713ff037b24fb0ce587da1d00246221e27a9b0c8e44a93af1f8cbe9484f9ca1143fa20ec82398b3be"},
			},
		},
		{
			entropySeed: "d47d04ae7c9f1e040dabf8c9855beb850145c65a9e59b909d6f9b1718d626ab0",
			mnemonic:    "stamp trial clog weird vehicle acoustic cute lecture sister client wife anxiety begin tobacco heavy sleep ribbon exchange salmon glass boat raise print banner",
			masterSeed:  "1e74afb395078dfc222874a2d25ff4d9d5d48a5bcad5a99e23822b65e460ff0881d369c96ef6dfe03aec09b3349cdfdb60bfd24193ce238690f1443ac85d4748",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "0e7343b59f38e7e84c58d5e6cfb19374a5717e785b5b95442bebd3fcb9883833146b674e2356a2f190b8927d86d82fe106abe60af9435b54c1a8aa06fcf6e043",
				coinSnKeyRootSeed:   "c8fa19b0101e1f0dbe9742ebf9d25d41d56aec06d8b03ac32f0689e114c2d6f0c31a9f2bb21e59b4068d9ec63caf71f63f8d5c8503fd1f15f63572e081d99e4f",
				coinDetectorRootKey: "64852150393bd5d22bad7e77c713ed3990c83ae7baf020788cfce93641fd1fa605d4439b3084dd36a5749ec5c1ed97495a4fec98934bc391da59c52e42748990",
				coinVKRootSeed:      "24b67523186eaa5e5ffc5ff736a8d87d4e9124ddc4a5331dbe9771522d3ddf7212996d597ca91929a38bd4a22fe174bbdb0d0f2bb3f27baf51c6a874159c021b",
				coinVKeyRootSeedAut: "25d31a20d649272a0eea69582e6409d8d1dbc9d8c5955f3a428aeaaceadcde0296c814022171008854d67e5589ec1defc9c3dd0e1d585a0c88fd97c7db8e9988",
			},
			publicRandRootSeed: "4878bd2f85ee3e87d41d8059385d56b8a7113e5a5d9b83001bba5535d61e15d5c630105d9c99d4f3f26d0640ab9ee3ee28df07a19002e8a5e42fc6f0567ad78a",
			publicRands: []publicRand{
				{seqNo: 0, expected: "357244a8edc63d352c804eea3594b3254026f93c2cf1858ce958c8cfa8854f9ad0247f5968ae2762dee24f81b312699d76355f171099769c7882f232b2cfc770"},
				{seqNo: 1, expected: "bae03882c192fcc69659f73642b95492409006c6ad77b1ae6e33d35ca80a0cf833c7e0e0ae2f408354e8ca7503259b5a247218e09ca3f0a44031ed00f5381ec5"},
				{seqNo: 2, expected: "3f667bc8ac3437e3ea368940006c32063978a9c115247f8d1f5da163dbcddac926125773186c6b1779f4569d53dc792e265f27e7faa34ebaee072990ac074448"},
				{seqNo: 3, expected: "145a5ece8e0f95fa6dee6962db138b1a14235d4c2cbc14ed0431bc0f5db959d45958ad199839da167cc8d6c67abc7115ad4e4356e142ac5f3e9a7a4875a7b6b5"},
				{seqNo: 4, expected: "f9d58a1c6bc3cdc97bce9ff43c14797887c4e5762b5d50584772a96a0ed46573aed358b364b5aeccc9ed448fdb7b55c8ebad07033be162fd16a59498ccf2fc26"},
			},
		},
		{
			entropySeed: "f2a81f84c7d5d8e07beb2ebfb94d7dcef78c4b0fc2068a737aa96a630ebf08d4",
			mnemonic:    "verify domain thrive moral frown ice use grape sausage skill garage over juice cereal disease dolphin media orange prevent state couch garbage cash mass",
			masterSeed:  "d522fc61d64426561a1c9048818539578988ae43a6a1ae1371366247a95b0df9b9c7430b313ec51cb8a0f834dcf5c9c8878b887d72144285700d8000a53ae165",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "0801bbe02967dff978b2a8a2f7889d7807763f83acedb8f65ce6dbad675f28356d40a89d06a92ffb773cd0dcc3c01481718c3a652eaedd5cfc631c150d6afdbb",
				coinSnKeyRootSeed:   "c967b90497f61a0939e209d90f25cd2eec6755f14c92cd6e58caf62cd5867edf9e4ba82cb136ff9c3a455c5b1c602546737adc839ef39d30774355bfc90c9fd1",
				coinDetectorRootKey: "e3c01a3a827158aa1cb0e4e43cff95f70a7e6afc8042418c86db844fb68f5a9770ccdc45295ec7395e4156541b7743775b1e80791de18118e5db5329fc0e52fe",
				coinVKRootSeed:      "2e7113fee536f9a806e7994814ce2ec71991f28432310bdba4a3cfe92e0d7fcca2bdfcdfddc6b8c9754510026f2c907e0f601c780c07bd54582ee1f110b34062",
				coinVKeyRootSeedAut: "7c8f387396894e8458be0629a492808498dacf41b548d1f16bdd4ebeea997616939abbe967c19427f37ad15deaa1a6bc933a41d05d3a8e6d046fb71f19f7f594",
			},
			publicRandRootSeed: "d50038dc642226c0da4962d9d70c54c63b6923f12b691429e1b6d624dfe7572cfc014c754219d3ea078a38a0fb36df7052a3258758b4fe9c619a785195f7c314",
			publicRands: []publicRand{
				{seqNo: 0, expected: "faef0f512d09d2962d4c1151c13e2d0421766a828c90998b0907cfec54b5a075d533f60bc26ed066bcd31fcd516d6b7d5898b7e32a8a5ecd38eb090517e7d368"},
				{seqNo: 1, expected: "7d7f60f3e923244d2dcfc26678704165ea1a368a9c2a031ab0a691c08a91ac800baedffea60b25c50e361d42d40d1f6fa6c95379afb17a2ee61369ca4234db1c"},
				{seqNo: 2, expected: "71fd996c05e59ffcc0fe9f1149ee9c6216e8ca39825620afd25c68056d22ba214240752b9d294f01dec71bc292a4578b3a318a3eef26253b3d8bb9989206ded5"},
				{seqNo: 3, expected: "46b9c240e01e7baad586d59cfb841e9dd2bc8719d6a1c359c49ec6aab2eb17908288e6732d1a3b63d8793c2ffbd27629fb2ce50bfb414bd530d996468b2f7dff"},
				{seqNo: 4, expected: "74b30b746889bc4e9e6570714c292ea5b46c2f18a5e785478b3ed63398f742e65f05163ca064fe2c01e8bb0fad54a1170a757901ce7e03095f44b1c7fafa8bde"},
			},
		},
		{
			entropySeed: "0000000000000000000000000000000000000000000000000000000000000000",
			mnemonic:    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			masterSeed:  "d4fde696ab58de7b5097a1ec017e59d1f440342c1e278ea092d2c88cec6cc147836245c200218a02dc0d00f8b875d19c7c5d89fdb2f85e085cdc7d45e7a94300",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "48d41357356d035064d5abb63b166413d362ef61f43bf333fffc5351dbbe977fb383e743727f0360b5e16cd1e5fe7fbda816d20e15b869e1bc90acee79962673",
				coinSnKeyRootSeed:   "56c658bad0035e16677d561b22ffb56e194f7160e40eb37466a8afbde5cb7bd76d4061b38a67f32b63b6e03f2b6b3e49a55671170990ee01be672bd4e0356632",
				coinDetectorRootKey: "bddd5c6a3049d96124666f009c0fb3af2b695fd28dd567b5eb25130b24788d2021edeae091cc10ae5154878dc94098c22e60f4a663efaa98c6916d055f7802ca",
				coinVKRootSeed:      "a2f568513bcd1610d4cca7f9770b84f7815c16a011a4fd27387f5e9067191f4f6b823290c0d8a394a412b5d068d3385e5a71cefb541c529e74c7215058f0ba0d",
				coinVKeyRootSeedAut: "7c7ac669e03127f1c040ec46d92d7d273f0ed2acd218f33b1dc56508934210e3ed06b7147dce709ac357ae90712d7b5e3cbcf1dc6bf7e4809a05f03d5b6787ea",
			},
			publicRandRootSeed: "e3a7966dd6e343509b682be724be4035ff8ac480775f4dd72559aa63f6124e569d5341321c43a68eec7c1cb9232cae7bd643da63c9306cdba7e3415315bd48b2",
			publicRands: []publicRand{
				{seqNo: 887699001, expected: "d832f4df91d59bf2c26c3dc75975c1a53b484089726bd4a82f10b46cbb6f56af094374b37d0953350af428153e99873a10265269db2b9ce4b30b0c292f7a3136"},
				{seqNo: 2172391158, expected: "dfa3ecb99d8c6ba43cd0fa4d778f910333125ab47833dc83279785dc87ee634fdd0562d6aa43004f6db3f94efcbdae4ace5f1b4b738de815c299e68aacf06928"},
				{seqNo: 2474215398, expected: "10d5530ffa173f24bdc2a2970e42403d55a676d2d29649f56f9e47458ff04681c1cbc08d6f15bb6fa34dea9d273b50e38da3047c8652dabe65d3f050e8ec6224"},
			},
		},
		{
			entropySeed: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			mnemonic:    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
			masterSeed:  "23ea3cb377aacebca6bc70e8b702b9098e7edd3f9fba5bc0ac03ff193797e83e1cbced261b9c138d9534e3c724683ff14751c352e34c5874439c2aa64f8f6b63",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "2d8dd5f03ae6de9a9852a8ebaa3407819437e426df170e3d1ed23937e8f601ab7a0efa8ddf5c75b58bf99b11ccea6e66242afe4d49f4b46795bee592c480096b",
				coinSnKeyRootSeed:   "c80dc924e3ea9c81c0284e9361d63ab3f1faedfe83a5afbffbfd42fe1a0244c9adacf693290ee764bf12b99e1c07501919096fdd6778e009bdccee203331385e",
				coinDetectorRootKey: "07d0cc2b43f66ef4c082cb633c279550270075f06242c78cfe7ba10a8d48e0dff8eaf1683868af72f5ff2320b8df05d4a486355ff1319a5d359cf72fe45fa4dd",
				coinVKRootSeed:      "32db13d53978947e0295e5ce056daca0db2d14266a83eee1687894a6239b7cde6e2414d966599e1f2e8253a223714eacc7f0cbd17c144264905457873acf2989",
				coinVKeyRootSeedAut: "98d10c98e5cc99c014539b97e93526d60d52f142ed553347c42c77388d886b7d21d9097756276562a895b142d633841883528c0b3ad3e56fe840bfa5ae390477",
			},
			publicRandRootSeed: "7d32f4fcfac883ac7ef93e9fb1ebeaf3ea51086551245e49f7b4f28c052bd661822d95387c56ba1857661d59ad66b30fb4a8c434a9a7bfbb673bc76b64e681db",
			publicRands: []publicRand{
				{seqNo: 202015495, expected: "3276ef36fe147d736fef8cb4008de0cf58ef18dedb298d3c70577be74163e7f1bb3c2948fda6d77b1ed31124717470b790ad87e7180dd41f9d6239f7fdf9f17a"},
				{seqNo: 4184040278, expected: "93d104339ba3a1fe765c7150a0c353dbbdd16feb44a564278d5392f191bdf62c1250a193e3ea4fecb74effe5b4c4bfc780058fc7de65db9deab64873fbd91388"},
				{seqNo: 3136240371, expected: "96744b584bc009bc451720f16ded480be573095bbc9a2af5685d9455fcd46c1271e1314f3bfafae9a0abfbc50b1114a0b812814750632e09c3ec6a1bcf0cd789"},
			},
		},
		{
			entropySeed: "8080808080808080808080808080808080808080808080808080808080808080",
			mnemonic:    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
			masterSeed:  "967ae5d533b0560b01c713f08e6e8fc5cac7e106e029c8a6ad835e68ae94db5cdb40edf00441cd9232be026089a86c8f8eee64292e2152c45a29d181268493dd",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "6af846a26566e6dcd5e55dc5549fda24a1afd9e420becbc383228db6cbb18c21436e0b0b9e7c331359e84efddc5fa06bebcc7a43e0f454becf8962cb5d9d4631",
				coinSnKeyRootSeed:   "9c45a797fc2d98fa6d259d2387565dde886d1a7fd316b05f586ec60b04c6062ca06efc1bcc56c620c11b087ec2068a64cdc9e8fe9fd96c1fbd6462b7c0e463dc",
				coinDetectorRootKey: "6b9caf9485bc375c5d810a2cc07774b688a736ff5ce8023ed22f7467ab51f43c106eaf975fdcd1b2c0eb7afe6df5c16242dab027f14cdbe3b057e05e58c448b3",
				coinVKRootSeed:      "57e389fafad8cdd8d496fc6fde89e5ebb1cb4dc96fcb1cdbd58e757579603b66d13daa40e9ba315bde8aefc1c4cfcae7e2bd45c98eb6289ab306b30fdc7d770d",
				coinVKeyRootSeedAut: "81a723c11135ee7c4308ba47149c419ebb069110b44f986b656f648429e7d2fdd2f3e3cc7855b504bf6d52528e2e5014c9c15375d23172f12eac9ce8a92a39f8",
			},
			publicRandRootSeed: "d8e0a5709e36a1b2fdb18b3c592859f23ca9743911396231be1b97ca6f85b8b124b30013773b5b0e44ba65dd566a81f6697e52e2897b0375f6761519e19da4fa",
			publicRands: []publicRand{
				{seqNo: 2400773142, expected: "1823c3c895c419aa32b993d788e87a722358d24dd57e05f0ab0c749e39a5be48e0075fdc07038eb9e1adbc274dd7cfa3d313ec97fcdefaff56aa9770d6046fd6"},
				{seqNo: 94650305, expected: "d2e984e12d818ba294d0571722d51d300ce32549016f0bc93cb1850b811d9b619f34bf3aa909c7d4a65253202fe11148cefd57a6b42dcb93891d94123e1dc474"},
				{seqNo: 3668972267, expected: "bc160f59c1885986b185540d8628485645ece76952bef6afde49ae7a5c1b5d89f8e3118ecf0d4f3d46ddae7cf95b88c9a9b49fe170a0696a6de9027782bde90e"},
			},
		},
		{
			entropySeed: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			mnemonic:    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
			masterSeed:  "4abcc8067fefc753596a079a6b2c81bbff92f65c0bae6369f7572f8cfe881161b7fc009b5591849caf79d7896c1963f2a39cc57049247173ecb037af59f97718",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "5b14a23daa5936f5828e5a7117dc1fd76c4aab6a23a57de8419ee52ca253021aaa6a4ccd6468e57ebc5ffb2e672171cd0216febd76fe1e8ab07fe16ca2775d71",
				coinSnKeyRootSeed:   "a46e06fa6d94789a147f22d4862e39b40a0d2cc05ca26738705cfe2d399d3c87b71f8d99dfc3900281a3b569a5ed2f54f0ee4d0d807593599bd2bedc170d4b7c",
				coinDetectorRootKey: "ae609c4c2ee8d33395452d0e03cb6be58a939ca6f28095235622cf542a51f407b0a2f31a8bdff957960518be5a1e2b8c0be53d98b75947525754a6820211ce47",
				coinVKRootSeed:      "7c32ecbc44e49533ce29946314848d60b5e432080a3de6db3b0abaab983a4a55d40744b86a10817347e89588ab622bc9a8369b3958d7f42b49b263992238cc38",
				coinVKeyRootSeedAut: "59b9400f1448564bccaa1a4c679810844fcaeef76a3e6fc6b75ba39e18485025789b917766cd589e3173e950a9b0bc4db78b9fd8a150bb46be1ca795d4e4e415",
			},
			publicRandRootSeed: "110851bc774a02d79b8df4896fd4e497befc1c7bb8d447d282fe94bb13574fb4ad68bca6337dd8575e907d4a94ef4dc2d180c9f4e99d567b19ca2d9e4459a214",
			publicRands: []publicRand{
				{seqNo: 4151069018, expected: "577ca99203857d5b233abafbee3327e7ea2d4af5d0d64014a4ac047a8f2d911c698bbee62e8d19e5738f615730b594e86f0098f02b29ef2d88ae3a9e92253a7d"},
				{seqNo: 810230981, expected: "1ed8f5a3bbdce1201782376807364ff46424bcebd43a01f6b8074c97c4c4cc576b497a8931ae874d08ae5aa04b4420d771e79a2a97a2636ee20d880424df6b86"},
				{seqNo: 1205304842, expected: "ef6df803d5b2ab20050752cdc59f7c4e16f11172e86782092dc15413484026b7aed522747178ddcc5b1b57f3067636b9392a41117a2975216d7bd34448eb82c5"},
			},
		},
		{
			entropySeed: "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
			mnemonic:    "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
			masterSeed:  "ec243d0407f4731085ecd7bef047db836b675e8622c937454c3313a8129d67337f7fb648ed71a8e7214f38779edf6c29bffb13fff3b42b7c8fc64ace75381c7f",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "1a8efaa57603373aa226bd25a734b355570f777dd3a50b113cdea7ce3902537ca80682f918a4c26796b4f3a2c64ceeab877d091adac6b1083237fdef19a81d5b",
				coinSnKeyRootSeed:   "b3b6835aa6dcbe526ff030bca5e71a825a23ff1605902f39e392971df493c30b2dd3c74082a97351bc3b0a152e1563f724ddbbf2adb8c2906e00c77d235b5515",
				coinDetectorRootKey: "becde156316d7470eacdc12d01452fc56aa27bb6f1a7ace1ba1a26da3752aabaf819d97609513fc11e4f8e34a631e062d6467626d47917e0438fdf3c3eb59ccb",
				coinVKRootSeed:      "ed54c3155e21d98f316fb521c92b09679e763e9b80695d62ab76cc17c57ece5786b54d83494f0e81967ff37c772f7dbcb830069665ad2fc95b83acfe6f9d3ea7",
				coinVKeyRootSeedAut: "a230714e5df98c856dedf7a387ac486b5ffa8fabf562d3563fd45b27ef16322cd15e2b3726300215b4c597b3bed385060a0a280c009cd5bbbbefbc041e0f56c1",
			},
			publicRandRootSeed: "f4b510fce8ad25bb3e8e2e3a371a813cd8557d1930284c1b54b301b481965232e4e36a91c19c622eba1625926d4df7654fbe51036d0af31bc6a93e1fd9f09932",
			publicRands: []publicRand{
				{seqNo: 1386746106, expected: "d6ed41486c223a9bc0877b1465d2ea412ecd7dc5d4aa6e7f5caaf65c1265d7f930e55c7c626715d7a9c614b00be192fbbae3293f8440e553f079ab35b24510db"},
				{seqNo: 757380707, expected: "2245d0ecf4e2ddffbeb80fbef9b507e35561acce80451c85e548eb431123ecd7032d34b182a381f5356db1dd5e92d2c0b40a36cb3e3a98b6ecdf81ae65f6e1e5"},
				{seqNo: 1590126875, expected: "f069a5a75a4563e6e190e8f8b1443341ce3272b68cff99ff384ac47478541dc5b061fcc78fd750fa3beea3a6e86530691cada8af012d1c12b34344bdab0caaeb"},
			},
		},
		{
			entropySeed: "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
			mnemonic:    "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
			masterSeed:  "cd33cfeaec5a48f52f485fea5e9637889609aa64cab852d80aa258e989071c607ae9c1f3b37bafe1284d6e06811bd4dfaf1e15a2bb9f895ef7a7584d0ac76903",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "88087c0f9482aed16a34017404c45541055be1624993b727d7296be581fa4d1105044b680ab2f00f8dfdb8f6f7712580082e6196e09179b27b529e9b1310d8fb",
				coinSnKeyRootSeed:   "a02c93c369274f3d866e98cf6980dfbac25587cbbb4c8b5f45c3f62e2e94b214913dcbe832a2908511b9d1373feb6ef1df42d147bc11a9e199d3d51638ca771f",
				coinDetectorRootKey: "babca8531d788cbec214e9a3180301479b2df429705aeb8e454630c5d54b0fccdc831f5a1c12bc3c8d92ac3ad37e0c195a7ea3041ff39d3bb855f02eadfb57c7",
				coinVKRootSeed:      "b2c572f0108cc12627d17f8b93e7dd86f0545ee568309c2c93ecf4d514b2501bb1e596e2bd4005d3068fe96f430b5564cd393aabfd792c40554bb9a09c8e1406",
				coinVKeyRootSeedAut: "3acda1d4b30360b2a200300238638f12a4e037eb2ab86e48b290afbd02bab60bd0b5e4e7bffa8f24359acd5c5ce53ec1b3328ed3f83ab6a252cab464228ca50f",
			},
			publicRandRootSeed: "e02c06fbe97da236dcfb098b256f4edf4727f0b19cf5f0afe7f4ed9ea524dab71adbfd0536267e7c8ebe0909d4820de92f5c37d3bfca0aeb1c34a210d9be189d",
			publicRands: []publicRand{
				{seqNo: 1349967783, expected: "1ab49a08f7dc26c37d10e78d9afdd81c08601391b31a81add08ffdf9374449531e16876deeaac3d1d896af37f26d0e8b4845205e11dc508c2c4789f0c1150aa2"},
				{seqNo: 2895057325, expected: "3eea3875fb600d6adf5134bb61ee794cd250441315dab228fef0ed070dd172e29382e62c1e09d1dd4f6b60113effed91d3a9c98c606d05307aeb644fc2c62402"},
				{seqNo: 335187303, expected: "627796c337060b19ec1c7178b4630f08062c6259318ad20b04d7f3308dff00b9416dfc75652cf3e63d63bec1bdf99599edc22c78003a885d1c6c42a94348d5bf"},
			},
		},
		{
			entropySeed: "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
			mnemonic:    "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
			masterSeed:  "7242f5fd0c0b8df7429d60a7a757687eb486e4f45f50f675a9d23fa034607f3a0e3a7c12a6d7eb0270bfcbdea0e045f8562f2a312765cdbdee4a31ee825634e3",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "70f94f5a37f48e64c8ccb91779d131c6fbd25f44e3a463a196f21de7502f2c5f5aa9461361af03d1fc560df9ccb96c1afaf1758e9112a01d555cdf42ead3b7de",
				coinSnKeyRootSeed:   "c63f57958e0b02af215837e7a9f7da3f6830ca849e9cc586a1016f59d518ff2db832d9b3a70fa8f46f91d63af9ecf4681a639683c8b178a3e4cc4d0ad2e2fdab",
				coinDetectorRootKey: "d1d62e7f9bee336a61e360785bf1fca64dc9b90602b99abeaff44f48c3dfdc7414d2a23dca36c929cbf093b27e63d6797797ffb8ff2c3862c90d3dbf4fa9a924",
				coinVKRootSeed:      "ae85d5eafd21843dc6f7518861982107fa63a2a95ab4eb09d0c7b50e5d4f3f9aafed0f23b2a1958c27f1f5d0d27e23f1716a9093abe2430de1f028f51a397b73",
				coinVKeyRootSeedAut: "4b4c30616d2a0b03fbae33ac9e172d4150a236b4ac416b7e11518b4b5bebd600dd3fbf9fe01759e1e56371f2dc9e14becc7058b58494fa1be57affa6c89af73c",
			},
			publicRandRootSeed: "dff3840573a631233b893c59c33518324f84c6da4e13cc19dff3aaca66285b0914dee95e6e8b6f2d1cba3d8ac46beebec09f7b7fadfd1a358cdd5bc26aa84a8d",
			publicRands: []publicRand{
				{seqNo: 3037234089, expected: "4fee704d8d687a026cfd98d1a19dc0cc1d7298b350f9115a722e4388d204e9036c8b698e2870ca8e04d5fc7716764ad16278022179d05bca86e8a5fdb0941b2c"},
				{seqNo: 3952040230, expected: "77a47010286d7b308e0ec22dfac6768f3a44a430ca54e11fcf72be6cf3379b4fa30f16a246e404166d2b13c02dc16e9300d84baf3986bd10d2eae731d1a43d52"},
				{seqNo: 997927870, expected: "d58a8e1f7e19a4f5ed092636be3477284a24d7b9d4d928776512123d291945796f3e286f097bac617faf946d5d55286eb7c670a26f382b0a6e1e27092f36a291"},
			},
		},
		{
			entropySeed: "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
			mnemonic:    "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
			masterSeed:  "e82bbf95ad7518c82df7165f575d07634edb48d9eb63e444a104e625dbca0e16dfc15e5004985e94597fb67b72fd9c35eb7621a654d76c9189c47b72c33ec58c",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "9f3e551aeafc8304816980d6c1e3fd4c10d24635df07900cf5dddfbe72a1e98d8308fc4cb7acf827e21136d352b92ba79bf8bdbbca45fc367817f65ec39a0367",
				coinSnKeyRootSeed:   "3f185e15f879378bc7df9c604fe966024f2aa46101eb9aecf873a556126ad924c9d8f1bce9a28238989404924cf1ee571b8f06015843010a38ed1fca6d9263e2",
				coinDetectorRootKey: "0ea3fc5da6fff18dfe3dfc9a87a394ac7543fa2f0cf26e5d8b7e2ec7bd3f7ac96d063217f60faa92d1de41b2504684219852de154b81ab3a507ba02562957591",
				coinVKRootSeed:      "a808ef8b153c4f53ad1dc6a64c2c2fea2998cdb41c2abdf1e4659bc07a9369a0048f4b5fd82385f7dc31780e789e6eed020cff9d0eacddd0faefe6d86e61e4ec",
				coinVKeyRootSeedAut: "d5d86a1e486ea52013b2a6967a65b16370b1cee6748ec92a6cd5bf45726e2758e2cf9f8b7935c825c472ee93a5895ba2ce697d021e84f0110f849604b7cc8b7b",
			},
			publicRandRootSeed: "8c8f88993d54e24c2d676042df3a3839d406d7d0d5166ca6d05a52d1aad0b04dc539f9194dcf492afce2ce1711b0c8e92e0660a54698c94c86835219304084c4",
			publicRands: []publicRand{
				{seqNo: 2282586443, expected: "13abd9c51cf91e7ffd7f90daf2c1bf3a1210bba87d75e4cfe09fa285a08c4079aea3efdcaa83f7a83df7a265d709bd6f817670a4791585e7011b461912479788"},
				{seqNo: 2058736541, expected: "2b51f39a3e6a049a5ab3d856962869580f889287758f32ebe7a5185f620da93fc4df5e62ce2d0b11295e3ad0e707df306c3c21ab45fe718c431e7c6ef8eb6c73"},
				{seqNo: 3650681307, expected: "b3923c0758fe02869413a515dbc8fd129b2b876f472c8db3ec114455fb21d37d3d97cf54f3f7540e182a610507e04dce7056bf8b294bb2bd887c22b7c9c742ca"},
			},
		},
	}
}

// Helper functions Examples and Tests

func TestCalculateChecksum(t *testing.T) {
	testCases := []struct {
		name           string
		entropy        []byte
		checksumLength int
		expected       []bool
	}{
		{
			name:           "Empty entropy, 0 bits checksum",
			entropy:        []byte{},
			checksumLength: 0,
			expected:       []bool{},
		},
		{
			name:           "16 bytes entropy, 4 bits checksum",
			entropy:        []byte{0xb2, 0xb5, 0x24, 0x8d, 0xeb, 0xc5, 0xe4, 0xa2, 0x41, 0x28, 0x63, 0x96, 0xd8, 0x9e, 0x25, 0x12},
			checksumLength: 4,
			expected:       []bool{true, false, false, true},
		},
		{
			name:           "32 bytes entropy, 8 bits checksum",
			entropy:        []byte{0x12, 0xd5, 0xaf, 0x2c, 0x5f, 0x6a, 0xee, 0xb9, 0xcb, 0x53, 0x8d, 0x66, 0x6a, 0x7d, 0xdb, 0x26, 0x79, 0x61, 0x8f, 0xbf, 0x55, 0x05, 0xc6, 0xcb, 0x73, 0x7b, 0x46, 0x77, 0xbe, 0xeb, 0x9f, 0xbb},
			checksumLength: 8,
			expected:       []bool{true, false, true, false, true, true, true, false},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := aip11.CalculateChecksum(tc.entropy, tc.checksumLength)
			assert.Equal(t, tc.expected, result, "CalculateChecksum result should match expected")
		})
	}
}

func TestBytesToBits(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected []bool
	}{
		{
			name:     "Single byte conversion",
			data:     []byte{10},
			expected: []bool{false, false, false, false, true, false, true, false},
		},
		{
			name:     "Multiple bytes conversion",
			data:     []byte{240, 15},
			expected: []bool{true, true, true, true, false, false, false, false, false, false, false, false, true, true, true, true},
		},
		{
			name:     "All zeros",
			data:     []byte{0},
			expected: []bool{false, false, false, false, false, false, false, false},
		},
		{
			name:     "All ones",
			data:     []byte{255},
			expected: []bool{true, true, true, true, true, true, true, true},
		},
		{
			name:     "Empty byte array",
			data:     []byte{},
			expected: []bool{},
		},
		{
			name: "Complex byte array",
			data: []byte{170, 85, 204},
			expected: []bool{
				true, false, true, false, true, false, true, false,
				false, true, false, true, false, true, false, true,
				true, true, false, false, true, true, false, false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := aip11.BytesToBits(tc.data)
			assert.Equal(t, tc.expected, result, "BytesToBits result should match expected")
		})
	}
}

func TestBitsToBytes(t *testing.T) {
	testCases := []struct {
		name        string
		bits        []bool
		expected    []byte
		expectError bool
	}{
		{
			name:        "Single byte conversion",
			bits:        []bool{false, false, false, false, true, false, true, false},
			expected:    []byte{10},
			expectError: false,
		},
		{
			name:        "Multiple bytes conversion",
			bits:        []bool{true, true, true, true, false, false, false, false, false, false, false, false, true, true, true, true},
			expected:    []byte{240, 15},
			expectError: false,
		},
		{
			name:        "All zeros",
			bits:        []bool{false, false, false, false, false, false, false, false},
			expected:    []byte{0},
			expectError: false,
		},
		{
			name:        "All ones",
			bits:        []bool{true, true, true, true, true, true, true, true},
			expected:    []byte{255},
			expectError: false,
		},
		{
			name:        "Empty bit array",
			bits:        []bool{},
			expected:    []byte{},
			expectError: false,
		},
		{
			name:        "Bit length not multiple of 8",
			bits:        []bool{true, false, true},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := aip11.BitsToBytes(tc.bits)
			if tc.expectError {
				assert.Error(t, err, "BitsToBytes should return an error")
			} else {
				assert.NoError(t, err, "BitsToBytes should not return an error")
				assert.Equal(t, tc.expected, result, "BitsToBytes result should match expected")
			}
		})
	}
}

func TestLookupIndex(t *testing.T) {
	testCases := []struct {
		word  string
		index int
	}{
		{word: "abandon", index: 0},
		{word: "about", index: 3},
		{word: "zoo", index: 2047},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			result, err := aip11.LookupIndex(tc.word, wordlists.English)
			assert.NoError(t, err, "LookupIndex should not return an error")
			assert.Equal(t, tc.index, result, "LookupIndex result should match expected")
		})
	}
}

func TestIntToBinary11(t *testing.T) {
	testCases := []struct {
		input    int
		expected string
	}{
		{expected: "00000000001", input: 1},
		{expected: "00000001000", input: 8},
		{expected: "10000000000", input: 1024},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			result, err := aip11.IntToBinary11(tc.input)
			assert.NoError(t, err, "IntToBinary11 should not return an error")
			assert.Equal(t, tc.expected, result, "IntToBinary11 result should match expected")
		})
	}
}

func TestBinaryToInt11(t *testing.T) {
	testCases := []struct {
		input    string
		expected int
	}{
		{input: "00000000001", expected: 1},
		{input: "00000001000", expected: 8},
		{input: "10000000000", expected: 1024},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			result, err := aip11.BinaryToInt11(tc.input)
			assert.NoError(t, err, "BinaryToInt11 should not return an error")
			assert.Equal(t, tc.expected, result, "BinaryToInt11 result should match expected")
		})
	}
}

func TestEqualBits(t *testing.T) {
	testCases := []struct {
		a        []bool
		b        []bool
		expected bool
	}{
		{
			a:        []bool{true, false, true, false},
			b:        []bool{true, false, true, false},
			expected: true,
		},
		{
			a:        []bool{true, false, true, false},
			b:        []bool{true, false, false, true},
			expected: false,
		},
		{
			a:        []bool{true, false, true},
			b:        []bool{true, false, true, false},
			expected: false,
		},
		{
			a:        []bool{},
			b:        []bool{},
			expected: true,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			assert.Equal(t, tc.expected, aip11.EqualBits(tc.a, tc.b), "EqualBits result should be the same")
		})
	}
}

func TestEncodeSeqNo(t *testing.T) {
	testCases := []struct {
		seqNo    uint32
		expected string
	}{
		{seqNo: 1, expected: "00000001"},
		{seqNo: 10, expected: "0000000a"},
		{seqNo: 30, expected: "0000001e"},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			assert.Equal(t, aip11.EncodeSeqNo(tc.seqNo), tc.expected, "Sequence number should be encoded correctly")
		})
	}
}

func TestPRF(t *testing.T) {
	testCases := []struct {
		key      string
		input    string
		expected string
	}{
		{key: "b799df2d62caa78831c196c5297b96e1c983c4ff40df6c1b1f5151396900a428", input: "ABELIAN", expected: "ce58d3e236052c5ce79f180e4d6b8b4745fff1ea527f3a8722215a53ba3d15d5c17ec088d9353d77ce0d1e098929294ae3c2a417f0bb62c0de1214787c87573c"},
		{key: "b799df2d62caa78831c196c5297b96e1c983c4ff40df6c1b1f5151396900a428", input: "PQABELIAN", expected: "264c1494933cab980d19a13859382bb89b7fdb3afef5d682b0cf280e492e60c333a98ac93d5f0265fa677e1a848f4eb5d083a8cee2df60145ab38937a190ef5f"},
		{key: "1d6076ef7dc55812b5d64c5644a104044e3adf1ac0ecc07fe38379dfd656a7b2", input: "ABELIAN", expected: "f0f2b810a8d1cf6d0392fb5cff14893de21ee92ba003ecfa1206904647c62a6a4e0396952bcf936aa747a373c6eaa4769ad40cc5438ec60c9b43ab74073bb14a"},
		{key: "1d6076ef7dc55812b5d64c5644a104044e3adf1ac0ecc07fe38379dfd656a7b2", input: "PQABELIAN", expected: "fdee680458d003d7fffb7d46b4ace47d4ea80292f9e105863fe034298ebdf579c8100de159e230127f15d665bfafd1263ad4aa4f91a2ed816253285d3e271d27"},
		{key: "201851eeb992890cebfdeecdb4325a77fcffe405ea9ef2ef920e533523c7c441", input: "ABELIAN", expected: "d32a5b7133087c99e9095cea7aaac96139f46c7b69d80b26ebc6d2b5c079ddb3794ef3cc53928b292c13586411cfabf903b7896bdd45b2197f80e4aa91d90e82"},
		{key: "201851eeb992890cebfdeecdb4325a77fcffe405ea9ef2ef920e533523c7c441", input: "PQABELIAN", expected: "e92803dea53aa8bf7e03e0dd10c4228d32414a9716bed299ac70825d93ccdf2a3e568db8b2f9a01ec33c8ceef9a782cf6b12aaec7ac670132359d58e66dcb793"},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			key, err := hex.DecodeString(tc.key)
			assert.NoError(t, err, "Key should be decoded correctly")
			hash := aip11.PRF(key, []byte(tc.input))
			assert.Equal(t, tc.expected, hex.EncodeToString(hash), "PRF should be the same")
		})
	}
}
