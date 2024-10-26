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
	entropySeed := aip11.SampleEntropySeed()
	fmt.Println(len(entropySeed))
	// Output: 32
}

func TestSampleEntropySeed(t *testing.T) {
	entropySeed := aip11.SampleEntropySeed()
	assert.Equal(t, 32, len(entropySeed), "Entropy seed length should be 32")
}

func ExampleEntropySeedToMnemonic() {
	entropySeed := aip11.SampleEntropySeed()
	mnemonic := aip11.EntropySeedToMnemonic(entropySeed, wordlists.English)
	fmt.Println(len(mnemonic))
	// Output: 24
}

func TestEntropySeedToMnemonic(t *testing.T) {
	vectors := getBIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			mnemonic := aip11.EntropySeedToMnemonic(entropySeed, wordlists.English)
			assert.Equal(t, v.mnemonic, strings.Join(mnemonic, " "), "Mnemonic should be the same")
		})
	}
}

func ExampleMnemonicToEntropySeed() {
	entropySeed := aip11.SampleEntropySeed()
	mnemonic := aip11.EntropySeedToMnemonic(entropySeed, wordlists.English)
	entropySeed2 := aip11.MnemonicToEntropySeed(mnemonic, wordlists.English)
	fmt.Println(len(entropySeed2))
	// Output: 32
}

func TestMnemonicToEntropySeed(t *testing.T) {
	vectors := getBIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			entropySeed2 := aip11.MnemonicToEntropySeed([]string(strings.Split(v.mnemonic, " ")), wordlists.English)
			assert.Equal(t, entropySeed, entropySeed2, "Entropy seed should be the same")
		})
	}
}

func ExampleEntropySeedToMasterSeed() {
	entropySeed := aip11.SampleEntropySeed()
	masterSeed := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
	fmt.Println(len(masterSeed))
	// Output: 64
}

func TestEntropySeedToMasterSeed(t *testing.T) {
	vectors := getBIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			masterSeed2 := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
			assert.Equal(t, v.masterSeed, hex.EncodeToString(masterSeed2), "Master seed should be the same")
		})
	}
}

func ExampleMasterSeedToAccountRootSeeds() {
	entropySeed := aip11.SampleEntropySeed()
	masterSeed := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
	accountRootSeeds := aip11.MasterSeedToAccountRootSeeds(masterSeed)
	fmt.Println(len(accountRootSeeds))
	for _, seed := range accountRootSeeds {
		fmt.Println(len(seed))
	}
	// Output: 4
	// 64
	// 64
	// 64
	// 64
}

func TestMasterSeedToAccountRootSeeds(t *testing.T) {
	vectors := getBIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			masterSeed := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
			accountRootSeeds := aip11.MasterSeedToAccountRootSeeds(masterSeed)
			assert.Equal(t, v.rootSeeds.coinSpKeyRootSeed, hex.EncodeToString(accountRootSeeds[0]), "Coin SP key root seed should be the same")
			assert.Equal(t, v.rootSeeds.coinSnKeyRootSeed, hex.EncodeToString(accountRootSeeds[1]), "Coin SN key root seed should be the same")
			assert.Equal(t, v.rootSeeds.coinDetectorRootKey, hex.EncodeToString(accountRootSeeds[2]), "Coin detector root key should be the same")
			assert.Equal(t, v.rootSeeds.coinVKRootSeed, hex.EncodeToString(accountRootSeeds[3]), "Coin VK root seed should be the same")
		})
	}
}

func ExampleMasterSeedToAccountPublicRandRootSeed() {
	entropySeed := aip11.SampleEntropySeed()
	masterSeed := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
	publicRandRootSeed := aip11.MasterSeedToAccountPublicRandRootSeed(masterSeed)
	fmt.Println(len(publicRandRootSeed))
	// Output: 64
}

func TestMasterSeedToAccountPublicRandRootSeed(t *testing.T) {
	vectors := getBIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			masterSeed := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
			publicRandRootSeed := aip11.MasterSeedToAccountPublicRandRootSeed(masterSeed)
			assert.Equal(t, v.publicRandRootSeed, hex.EncodeToString(publicRandRootSeed), "Public rand root seed should be the same")
		})
	}
}

func ExampleDerivePublicRand() {
	entropySeed := aip11.SampleEntropySeed()
	masterSeed := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
	publicRandRootSeed := aip11.MasterSeedToAccountPublicRandRootSeed(masterSeed)

	for i := 1; i <= 5; i++ {
		publicRand := aip11.DerivePublicRand(publicRandRootSeed, uint32(i))
		fmt.Println(len(publicRand))
	}
	// Output: 64
	// 64
	// 64
	// 64
	// 64
}

func TestDerivePublicRand(t *testing.T) {
	vectors := getBIP11Vector()
	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector %d", i), func(t *testing.T) {
			entropySeed, err := hex.DecodeString(v.entropySeed)
			assert.NoError(t, err, "Entropy seed should be decoded correctly")
			masterSeed := aip11.EntropySeedToMasterSeed(entropySeed, []byte{})
			publicRandRootSeed := aip11.MasterSeedToAccountPublicRandRootSeed(masterSeed)
			for _, publicRand := range v.publicRands {
				assert.Equal(t, publicRand.expected, hex.EncodeToString(aip11.DerivePublicRand(publicRandRootSeed, publicRand.seqNo)), "Public rand should be the same")
			}
		})
	}
}

type rootSeeds struct {
	coinSpKeyRootSeed   string
	coinSnKeyRootSeed   string
	coinDetectorRootKey string
	coinVKRootSeed      string
}

type publicRand struct {
	seqNo    uint32
	expected string
}

type bip11Vector struct {
	entropySeed        string
	mnemonic           string
	masterSeed         string
	rootSeeds          rootSeeds
	publicRandRootSeed string
	publicRands        []publicRand
}

func getBIP11Vector() []bip11Vector {
	return []bip11Vector{
		{
			entropySeed: "0182bd0265054bb872a69678465fd218116901e6da9c6dbd722f65fb7bc18fdc",
			mnemonic:    "account bicycle dog skate feed switch skin spot joke cream virus coral bird liberty opinion fatal horror twist mesh slogan response this disorder miracle",
			masterSeed:  "4f9045c1d0def3806c8944efb34b85526c63732c262ef4edf88948e356ed405ac500113725f4d799efd120893b8cd1ffbe80ef780b165169e1b2a7da8db54621",
			rootSeeds: rootSeeds{
				coinSpKeyRootSeed:   "bf0933e63d540fe6ca0ab133143d2a96d853203d3d332db22f153f93d3a75621e70481878408795d143f0112e908a8d9990e2191f152336eb32d1ec2f9a40bda",
				coinSnKeyRootSeed:   "b1ebc633a935289425b96ce9d746eb1db77e0a695b17e707c2bac6250507c1db688ca2787e9175f907f350d7ed5d2372759708de7a267fa76fdbfaf3d9a66f1d",
				coinDetectorRootKey: "4edffe95c1b6f4a9f9b7ed8d23121d49bdde839e681b333df781f0332a37a2fc8322e5151fdc66df636c6deda0faf23c5d42aede1e75360695190c936f04d0ec",
				coinVKRootSeed:      "46f0de692307076dadbe4beabdd1bd0b93328e352ff29ec4f707a570888a6d1a31be95ae456d3d1cbdb8ce5914f286293b4f431c60694bc8bb3bcf4ea4f3767a",
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
			if tc.expectError {
				assert.Panics(t, func() { aip11.BitsToBytes(tc.bits) }, "BitsToBytes should panic")
			} else {
				assert.Equal(t, tc.expected, aip11.BitsToBytes(tc.bits), "BitsToBytes result should match expected")
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
			assert.Equal(t, tc.index, aip11.LookupIndex(tc.word, wordlists.English), "LookupIndex result should match expected")
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
			assert.Equal(t, tc.expected, aip11.IntToBinary11(tc.input), "IntToBinary11 result should match expected")
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
			assert.Equal(t, tc.expected, aip11.BinaryToInt11(tc.input), "BinaryToInt11 result should match expected")
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
