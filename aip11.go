package aip11

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strconv"
)

// Main functions

// SampleEntropySeed generates a random 256-bit(32 bytes) entropy seed.
func SampleEntropySeed() []byte {
	entropySeed := make([]byte, 32)
	_, err := rand.Read(entropySeed)
	if err != nil {
		panic("failed to generate secure random bytes: " + err.Error())
	}

	return entropySeed
}

// EntropySeedToMnemonic converts a 256-bit entropy seed to a mnemonic.
func EntropySeedToMnemonic(entropySeed []byte, wordlist []string) []string {
	if len(wordlist) != 2048 {
		panic("wordlist must contain 2048 words")
	}

	entropyBitLength := len(entropySeed) * 8
	if entropyBitLength != 256 {
		panic("entropy seed must be 256 bits")
	}

	checksumLength := entropyBitLength / 32
	checksum := CalculateChecksum(entropySeed, checksumLength)

	bits := BytesToBits(entropySeed)
	bits = append(bits, checksum...)

	words := []string{}
	for i := 0; i < len(bits); i += 11 {
		chunk := ""
		for _, b := range bits[i : i+11] {
			if b {
				chunk += "1"
			} else {
				chunk += "0"
			}
		}
		index := BinaryToInt11(chunk)
		words = append(words, wordlist[index])
	}

	return words
}

// MnemonicToEntropySeed converts a mnemonic to a 256-bit entropy seed.
func MnemonicToEntropySeed(mnemonic []string, wordlist []string) []byte {
	if len(wordlist) != 2048 {
		panic("wordlist must contain 2048 words")
	}

	if len(mnemonic) != 24 {
		panic("invalid mnemonic")
	}

	bits := []bool{}
	for _, word := range mnemonic {
		index := LookupIndex(word, wordlist)
		binaryString := IntToBinary11(index)
		wordBits := []bool{}
		for _, b := range binaryString {
			if b == '1' {
				wordBits = append(wordBits, true)
			} else {
				wordBits = append(wordBits, false)
			}
		}
		bits = append(bits, wordBits...)
	}

	checksumLength := len(bits) / 33
	entropySeedBits := bits[:len(bits)-checksumLength]
	checksumBits := bits[len(bits)-checksumLength:]

	entropySeedBytes := BitsToBytes(entropySeedBits)
	expectedChecksum := CalculateChecksum(entropySeedBytes, checksumLength)
	if !EqualBits(checksumBits, expectedChecksum) {
		panic("checksum mismatch")
	}

	return entropySeedBytes
}

// EntropySeedToMasterSeed derives the master seed from the entropy seed.
func EntropySeedToMasterSeed(entropySeed []byte, customizationContext []byte) []byte {
	if len(entropySeed) != 32 {
		panic("entropy seed must be 32 bytes")
	}
	return PRF(entropySeed, append([]byte("AccountMasterSeed"), customizationContext...))
}

// MasterSeedToAccountRootSeeds derives the account root seeds from the master seed.
func MasterSeedToAccountRootSeeds(masterSeed []byte) [][]byte {
	if len(masterSeed) != 64 {
		panic("master seed must be 64 bytes")
	}

	coinSpKeyRootSeed := PRF(masterSeed, []byte("CoinSpendKeyRootSeed"))
	coinSnKeyRootSeed := PRF(masterSeed, []byte("CoinSerialNumberKeyRootSeed"))
	coinDetectorRootKey := PRF(masterSeed, []byte("CoinDetectorRootKey"))
	coinVKRootSeed := PRF(masterSeed, []byte("CoinValueKeyRootSeed"))

	return [][]byte{
		coinSpKeyRootSeed,
		coinSnKeyRootSeed,
		coinDetectorRootKey,
		coinVKRootSeed,
	}
}

// MasterSeedToAccountPublicRandRootSeed derives the public rand root seed from the master seed.
func MasterSeedToAccountPublicRandRootSeed(masterSeed []byte) []byte {
	if len(masterSeed) != 64 {
		panic("master seed must be 64 bytes")
	}
	return PRF(masterSeed, []byte("PublicRandRootSeed"))
}

// DerivePublicRand derives the public rand from the public rand root seed.
func DerivePublicRand(publicRandRootSeed []byte, index uint32) []byte {
	if len(publicRandRootSeed) != 64 {
		panic("public rand root seed must be 64 bytes")
	}
	seqNo := EncodeSeqNo(index)
	return PRF(publicRandRootSeed, []byte(seqNo))
}

// Helper functions

// Calculate the checksum
func CalculateChecksum(entropy []byte, checksumLength int) []bool {
	hash := sha256.Sum256(entropy)
	hashBits := BytesToBits(hash[:])
	return hashBits[:checksumLength]
}

// BytesToBits Convert byte array to bit array
func BytesToBits(data []byte) []bool {
	bits := []bool{}
	for _, b := range data {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>i)&1 == 1)
		}
	}
	return bits
}

// BitsToBytes Convert bit array to byte array
func BitsToBytes(bits []bool) []byte {
	if len(bits)%8 != 0 {
		panic("bit length is not a multiple of 8")
	}
	bytes := make([]byte, len(bits)/8)
	for i := 0; i < len(bytes); i++ {
		for j := 0; j < 8; j++ {
			if bits[i*8+j] {
				bytes[i] |= 1 << uint(7-j)
			}
		}
	}
	return bytes
}

// LookupIndex looks up the index of a word in the wordlist.
func LookupIndex(word string, wordlist []string) int {
	index := -1
	for i, w := range wordlist {
		if w == word {
			index = i
			break
		}
	}
	if index == -1 {
		panic("invalid word in mnemonic")
	}
	return index
}

// IntToBinary11 converts an integer in the range [0, 2047] to an 11-bit binary string.
func IntToBinary11(n int) string {
	if n < 0 || n > 2047 {
		panic("Input integer must be in the range 0 to 2047")
	}
	return fmt.Sprintf("%011b", n)
}

// BinaryToInt11 converts an 11-bit binary string to an integer.
func BinaryToInt11(s string) int {
	if len(s) != 11 {
		panic("Input binary string must be 11 characters long")
	}

	for _, c := range s {
		if c != '0' && c != '1' {
			panic("Input string must contain only '0' and '1'")
		}
	}

	n, err := strconv.ParseInt(s, 2, 64)
	if err != nil {
		panic(err)
	}

	if n < 0 || n > 2047 {
		panic("Parsed integer is out of range (0 to 2047)")
	}
	return int(n)
}

// EqualBits Compare two bit arrays for equality
func EqualBits(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// EncodeSeqNo encodes an unsigned 32-bit integer to an 8-character hex string.
func EncodeSeqNo(i uint32) string {
	return fmt.Sprintf("%08x", i)
}

// PRF is the PRF function used in the seed derivation.
func PRF(key, input []byte) []byte {
	kmac256 := NewKMAC256(key, 512/8, []byte("ABELIANPRF"))
	kmac256.Write(input)
	return kmac256.Sum(nil)
}
