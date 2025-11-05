package aip11

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
)

// Errors

var (
	ErrEntropySeedGenFailed      = errors.New("failed to generate entropy seed after 3 attempts")
	ErrWordlistLengthInvalid     = errors.New("wordlist must contain exactly 2048 words")
	ErrEntropySeedInvalid        = errors.New("entropy seed must be exactly 256 bits (32 bytes)")
	ErrMnemonicInvalid           = errors.New("mnemonic must contain exactly 24 words")
	ErrChecksumMismatch          = errors.New("checksum does not match")
	ErrMasterSeedInvalid         = errors.New("master seed must be exactly 64 bytes")
	ErrPublicRandRootSeedInvalid = errors.New("public random root seed must be exactly 64 bytes")
	ErrBitLengthInvalid          = errors.New("bit length must be a multiple of 8")
	ErrWordNotFound              = errors.New("word not found in wordlist")
	ErrBinaryStringLength        = errors.New("input binary string must be exactly 11 characters long")
	ErrBinaryStringInvalidChar   = errors.New("input string must contain only '0' and '1'")
	ErrParsedIntegerOutOfRange   = errors.New("parsed integer is out of range (0 to 2047)")
)

// Main functions

// SampleEntropySeed generates a random 256-bit(32 bytes) entropy seed.
func SampleEntropySeed() ([]byte, error) {
	for i := 0; i < 3; i++ {
		entropySeed := make([]byte, 32)
		if _, err := rand.Read(entropySeed); err == nil {
			return entropySeed, nil
		}
	}

	return nil, ErrEntropySeedGenFailed
}

// EntropySeedToMnemonic converts a 256-bit entropy seed to a mnemonic.
func EntropySeedToMnemonic(entropySeed []byte, wordlist []string) ([]string, error) {
	if len(wordlist) != 2048 {
		return nil, ErrWordlistLengthInvalid
	}

	entropyBitLength := len(entropySeed) * 8
	if entropyBitLength != 256 {
		return nil, ErrEntropySeedInvalid
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
		index, err := BinaryToInt11(chunk)
		if err != nil {
			return nil, err
		}
		words = append(words, wordlist[index])
	}

	return words, nil
}

// MnemonicToEntropySeed converts a mnemonic to a 256-bit entropy seed.
func MnemonicToEntropySeed(mnemonic []string, wordlist []string) ([]byte, error) {
	if len(wordlist) != 2048 {
		return nil, ErrWordlistLengthInvalid
	}

	if len(mnemonic) != 24 {
		return nil, ErrMnemonicInvalid
	}

	bits := []bool{}
	for _, word := range mnemonic {
		index, err := LookupIndex(word, wordlist)
		if err != nil {
			return nil, err
		}
		binaryString, err := IntToBinary11(index)
		if err != nil {
			return nil, err
		}
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

	entropySeedBytes, err := BitsToBytes(entropySeedBits)
	if err != nil {
		return nil, err
	}
	expectedChecksum := CalculateChecksum(entropySeedBytes, checksumLength)
	if !EqualBits(checksumBits, expectedChecksum) {
		return nil, ErrChecksumMismatch
	}

	return entropySeedBytes, nil
}

// EntropySeedToMasterSeed derives the master seed from the entropy seed.
func EntropySeedToMasterSeed(entropySeed []byte, customizationContext []byte) ([]byte, error) {
	if len(entropySeed) != 32 {
		return nil, ErrEntropySeedInvalid
	}
	return PRF(entropySeed, append([]byte("AccountMasterSeed"), customizationContext...)), nil
}

// MasterSeedToAccountRootSeeds derives the account root seeds from the master seed.
func MasterSeedToAccountRootSeeds(masterSeed []byte) ([][]byte, error) {
	if len(masterSeed) != 64 {
		return nil, ErrMasterSeedInvalid
	}

	coinSpKeyRootSeed := PRF(masterSeed, []byte("CoinSpendKeyRootSeed"))
	coinSnKeyRootSeed := PRF(masterSeed, []byte("CoinSerialNumberKeyRootSeed"))
	coinDetectorRootKey := PRF(masterSeed, []byte("CoinDetectorRootKey"))
	coinVKRootSeed := PRF(masterSeed, []byte("CoinValueKeyRootSeed"))
	coinVKeyRootSeedAut := PRF(masterSeed, []byte("CoinValueKeyRootSeedAut"))

	return [][]byte{
		coinSpKeyRootSeed,
		coinSnKeyRootSeed,
		coinDetectorRootKey,
		coinVKRootSeed,
		coinVKeyRootSeedAut,
	}, nil
}

// MasterSeedToAccountPublicRandRootSeed derives the public rand root seed from the master seed.
func MasterSeedToAccountPublicRandRootSeed(masterSeed []byte) ([]byte, error) {
	if len(masterSeed) != 64 {
		return nil, ErrMasterSeedInvalid
	}
	return PRF(masterSeed, []byte("PublicRandRootSeed")), nil
}

// DerivePublicRand derives the public rand from the public rand root seed.
func DerivePublicRand(publicRandRootSeed []byte, index uint32) ([]byte, error) {
	if len(publicRandRootSeed) != 64 {
		return nil, ErrPublicRandRootSeedInvalid
	}
	seqNo := EncodeSeqNo(index)
	return PRF(publicRandRootSeed, []byte(seqNo)), nil
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
func BitsToBytes(bits []bool) ([]byte, error) {
	if len(bits)%8 != 0 {
		return nil, ErrBitLengthInvalid
	}
	bytes := make([]byte, len(bits)/8)
	for i := 0; i < len(bytes); i++ {
		for j := 0; j < 8; j++ {
			if bits[i*8+j] {
				bytes[i] |= 1 << uint(7-j)
			}
		}
	}
	return bytes, nil
}

// LookupIndex looks up the index of a word in the wordlist.
func LookupIndex(word string, wordlist []string) (int, error) {
	index := -1
	for i, w := range wordlist {
		if w == word {
			index = i
			break
		}
	}
	if index == -1 {
		return -1, ErrWordNotFound
	}
	return index, nil
}

// IntToBinary11 converts an integer in the range [0, 2047] to an 11-bit binary string.
func IntToBinary11(n int) (string, error) {
	if n < 0 || n > 2047 {
		return "", ErrParsedIntegerOutOfRange
	}
	return fmt.Sprintf("%011b", n), nil
}

// BinaryToInt11 converts an 11-bit binary string to an integer.
func BinaryToInt11(s string) (int, error) {
	if len(s) != 11 {
		return -1, ErrBinaryStringLength
	}

	for _, c := range s {
		if c != '0' && c != '1' {
			return -1, ErrBinaryStringInvalidChar
		}
	}

	n, err := strconv.ParseInt(s, 2, 64)
	if err != nil {
		return -1, err
	}

	if n < 0 || n > 2047 {
		return -1, ErrParsedIntegerOutOfRange
	}
	return int(n), nil
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
