// Package aessiv implements AES-SIV (Synthetic Initialization Vector) mode
// as defined in RFC 5297. AES-SIV provides nonce-reuse misuse-resistant
// authenticated encryption.
package aessiv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

const (
	// TagSize is the size of the authentication tag (SIV) in bytes.
	TagSize = blockSize

	// KeySize256 is the key size for AES-SIV with AES-128 (256 bits total).
	KeySize256 = 32

	// KeySize384 is the key size for AES-SIV with AES-192 (384 bits total).
	KeySize384 = 48

	// KeySize512 is the key size for AES-SIV with AES-256 (512 bits total).
	KeySize512 = 64
)

var (
	// ErrInvalidKeySize is returned when the key size is not valid.
	ErrInvalidKeySize = errors.New("aessiv: invalid key size")

	// ErrOpen is returned when decryption fails (authentication error).
	ErrOpen = errors.New("aessiv: message authentication failed")

	// ErrCiphertextTooShort is returned when the ciphertext is shorter than the tag.
	ErrCiphertextTooShort = errors.New("aessiv: ciphertext too short")
)

// AESSIV implements the AES-SIV AEAD construction.
// It implements the cipher.AEAD interface.
type AESSIV struct {
	cmac *cmac
	ctr  cipher.Block
}

var _ cipher.AEAD = (*AESSIV)(nil)

// New creates a new AES-SIV instance with the given key.
// The key must be 32, 48, or 64 bytes long (for AES-128, AES-192, or AES-256).
func New(key []byte) (*AESSIV, error) {
	keyLen := len(key)
	if keyLen != KeySize256 && keyLen != KeySize384 && keyLen != KeySize512 {
		return nil, ErrInvalidKeySize
	}

	halfLen := keyLen / 2

	cmac, err := newCMAC(key[:halfLen])
	if err != nil {
		return nil, err
	}

	ctr, err := aes.NewCipher(key[halfLen:])
	if err != nil {
		return nil, err
	}

	return &AESSIV{
		cmac: cmac,
		ctr:  ctr,
	}, nil
}

// s2v implements the S2V algorithm from RFC 5297.
// It computes a pseudo-random function over the associated data and plaintext.
// The plaintext is always treated as the final string Sn.
func (s *AESSIV) s2v(associatedData [][]byte, plaintext []byte) [blockSize]byte {
	// D = AES-CMAC(K, <zero>)
	var zero [blockSize]byte
	D := s.cmac.MAC(zero[:])

	// Process each associated data element
	for _, ad := range associatedData {
		D = dbl(D)
		adMAC := s.cmac.MAC(ad)
		xorBlock(&D, &adMAC)
	}

	// Process the final string (plaintext)
	if len(plaintext) >= blockSize {
		// T = Sn xorend D
		T := make([]byte, len(plaintext))
		copy(T, plaintext)
		subtle.XORBytes(T[len(T)-blockSize:], T[len(T)-blockSize:], D[:])
		return s.cmac.MAC(T)
	}

	// T = dbl(D) xor pad(Sn)
	D = dbl(D)
	var T [blockSize]byte
	copy(T[:], plaintext)
	T[len(plaintext)] = 0x80
	xorBlock(&T, &D)
	return s.cmac.MAC(T[:])
}

// Seal encrypts and authenticates plaintext with the given nonce and additional data.
// The nonce can be nil for deterministic encryption, or provided as part of additionalData.
// Returns the ciphertext with the authentication tag prepended.
func (s *AESSIV) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	// Build the associated data list
	var ad [][]byte
	if additionalData != nil {
		ad = append(ad, additionalData)
	}
	if nonce != nil {
		ad = append(ad, nonce)
	}

	return s.seal(dst, ad, plaintext)
}

// SealWithAssociatedDataList encrypts plaintext with multiple associated data items.
// This follows the RFC 5297 interface more closely.
func (s *AESSIV) SealWithAssociatedDataList(dst []byte, associatedData [][]byte, plaintext []byte) []byte {
	return s.seal(dst, associatedData, plaintext)
}

func (s *AESSIV) seal(dst []byte, associatedData [][]byte, plaintext []byte) []byte {
	// Compute the SIV
	v := s.s2v(associatedData, plaintext)

	// Prepare output buffer
	ret, out := sliceForAppend(dst, TagSize+len(plaintext))
	copy(out, v[:])

	if len(plaintext) > 0 {
		// Clear bits 31 and 63 for CTR mode
		v[8] &= 0x7F
		v[12] &= 0x7F
		cipher.NewCTR(s.ctr, v[:]).XORKeyStream(out[TagSize:], plaintext)
	}

	return ret
}

// Open decrypts and authenticates ciphertext with the given nonce and additional data.
// Returns the plaintext or an error if authentication fails.
func (s *AESSIV) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	// Build the associated data list
	var ad [][]byte
	if additionalData != nil {
		ad = append(ad, additionalData)
	}
	if nonce != nil {
		ad = append(ad, nonce)
	}

	return s.open(dst, ad, ciphertext)
}

// OpenWithAssociatedDataList decrypts ciphertext with multiple associated data items.
func (s *AESSIV) OpenWithAssociatedDataList(dst []byte, associatedData [][]byte, ciphertext []byte) ([]byte, error) {
	return s.open(dst, associatedData, ciphertext)
}

func (s *AESSIV) open(dst []byte, associatedData [][]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, ErrCiphertextTooShort
	}

	// Extract tag and encrypted data
	var v [blockSize]byte
	copy(v[:], ciphertext[:TagSize])
	encrypted := ciphertext[TagSize:]

	// Prepare output buffer
	ret, plaintext := sliceForAppend(dst, len(encrypted))

	if len(encrypted) > 0 {
		q := v
		q[8] &= 0x7F
		q[12] &= 0x7F
		cipher.NewCTR(s.ctr, q[:]).XORKeyStream(plaintext, encrypted)
	}

	// Verify the tag
	computedV := s.s2v(associatedData, plaintext)

	if subtle.ConstantTimeCompare(v[:], computedV[:]) != 1 {
		clear(plaintext)
		return nil, ErrOpen
	}

	return ret, nil
}

// sliceForAppend extends the input slice to accommodate n more bytes.
// Returns the extended slice and the n-byte slice to write to.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// NonceSize returns 0 as AES-SIV can work without a nonce.
// When using a nonce, it should be passed as part of additional data.
func (s *AESSIV) NonceSize() int {
	return 0
}

// Overhead returns the maximum difference between plaintext and ciphertext lengths.
func (s *AESSIV) Overhead() int {
	return TagSize
}
