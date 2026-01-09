/*
Package aessiv implements AES-SIV (Synthetic Initialization Vector) authenticated
encryption as defined in RFC 5297.

AES-SIV provides nonce-reuse misuse-resistant authenticated encryption. Unlike
standard AEAD modes like AES-GCM, AES-SIV remains secure even if the same nonce
is accidentally reused - it only leaks whether the same plaintext was encrypted
with the same key and associated data.

Key Sizes:
  - 32 bytes (256 bits): AES-128-SIV
  - 48 bytes (384 bits): AES-192-SIV
  - 64 bytes (512 bits): AES-256-SIV

The key is internally split into two halves: the first half for CMAC (authentication)
and the second half for CTR mode (encryption).

Basic Usage:

	key := make([]byte, 32) // 256-bit key for AES-128-SIV
	// Fill key with random bytes...

	siv, err := aessiv.New(key)
	if err != nil {
		panic(err)
	}

	plaintext := []byte("secret message")
	ad := []byte("additional authenticated data")

	// Encrypt (nonce can be nil for deterministic encryption)
	ciphertext := siv.Seal(nil, nil, plaintext, ad)

	// Decrypt
	decrypted, err := siv.Open(nil, nil, ciphertext, ad)
	if err != nil {
		panic("authentication failed")
	}

Multiple Associated Data:

	ad1 := []byte("header")
	ad2 := []byte("context")
	nonce := make([]byte, 16)

	// Encrypt with multiple AD components (nonce is typically the last AD)
	ciphertext := siv.SealWithAssociatedDataList(nil, [][]byte{ad1, ad2, nonce}, plaintext)

	// Decrypt
	decrypted, err := siv.OpenWithAssociatedDataList(nil, [][]byte{ad1, ad2, nonce}, ciphertext)

The ciphertext is 16 bytes (128 bits) longer than the plaintext, consisting of
the authentication tag (SIV) followed by the encrypted plaintext.
*/
package aessiv
