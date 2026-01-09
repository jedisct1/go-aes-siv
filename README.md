# go-aes-siv

A pure Go implementation of AES-SIV (RFC 5297), a deterministic authenticated encryption scheme. Zero dependencies beyond the standard library.

## What is AES-SIV?

AES-SIV is a deterministic authenticated encryption mode: the same plaintext and associated data always produce the same ciphertext. This is intentional and useful for:

- Key wrapping and key derivation: derive subkeys deterministically from a master key
- Encrypted database indexes: encrypt values while preserving the ability to search for exact matches
- Deduplication: detect duplicate encrypted data without decryption
- Convergent encryption: multiple parties encrypting the same data produce identical ciphertexts

Because encryption is deterministic, AES-SIV is also nonce-reuse misuse-resistant. If you do provide a nonce and accidentally reuse it, the only information leaked is whether two plaintexts are identical. The ciphertexts themselves remain secure.

A nonce can optionally be provided as additional associated data when you want randomized encryption.

## Installation

```
go get github.com/jedisct1/go-aes-siv
```

## Usage

### Deterministic Encryption

```go
key := make([]byte, 32) // Use crypto/rand in real code
siv, _ := aessiv.New(key)

plaintext := []byte("hello world")
additionalData := []byte("context")

// Encrypt deterministically
ciphertext := siv.Seal(nil, nil, plaintext, additionalData)

// Same inputs always produce the same ciphertext
ciphertext2 := siv.Seal(nil, nil, plaintext, additionalData)
// ciphertext == ciphertext2

// Decrypt
decrypted, err := siv.Open(nil, nil, ciphertext, additionalData)
```

### Key Wrapping

AES-SIV is an efficient alternative to AES-KW (RFC 3394) for wrapping cryptographic keys:

```go
kek := make([]byte, 32) // Key Encryption Key
siv, _ := aessiv.New(kek)

keyToWrap := make([]byte, 32) // The key being protected

// Wrap the key
wrappedKey := siv.Seal(nil, nil, keyToWrap, []byte("wrapped-key-v1"))

// Unwrap
unwrappedKey, err := siv.Open(nil, nil, wrappedKey, []byte("wrapped-key-v1"))
```

Why use AES-SIV instead of AES-KW?

- Faster: AES-KW iterates 6×n times over the data. AES-SIV makes two passes regardless of size.
- Arbitrary sizes: AES-KW requires the wrapped key to be a multiple of 8 bytes. AES-SIV handles any size.
- Associated data: AES-SIV can bind the wrapped key to a context (key ID, version, purpose). AES-KW cannot.
- Same security: Both provide authenticated encryption. AES-SIV's determinism is fine for key wrapping since keys should never repeat.

For a 256-bit key, AES-KW performs 48 AES operations. AES-SIV performs around 6 (two CMAC + two CTR blocks), making it roughly 8× faster.

### Key Derivation

AES-SIV can derive subkeys from a master key using the S2V function internally:

```go
masterKey := make([]byte, 32)
siv, _ := aessiv.New(masterKey)

// Derive a key for a specific purpose
subkey := siv.Seal(nil, nil, nil, []byte("encryption-key-for-user-123"))

// The first 16 bytes are the SIV tag, which serves as the derived key
derivedKey := subkey[:16]
```

The S2V component (CMAC-based PRF) makes this deterministic: the same context always produces the same derived key. This is useful for deriving multiple purpose-specific keys from a single master key without storing them.

### With a Nonce

When you need randomized encryption, pass a nonce:

```go
nonce := make([]byte, 16)
rand.Read(nonce)

ciphertext := siv.Seal(nil, nonce, plaintext, additionalData)
decrypted, err := siv.Open(nil, nonce, ciphertext, additionalData)
```

The nonce is simply appended to the associated data internally.

### Multiple Associated Data

RFC 5297 supports multiple associated data inputs:

```go
ad := [][]byte{
    []byte("header1"),
    []byte("header2"),
}

ciphertext := siv.SealWithAssociatedDataList(nil, ad, plaintext)
decrypted, err := siv.OpenWithAssociatedDataList(nil, ad, ciphertext)
```

## API

```go
func New(key []byte) (*AESSIV, error)
```

Creates a new AES-SIV instance. Key must be 32, 48, or 64 bytes (for AES-128, AES-192, or AES-256).

```go
func (s *AESSIV) Seal(dst, nonce, plaintext, additionalData []byte) []byte
func (s *AESSIV) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
```

Encrypt and decrypt with optional nonce and single associated data.

```go
func (s *AESSIV) SealWithAssociatedDataList(dst []byte, ad [][]byte, plaintext []byte) []byte
func (s *AESSIV) OpenWithAssociatedDataList(dst []byte, ad [][]byte, ciphertext []byte) ([]byte, error)
```

Encrypt and decrypt with multiple associated data inputs (RFC 5297 style).

### Constants

```go
const TagSize = 16     // Authentication tag size in bytes
const KeySize256 = 32  // Key size for AES-128-SIV
const KeySize384 = 48  // Key size for AES-192-SIV
const KeySize512 = 64  // Key size for AES-256-SIV
```
