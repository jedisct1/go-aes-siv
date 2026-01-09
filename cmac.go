package aessiv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
)

const blockSize = aes.BlockSize

// cmac implements AES-CMAC as defined in RFC 4493 / NIST SP 800-38B.
type cmac struct {
	cipher cipher.Block
	k1, k2 [blockSize]byte
}

// newCMAC creates a new CMAC instance with the given AES key.
func newCMAC(key []byte) (*cmac, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	c := &cmac{cipher: block}
	c.deriveSubkeys()
	return c, nil
}

// deriveSubkeys generates the CMAC subkeys K1 and K2.
func (c *cmac) deriveSubkeys() {
	var zero [blockSize]byte
	var L [blockSize]byte

	c.cipher.Encrypt(L[:], zero[:])

	c.k1 = dbl(L)
	c.k2 = dbl(c.k1)
}

// dbl performs the doubling operation in GF(2^128).
// This is a left shift with conditional XOR of the polynomial 0x87.
func dbl(input [blockSize]byte) [blockSize]byte {
	var output [blockSize]byte

	carry := byte(0)
	for i := blockSize - 1; i >= 0; i-- {
		output[i] = (input[i] << 1) | carry
		carry = input[i] >> 7
	}

	// If MSB was 1, XOR with the irreducible polynomial
	mask := byte(0 - carry) // 0xFF if carry was 1, 0x00 otherwise
	output[blockSize-1] ^= 0x87 & mask

	return output
}

// MAC computes the CMAC of the given message.
func (c *cmac) MAC(message []byte) [blockSize]byte {
	var tag [blockSize]byte
	n := len(message)

	if n == 0 {
		// Empty message: pad a single block
		var padded [blockSize]byte
		padded[0] = 0x80
		xorBlock(&padded, &c.k2)
		c.cipher.Encrypt(tag[:], padded[:])
		return tag
	}

	numBlocks := (n + blockSize - 1) / blockSize
	var state [blockSize]byte

	for i := 0; i < numBlocks-1; i++ {
		subtle.XORBytes(state[:], state[:], message[i*blockSize:(i+1)*blockSize])
		c.cipher.Encrypt(state[:], state[:])
	}

	// Process last block
	lastBlockStart := (numBlocks - 1) * blockSize
	lastBlockLen := n - lastBlockStart
	var lastBlock [blockSize]byte

	if lastBlockLen == blockSize {
		// Complete block: use K1
		copy(lastBlock[:], message[lastBlockStart:])
		xorBlock(&lastBlock, &c.k1)
	} else {
		// Incomplete block: pad and use K2
		copy(lastBlock[:lastBlockLen], message[lastBlockStart:])
		lastBlock[lastBlockLen] = 0x80
		xorBlock(&lastBlock, &c.k2)
	}

	xorBlock(&lastBlock, &state)
	c.cipher.Encrypt(tag[:], lastBlock[:])

	return tag
}

// xorBlock XORs src into dst.
func xorBlock(dst, src *[blockSize]byte) {
	subtle.XORBytes(dst[:], dst[:], src[:])
}
