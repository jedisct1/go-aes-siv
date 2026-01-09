package aessiv

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Test vectors from RFC 5297 Appendix A

func TestRFC5297_A1_DeterministicMode(t *testing.T) {
	// A.1. Deterministic Authenticated Encryption Example
	key := mustDecodeHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" +
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	ad := mustDecodeHex("101112131415161718191a1b1c1d1e1f2021222324252627")

	plaintext := mustDecodeHex("112233445566778899aabbccddee")

	expectedCiphertext := mustDecodeHex("85632d07c6e8f37f950acd320a2ecc93" +
		"40c02b9690c4dc04daef7f6afe5c")

	siv, err := New(key)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ciphertext := siv.SealWithAssociatedDataList(nil, [][]byte{ad}, plaintext)
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("Seal() failed\ngot:  %x\nwant: %x", ciphertext, expectedCiphertext)
	}

	decrypted, err := siv.OpenWithAssociatedDataList(nil, [][]byte{ad}, ciphertext)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Open() failed\ngot:  %x\nwant: %x", decrypted, plaintext)
	}
}

func TestRFC5297_A2_NonceBasedMode(t *testing.T) {
	// A.2. Nonce-Based Authenticated Encryption Example
	key := mustDecodeHex("7f7e7d7c7b7a79787776757473727170" +
		"404142434445464748494a4b4c4d4e4f")

	ad1 := mustDecodeHex("00112233445566778899aabbccddeeff" +
		"deaddadadeaddadaffeeddccbbaa9988" +
		"7766554433221100")

	ad2 := mustDecodeHex("102030405060708090a0")

	nonce := mustDecodeHex("09f911029d74e35bd84156c5635688c0")

	plaintext := mustDecodeHex("7468697320697320736f6d6520706c61" +
		"696e7465787420746f20656e63727970" +
		"74207573696e67205349562d414553")

	expectedCiphertext := mustDecodeHex("7bdb6e3b432667eb06f4d14bff2fbd0f" +
		"cb900f2fddbe404326601965c889bf17" +
		"dba77ceb094fa663b7a3f748ba8af829" +
		"ea64ad544a272e9c485b62a3fd5c0d")

	siv, err := New(key)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// In nonce-based mode, the nonce is the last AD before plaintext
	ciphertext := siv.SealWithAssociatedDataList(nil, [][]byte{ad1, ad2, nonce}, plaintext)
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("Seal() failed\ngot:  %x\nwant: %x", ciphertext, expectedCiphertext)
	}

	decrypted, err := siv.OpenWithAssociatedDataList(nil, [][]byte{ad1, ad2, nonce}, ciphertext)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Open() failed\ngot:  %x\nwant: %x", decrypted, plaintext)
	}
}

func TestEmptyPlaintext(t *testing.T) {
	// Test vector from Miscreant: empty AD and empty plaintext
	key := mustDecodeHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" +
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	expectedCiphertext := mustDecodeHex("f2007a5beb2b8900c588a7adf599f172")

	siv, err := New(key)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test with empty plaintext and no AD
	ciphertext := siv.SealWithAssociatedDataList(nil, nil, nil)
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("Seal() failed\ngot:  %x\nwant: %x", ciphertext, expectedCiphertext)
	}

	decrypted, err := siv.OpenWithAssociatedDataList(nil, nil, ciphertext)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %x", decrypted)
	}
}

func TestAuthenticationFailure(t *testing.T) {
	key := mustDecodeHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" +
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	siv, err := New(key)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	plaintext := []byte("hello world")
	ad := []byte("additional data")

	ciphertext := siv.SealWithAssociatedDataList(nil, [][]byte{ad}, plaintext)

	// Modify ciphertext
	modified := make([]byte, len(ciphertext))
	copy(modified, ciphertext)
	modified[0] ^= 0x01

	_, err = siv.OpenWithAssociatedDataList(nil, [][]byte{ad}, modified)
	if err != ErrOpen {
		t.Errorf("expected ErrOpen, got %v", err)
	}

	// Modify AD
	_, err = siv.OpenWithAssociatedDataList(nil, [][]byte{[]byte("wrong data")}, ciphertext)
	if err != ErrOpen {
		t.Errorf("expected ErrOpen, got %v", err)
	}
}

func TestInvalidKeySize(t *testing.T) {
	invalidKeys := [][]byte{
		make([]byte, 16),
		make([]byte, 24),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 65),
	}

	for _, key := range invalidKeys {
		_, err := New(key)
		if err != ErrInvalidKeySize {
			t.Errorf("expected ErrInvalidKeySize for key length %d, got %v", len(key), err)
		}
	}
}

func TestValidKeySizes(t *testing.T) {
	validKeys := [][]byte{
		make([]byte, 32), // AES-128-SIV
		make([]byte, 48), // AES-192-SIV
		make([]byte, 64), // AES-256-SIV
	}

	for _, key := range validKeys {
		_, err := New(key)
		if err != nil {
			t.Errorf("unexpected error for key length %d: %v", len(key), err)
		}
	}
}

func TestCiphertextTooShort(t *testing.T) {
	key := make([]byte, 32)
	siv, _ := New(key)

	_, err := siv.OpenWithAssociatedDataList(nil, nil, make([]byte, 15))
	if err != ErrCiphertextTooShort {
		t.Errorf("expected ErrCiphertextTooShort, got %v", err)
	}
}

func TestSealOpenInterface(t *testing.T) {
	key := mustDecodeHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" +
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	siv, err := New(key)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	plaintext := []byte("test message")
	nonce := []byte("nonce123456")
	ad := []byte("additional data")

	ciphertext := siv.Seal(nil, nonce, plaintext, ad)

	decrypted, err := siv.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Open() failed\ngot:  %x\nwant: %x", decrypted, plaintext)
	}
}

func TestDeterministicProperty(t *testing.T) {
	key := make([]byte, 32)
	siv, _ := New(key)

	plaintext := []byte("same plaintext")
	ad := []byte("same ad")

	ct1 := siv.SealWithAssociatedDataList(nil, [][]byte{ad}, plaintext)
	ct2 := siv.SealWithAssociatedDataList(nil, [][]byte{ad}, plaintext)

	if !bytes.Equal(ct1, ct2) {
		t.Error("AES-SIV should be deterministic with same inputs")
	}
}

func TestCMACSubkeys(t *testing.T) {
	// Test CMAC with known test vectors from RFC 4493
	key := mustDecodeHex("2b7e151628aed2a6abf7158809cf4f3c")

	cmac, err := newCMAC(key)
	if err != nil {
		t.Fatalf("newCMAC() failed: %v", err)
	}

	// K1 and K2 from RFC 4493
	expectedK1 := mustDecodeHex("fbeed618357133667c85e08f7236a8de")
	expectedK2 := mustDecodeHex("f7ddac306ae266ccf90bc11ee46d513b")

	if !bytes.Equal(cmac.k1[:], expectedK1) {
		t.Errorf("K1 mismatch\ngot:  %x\nwant: %x", cmac.k1[:], expectedK1)
	}
	if !bytes.Equal(cmac.k2[:], expectedK2) {
		t.Errorf("K2 mismatch\ngot:  %x\nwant: %x", cmac.k2[:], expectedK2)
	}
}

func TestCMACVectors(t *testing.T) {
	// Test vectors from RFC 4493
	key := mustDecodeHex("2b7e151628aed2a6abf7158809cf4f3c")

	cmac, err := newCMAC(key)
	if err != nil {
		t.Fatalf("newCMAC() failed: %v", err)
	}

	tests := []struct {
		name     string
		message  []byte
		expected string
	}{
		{
			name:     "empty",
			message:  []byte{},
			expected: "bb1d6929e95937287fa37d129b756746",
		},
		{
			name:     "16 bytes",
			message:  mustDecodeHex("6bc1bee22e409f96e93d7e117393172a"),
			expected: "070a16b46b4d4144f79bdd9dd04a287c",
		},
		{
			name:     "40 bytes",
			message:  mustDecodeHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
			expected: "dfa66747de9ae63030ca32611497c827",
		},
		{
			name:     "64 bytes",
			message:  mustDecodeHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
			expected: "51f0bebf7e3b9d92fc49741779363cfe",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := cmac.MAC(tc.message)
			expected := mustDecodeHex(tc.expected)
			if !bytes.Equal(result[:], expected) {
				t.Errorf("CMAC mismatch\ngot:  %x\nwant: %x", result[:], expected)
			}
		})
	}
}

func TestAES256SIV_512BitKey(t *testing.T) {
	// Test vectors generated with Python cryptography library
	key := mustDecodeHex("000102030405060708090a0b0c0d0e0f" +
		"101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f" +
		"303132333435363738393a3b3c3d3e3f")

	tests := []struct {
		name       string
		ad         [][]byte
		plaintext  []byte
		ciphertext string
	}{
		{
			name:       "basic encryption",
			ad:         [][]byte{mustDecodeHex("00112233445566778899aabbccddeeff")},
			plaintext:  mustDecodeHex("48656c6c6f2c20576f726c6421"), // "Hello, World!"
			ciphertext: "8c98e898ce0d870f2e08f524be13b6b61a3818f1c389687f00532f3b44",
		},
		{
			name:       "empty plaintext",
			ad:         [][]byte{mustDecodeHex("aabbccdd")},
			plaintext:  []byte{},
			ciphertext: "119b82ddc6abf6eb630f7f812caeaa84",
		},
		{
			name: "multiple AD",
			ad: [][]byte{
				mustDecodeHex("001122"),
				mustDecodeHex("334455"),
				mustDecodeHex("667788"),
			},
			plaintext:  mustDecodeHex("546865207175696b6b2062726f776e20666f78"),
			ciphertext: "2ade2c1a32d2067cd3b4748d4a14b8409751a0d394f7d98acf80734f481a2423d207df",
		},
	}

	siv, err := New(key)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expected := mustDecodeHex(tc.ciphertext)
			ciphertext := siv.SealWithAssociatedDataList(nil, tc.ad, tc.plaintext)
			if !bytes.Equal(ciphertext, expected) {
				t.Errorf("Seal() failed\ngot:  %x\nwant: %x", ciphertext, expected)
			}

			decrypted, err := siv.OpenWithAssociatedDataList(nil, tc.ad, ciphertext)
			if err != nil {
				t.Fatalf("Open() failed: %v", err)
			}
			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("Open() failed\ngot:  %x\nwant: %x", decrypted, tc.plaintext)
			}
		})
	}
}

func TestAES192SIV_384BitKey(t *testing.T) {
	// Test vector generated with Python cryptography library
	key := mustDecodeHex("000102030405060708090a0b0c0d0e0f" +
		"101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f")

	ad := [][]byte{mustDecodeHex("deadbeef")}
	plaintext := mustDecodeHex("5468697320697320612074657374206d657373616765")
	expectedCiphertext := mustDecodeHex("f0d8bff2680daed2f448e32121e76e27a4dcd520ca3aa101dd5e1a7680179fc44d62b444bc8e")

	siv, err := New(key)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ciphertext := siv.SealWithAssociatedDataList(nil, ad, plaintext)
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("Seal() failed\ngot:  %x\nwant: %x", ciphertext, expectedCiphertext)
	}

	decrypted, err := siv.OpenWithAssociatedDataList(nil, ad, ciphertext)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Open() failed\ngot:  %x\nwant: %x", decrypted, plaintext)
	}
}

func TestLargePlaintext(t *testing.T) {
	// Test with 256 bytes plaintext
	key := mustDecodeHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" +
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	ad := [][]byte{mustDecodeHex("aabbccdd")}

	// 256 bytes: 0x00, 0x01, ..., 0xff
	plaintext := make([]byte, 256)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	expectedCiphertext := mustDecodeHex("200faf44e32d562d8bf229f197f17ba4" +
		"680df4610a1c1fbc52ecad7b26f8a7d7" +
		"49f853450d951c012b29837ae9c30ee0" +
		"e4ebcfcf9498fc1c2ce577d4c0302714" +
		"c57018ccd1ea067ca25cd9fbabb2ea12" +
		"d4a1c112ec5b77e871b1c64e522c3d22" +
		"ead65fc421c33a96de1c96835dba87f8" +
		"436e72dcba73145ce117e7271f1c4772" +
		"cabe5ff3045e0374cfb81890b607fc6c" +
		"a0d5401a95ba5d883725be167aee6eca" +
		"2935046c6c8f23d2ccfe378c49b6ff53" +
		"b1ea0234a7b5adb001218fcf47b8383e" +
		"e7319a6d50a07184e7ab5001366357e2" +
		"073820b6f3e21011651a18d00f1caeab" +
		"e9bb51d6bca9b969ce6ffbbc55699806" +
		"000f192927604c0b26706c55042c1143" +
		"20586dfd982c847cbc5a8c7528eef8d7")

	siv, err := New(key)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ciphertext := siv.SealWithAssociatedDataList(nil, ad, plaintext)
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("Seal() failed\ngot:  %x\nwant: %x", ciphertext, expectedCiphertext)
	}

	decrypted, err := siv.OpenWithAssociatedDataList(nil, ad, ciphertext)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Open() failed\ngot:  %x\nwant: %x", decrypted, plaintext)
	}
}

func TestMultipleADComponents(t *testing.T) {
	key := make([]byte, 32)
	siv, _ := New(key)

	plaintext := []byte("test message")
	ad1 := []byte("first")
	ad2 := []byte("second")
	ad3 := []byte("third")

	ct := siv.SealWithAssociatedDataList(nil, [][]byte{ad1, ad2, ad3}, plaintext)

	pt, err := siv.OpenWithAssociatedDataList(nil, [][]byte{ad1, ad2, ad3}, ct)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext mismatch")
	}

	// Order matters
	_, err = siv.OpenWithAssociatedDataList(nil, [][]byte{ad2, ad1, ad3}, ct)
	if err != ErrOpen {
		t.Error("expected authentication failure when AD order changed")
	}
}

func TestOverhead(t *testing.T) {
	key := make([]byte, 32)
	siv, _ := New(key)

	if siv.Overhead() != TagSize {
		t.Errorf("expected overhead %d, got %d", TagSize, siv.Overhead())
	}
}

func TestNonceSize(t *testing.T) {
	key := make([]byte, 32)
	siv, _ := New(key)

	if siv.NonceSize() != 0 {
		t.Errorf("expected nonce size 0, got %d", siv.NonceSize())
	}
}

func BenchmarkSeal(b *testing.B) {
	key := make([]byte, 32)
	siv, _ := New(key)
	plaintext := make([]byte, 1024)
	ad := make([]byte, 32)

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()

	for b.Loop() {
		siv.SealWithAssociatedDataList(nil, [][]byte{ad}, plaintext)
	}
}

func BenchmarkOpen(b *testing.B) {
	key := make([]byte, 32)
	siv, _ := New(key)
	plaintext := make([]byte, 1024)
	ad := make([]byte, 32)
	ciphertext := siv.SealWithAssociatedDataList(nil, [][]byte{ad}, plaintext)

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()

	for b.Loop() {
		siv.OpenWithAssociatedDataList(nil, [][]byte{ad}, ciphertext)
	}
}
