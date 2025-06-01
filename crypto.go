package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	AESKeyLen   = 32 // AES-256
	NonceLen    = 12 // GCM recommended nonce size
	GCMTagLen   = 16 // GCM authentication tag size
	MasterKeyLen = 32 // For session token signing/encryption
)

// GenerateRandomBytes generates a slice of cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// DeriveSessionKey uses HKDF-SHA256 to derive a session key.
// `ikm` (Input Keying Material) could be the SSH KEX shared secret.
// `salt` adds entropy and context.
// `info` binds the key to a specific application and purpose.
func DeriveSessionKey(ikm, salt []byte, info string) ([]byte, error) {
	kdf := hkdf.New(sha256.New, ikm, salt, []byte(info))
	key := make([]byte, AESKeyLen)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}
	return key, nil
}

// EncryptGCM encrypts plaintext using AES-256-GCM.
// nonce must be unique for each encryption with the same key.
// aad (Additional Authenticated Data) is authenticated but not encrypted.
func EncryptGCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	if len(nonce) != aesgcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: %d, expected %d", len(nonce), aesgcm.NonceSize())
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nil
}

// DecryptGCM decrypts ciphertext using AES-256-GCM.
func DecryptGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	if len(nonce) != aesgcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: %d, expected %d", len(nonce), aesgcm.NonceSize())
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt GCM: %w", err)
	}
	return plaintext, nil
}

// MasterKeyFromHex converts a hex string to a byte slice for the master key.
func MasterKeyFromHex(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string for master key: %w", err)
	}
	if len(key) != MasterKeyLen {
		return nil, fmt.Errorf("master key must be %d bytes long", MasterKeyLen)
	}
	return key, nil
}
