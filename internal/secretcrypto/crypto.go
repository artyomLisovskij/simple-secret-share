package secretcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	Version    = 1
	KDFName    = "PBKDF2-SHA256"
	Iterations = 210000
	SaltSize   = 16
	NonceSize  = 12
	KeySize    = 32
)

var (
	ErrInvalidPayload = errors.New("invalid encrypted payload")
	ErrDecryptFailed  = errors.New("decrypt failed")
)

type Payload struct {
	Version    int    `json:"v"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iter"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ct"`
}

func Encrypt(plaintext []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password is required")
	}

	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(password), salt, Iterations, KeySize, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ct := gcm.Seal(nil, nonce, plaintext, nil)
	payload := Payload{
		Version:    Version,
		KDF:        KDFName,
		Iterations: Iterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	return json.Marshal(payload)
}

func Decrypt(blob []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password is required")
	}

	var payload Payload
	if err := json.Unmarshal(blob, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	if payload.Version != Version || payload.KDF != KDFName || payload.Iterations < 1 {
		return nil, ErrInvalidPayload
	}

	salt, err := base64.StdEncoding.DecodeString(payload.Salt)
	if err != nil || len(salt) != SaltSize {
		return nil, ErrInvalidPayload
	}
	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil || len(nonce) != NonceSize {
		return nil, ErrInvalidPayload
	}
	ct, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil || len(ct) == 0 {
		return nil, ErrInvalidPayload
	}

	key := pbkdf2.Key([]byte(password), salt, payload.Iterations, KeySize, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plain, nil
}

func IsPayload(blob []byte) bool {
	var payload Payload
	if err := json.Unmarshal(blob, &payload); err != nil {
		return false
	}
	return payload.Version == Version &&
		payload.KDF == KDFName &&
		payload.Salt != "" &&
		payload.Nonce != "" &&
		payload.Ciphertext != ""
}
