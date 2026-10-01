// Package secret
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

type Box struct {
	aead cipher.AEAD
}

// NewBox создаёт Box из мастер-ключа в base64 (32 байта)
func NewBox(masterKeyB64 string) (*Box, error) {
	key, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		return nil, fmt.Errorf("мастер-ключ не в base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("мастер-ключ должен быть 32 байта, получено %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal шифрует данные, nonce кладётся в начало результата
func (b *Box) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, nil), nil
}

// Open расшифровывает данные, зашифрованные Seal
func (b *Box) Open(sealed []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("шифротекст короче nonce")
	}
	return b.aead.Open(nil, sealed[:n], sealed[n:], nil)
}

// NewToken создаёт случайный токен доступа и его хеш для хранения в базе
func NewToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = hex.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken хеширует токен
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// EqualToken сравнивает токены за постоянное время
func EqualToken(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
