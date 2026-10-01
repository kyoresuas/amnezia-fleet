// Package awg, логика протокола AmneziaWG без ввода-вывода
package awg

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const KeyLen = 32

type Key [KeyLen]byte

// GeneratePrivateKey создаёт приватный ключ X25519
func GeneratePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("генерация ключа: %w", err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// GenerateSymmetricKey создаёт случайный ключ
func GenerateSymmetricKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("генерация ключа: %w", err)
	}
	return k, nil
}

// PublicKey вычисляет публичный ключ по приватному
func (k Key) PublicKey() Key {
	var pub Key
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&k))
	return pub
}

// IsZero сообщает, что ключ не задан
func (k Key) IsZero() bool {
	return k == Key{}
}

// String возвращает ключ в стандартном base64, как в конфигах WireGuard
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// ParseKey разбирает ключ из base64
func ParseKey(s string) (Key, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("ключ не в base64: %w", err)
	}
	if len(raw) != KeyLen {
		return Key{}, fmt.Errorf("длина ключа %d, ожидается %d", len(raw), KeyLen)
	}
	var k Key
	copy(k[:], raw)
	return k, nil
}

// MarshalText сериализует ключ в base64, пустой ключ, в пустую строку
func (k Key) MarshalText() ([]byte, error) {
	if k.IsZero() {
		return []byte{}, nil
	}
	return []byte(k.String()), nil
}

// UnmarshalText разбирает ключ из base64, пустая строка даёт нулевой ключ
func (k *Key) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*k = Key{}
		return nil
	}
	parsed, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}
