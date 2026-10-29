package ssplus

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

type User struct {
	ID                 uint32
	KeyID              uint32
	Key                string
	PreviousKeyID      uint32
	PreviousKey        string
	PreviousValidUntil int64
	Name               string
	Level              uint32
}
type credential struct {
	User
	key, previous []byte
}

func decodeKey(value string) ([]byte, error) {
	if len(value) != 44 {
		return nil, errors.New("expected a canonical base64-encoded 32-byte random key")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != value {
		return nil, errors.New("expected a canonical base64-encoded 32-byte random key")
	}
	return key, nil
}

// KeyID is a stable public selector, not a secret or an authentication token.
func KeyID(value string) (uint32, error) {
	key, err := decodeKey(value)
	if err != nil {
		return 0, err
	}
	defer clear(key)
	return keyID(key), nil
}
func keyID(key []byte) uint32 {
	sum := sha256.Sum256(key)
	id := binary.BigEndian.Uint32(sum[:4])
	if id == 0 {
		id = 1
	}
	return id
}
func GenerateKey() (string, uint32, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", 0, err
	}
	value := base64.StdEncoding.EncodeToString(key[:])
	clear(key[:])
	id, err := KeyID(value)
	return value, id, err
}
func parseUser(user User) (credential, error) {
	if user.ID == 0 {
		return credential{}, errors.New("ssplus: user_id must be nonzero")
	}
	key, err := decodeKey(user.Key)
	if err != nil {
		return credential{}, fmt.Errorf("ssplus user %d: %w", user.ID, err)
	}
	if user.KeyID == 0 {
		user.KeyID = keyID(key)
	}
	u := credential{User: user, key: key}
	if user.PreviousKey == "" {
		if user.PreviousKeyID != 0 || user.PreviousValidUntil != 0 {
			return credential{}, errors.New("ssplus: previous key fields require previous_key")
		}
		return u, nil
	}
	if user.PreviousValidUntil <= 0 {
		return credential{}, errors.New("ssplus: previous_key requires a positive Unix expiry")
	}
	u.previous, err = decodeKey(user.PreviousKey)
	if err != nil {
		return credential{}, fmt.Errorf("ssplus previous key: %w", err)
	}
	if u.PreviousKeyID == 0 {
		u.PreviousKeyID = keyID(u.previous)
	}
	if u.PreviousKeyID == u.KeyID || user.PreviousKey == user.Key {
		return credential{}, errors.New("ssplus: current and previous keys/IDs must differ")
	}
	return u, nil
}
func ValidateUser(user User) error {
	u, err := parseUser(user)
	clear(u.key)
	clear(u.previous)
	return err
}
func (u *credential) selectKey(id uint32, now time.Time) ([]byte, bool) {
	if id == u.KeyID {
		return u.key, true
	}
	if len(u.previous) > 0 && id == u.PreviousKeyID && now.Unix() < u.PreviousValidUntil {
		return u.previous, true
	}
	return nil, false
}
