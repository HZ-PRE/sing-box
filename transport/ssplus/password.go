package ssplus

import (
	"encoding/base64"
	"fmt"
)

// ResolveKey preserves explicit v1 keys and maps a panel password to a v1 key.
// Passwords must have sufficient entropy (for example a panel-generated UUID).
func ResolveKey(key, password string) (string, error) {
	if key != "" && password != "" {
		return "", fmt.Errorf("ssplus: specify either key or password")
	}
	if password != "" {
		return base64.StdEncoding.EncodeToString(deriveKey([]byte(password), nil, "password")), nil
	}
	if _, err := decodeKey(key); err != nil {
		return "", err
	}
	return key, nil
}
