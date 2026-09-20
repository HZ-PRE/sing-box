package ssplus

import "testing"

func TestPasswordKeyVector(t *testing.T) {
	// Independently calculated HKDF-Extract/Expand using HMAC-SHA256.
	const expected = "eY97KJrQ05FQwti2DS4Md0V+jdSP1fiKYyko3mfU0L4="
	got, err := ResolveKey("", "11111111-1111-4111-8111-111111111111")
	if err != nil || got != expected { t.Fatalf("password derivation: %s %v", got, err) }
	got, err = ResolveKey(expected, "")
	if err != nil || got != expected { t.Fatal("explicit key changed") }
	for _, input := range [][2]string{{"", ""}, {"bad", ""}, {expected, "password"}} {
		if _, err := ResolveKey(input[0], input[1]); err == nil { t.Fatal("invalid credentials accepted") }
	}
}
