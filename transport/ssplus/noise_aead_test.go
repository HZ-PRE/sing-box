package ssplus

import (
	"bytes"
	"github.com/flynn/noise"
	"testing"
)

func TestV2AEADMatchesUpstreamAtNonceBoundaries(t *testing.T) {
	for _, method := range []byte{1, 2} {
		key := [32]byte{77}
		fast := noiseAEADFunc{method}.Cipher(key)
		standard := noise.CipherAESGCM
		if method == 2 {
			standard = noise.CipherChaChaPoly
		}
		reference := standard.Cipher(key)
		for _, nonce := range []uint64{0, 1, 255, 65535, 65536, 1 << 32, 1 << 63, ^uint64(0)} {
			for _, size := range []int{0, 1, 2, 64, 16384} {
				p := bytes.Repeat([]byte{42}, size)
				ad := []byte("authenticated header")
				actual := fast.Encrypt(nil, nonce, ad, p)
				expected := reference.Encrypt(nil, nonce, ad, p)
				if !bytes.Equal(actual, expected) {
					t.Fatal("nonce encoding mismatch", method, nonce, size)
				}
				decoded, err := fast.Decrypt(nil, nonce, ad, expected)
				if err != nil || !bytes.Equal(decoded, p) {
					t.Fatal("decrypt mismatch", err)
				}
			}
		}
	}
}
