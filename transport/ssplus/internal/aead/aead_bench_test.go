package shadowaead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func benchmarkCipher(method string) cipher.AEAD {
	key := make([]byte, 32)
	if method == "chacha20" {
		c, _ := chacha20poly1305.New(key)
		return c
	}
	block, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(block)
	return c
}

func BenchmarkAEAD(b *testing.B) {
	for _, method := range []string{"aes", "chacha20"} {
		for _, size := range []int{64, 4096, MaxPacketSize} {
			b.Run(fmt.Sprintf("%s/%d", method, size), func(b *testing.B) {
				c := benchmarkCipher(method)
				p := make([]byte, size)
				var wire bytes.Buffer
				wire.Grow(size + 64)
				out := make([]byte, size)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					wire.Reset()
					w := NewWriter(&wire, c, MaxPacketSize)
					if _, err := w.Write(p); err != nil {
						b.Fatal(err)
					}
					r := NewReader(&wire, c, MaxPacketSize)
					if _, err := io.ReadFull(r, out); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
