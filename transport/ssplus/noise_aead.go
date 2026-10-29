package ssplus

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
)

// Noise's stock AEAD adapter allocates a nonce slice for every operation.
// Keep the standard Noise nonce encoding in per-CipherState scratch storage.
// Like CipherState itself this adapter requires serialized access; streamConn
// has independent read/write locks and handshake states have one owner.
type noiseAEADFunc struct{ method byte }

func (f noiseAEADFunc) CipherName() string {
	if f.method == 2 {
		return "ChaChaPoly"
	}
	return "AESGCM"
}
func (f noiseAEADFunc) Cipher(key [32]byte) noise.Cipher {
	var a cipher.AEAD
	var err error
	if f.method == 2 {
		a, err = chacha20poly1305.New(key[:])
	} else {
		var b cipher.Block
		b, err = aes.NewCipher(key[:])
		if err == nil {
			a, err = cipher.NewGCM(b)
		}
	}
	// Keys always have 32 bytes; invalid method values cannot enter NewConfig.
	if err != nil {
		panic(err)
	}
	return &noiseAEAD{aead: a, littleEndian: f.method == 2}
}

type noiseAEAD struct {
	aead         cipher.AEAD
	nonce        [12]byte
	littleEndian bool
}

func (c *noiseAEAD) setNonce(n uint64) {
	if c.littleEndian {
		binary.LittleEndian.PutUint64(c.nonce[4:], n)
	} else {
		binary.BigEndian.PutUint64(c.nonce[4:], n)
	}
}
func (c *noiseAEAD) Encrypt(out []byte, n uint64, ad, plain []byte) []byte {
	c.setNonce(n)
	return c.aead.Seal(out, c.nonce[:], plain, ad)
}
func (c *noiseAEAD) Decrypt(out []byte, n uint64, ad, encrypted []byte) ([]byte, error) {
	c.setNonce(n)
	return c.aead.Open(out, c.nonce[:], encrypted, ad)
}
