package ssplus

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNativeMaskPaddingAndMTU(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, limit := range []int{0, 1, 15, 31} {
			t.Run(fmt.Sprintf("%s/%d", method, limit), func(t *testing.T) {
				tx, rx := nativeTestCiphers(t, method)
				tx.padding = limit
				for _, size := range []int{1, 32, 128, 14 + nativeFragment} {
					lengths := make(map[int]bool)
					masked := 0
					plain := bytes.Repeat([]byte{0x5a}, size)
					for i := 0; i < 256; i++ {
						tx.policy = nativeTestConfig(t, method).paddingState(nativeTestConfig(t, method).newPaddingAllowance())
						p, err := tx.seal(make([]byte, 0, nativeMTU), plain)
						if err != nil {
							t.Fatal(err)
						}
						base := nativeHeader + nativeEnvelope + 16 + size
						if len(p) < base || len(p) > base+limit || len(p) > nativeMTU {
							t.Fatal("padding/MTU bound", len(p))
						}
						lengths[len(p)] = true
						if p[0]&0xe0 != 0x40 || !bytes.Equal(p[1:17], tx.id[:]) {
							t.Fatal("invalid QUIC short-header shape")
						}
						if binary.BigEndian.Uint32(p[17:21]) != uint32(tx.seq) {
							masked++
						}
						before := bytes.Clone(p)
						decoded, seq, err := rx.open(nil, p)
						if err != nil || seq != tx.seq || !bytes.Equal(decoded, plain) || !bytes.Equal(p, before) {
							t.Fatal("decode mismatch", err)
						}
					}
					if limit > 0 && len(lengths) < 2 {
						t.Fatal("constant packet length")
					}
					if masked < 250 {
						t.Fatal("packet numbers not masked")
					}
				}
			})
		}
	}
}

func TestNativeMaskTamperingAndKeySeparation(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		tx, rx := nativeTestCiphers(t, method)
		p, err := tx.seal(nil, []byte("authenticated payload"))
		if err != nil {
			t.Fatal(err)
		}
		for i := range p {
			bad := bytes.Clone(p)
			bad[i] ^= 1
			if _, _, err := rx.open(nil, bad); err == nil {
				t.Fatalf("tamper accepted at %d", i)
			}
			if rx.replay.highest != 0 {
				t.Fatal("unauthenticated replay window advance")
			}
		}
		if _, _, err := rx.open(nil, p); err != nil {
			t.Fatal(err)
		}
		seed := make([]byte, 48)
		seed[0] = 42
		opposite := newNativeCipher(nativeTestConfig(t, method), seed, "response")
		if _, _, err := opposite.open(nil, p); err == nil {
			t.Fatal("direction reflection accepted")
		}
		seed[47] = 1
		other := newNativeCipher(nativeTestConfig(t, method), seed, "request")
		if _, _, err := other.open(nil, p); err == nil {
			t.Fatal("other session secret accepted")
		}
	}
}

// Build a valid authenticated packet with a malformed inner length/padding.
func nativeMalformedEnvelope(t *testing.T, tx *nativeCipher, body []byte) []byte {
	t.Helper()
	p := make([]byte, nativeHeader, nativeMTU)
	p[0] = nativeShortHeader
	copy(p[nativeCIDOffset:nativePNOffset], tx.id[:])
	binary.BigEndian.PutUint32(p[nativePNOffset:], 1)
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], 1)
	p = tx.aead.Seal(p, nonce[:], body, p)
	var mask [16]byte
	tx.header.Encrypt(mask[:], p[nativeHeader:nativeHeader+16])
	p[0] ^= mask[0] & 0x1f
	for i := 0; i < 4; i++ {
		p[nativePNOffset+i] ^= mask[1+i]
	}
	return p
}

func TestNativeInvalidEnvelopeAndBounds(t *testing.T) {
	for _, body := range [][]byte{{}, {0}, {0, 0}, {0, 0, 1}, {0, 2, 1}, append([]byte{0, 1, 1}, make([]byte, 32)...)} {
		tx, rx := nativeTestCiphers(t, "aes-256-gcm")
		p := nativeMalformedEnvelope(t, &tx, body)
		if _, _, err := rx.open(nil, p); err == nil {
			t.Fatal("invalid envelope accepted")
		}
		if rx.replay.highest != 0 {
			t.Fatal("invalid envelope consumed sequence")
		}
	}
	tx, rx := nativeTestCiphers(t, "aes-256-gcm")
	for _, size := range []int{0, nativeMTU} {
		if _, err := tx.seal(nil, make([]byte, size)); err == nil {
			t.Fatal("invalid size accepted")
		}
	}
	if tx.seq != 0 {
		t.Fatal("invalid write consumed sequence")
	}
	if _, _, err := rx.open(nil, make([]byte, nativeMTU+1)); err == nil {
		t.Fatal("oversize accepted")
	}
	c := nativeTestConfig(t, "aes-256-gcm")
	for _, limit := range []int{-1, 32, 256} {
		if c.SetNativePadding(limit) == nil {
			t.Fatal("invalid padding config")
		}
	}
	for _, limit := range []int{0, 31} {
		if err := c.SetNativePadding(limit); err != nil {
			t.Fatal(err)
		}
		if newNativeCipher(c, make([]byte, 48), "request").padding != limit {
			t.Fatal("padding lost")
		}
	}
}

func TestNativeControlPaddingNoAmplification(t *testing.T) {
	tx, rx := nativeTestCiphers(t, "chacha20-ietf-poly1305")
	minimum := nativeHeader + nativeEnvelope + 16 + 32
	for limit := minimum; limit <= minimum+nativePaddingMax; limit++ {
		for i := 0; i < 128; i++ {
			p, err := tx.sealLimit(nil, make([]byte, 32), limit)
			if err != nil || len(p) > limit {
				t.Fatal("control amplification", err)
			}
			if plain, _, err := rx.open(nil, p); err != nil || len(plain) != 32 {
				t.Fatal("bad control payload", err)
			}
		}
	}
	if _, err := tx.sealLimit(nil, make([]byte, 32), minimum-1); err == nil {
		t.Fatal("too-small limit accepted")
	}
}

func TestNativeRejectsLegacyBootstrap(t *testing.T) {
	for _, version := range []string{"SSPUDP01", "SSPUDP02", "SSPUDP03"} {
		t.Run(version, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			u, v := net.Pipe()
			defer v.Close()
			go func() {
				var bootstrap [56]byte
				copy(bootstrap[:8], version)
				_, _ = b.Write(bootstrap[:])
			}()
			c := &Client{config: nativeTestConfig(t, "aes-256-gcm")}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := c.OpenNative(ctx, a, u); err != errNativePacket {
				t.Fatal("legacy bootstrap accepted", err)
			}
			if _, err := u.Write([]byte{1}); err == nil {
				t.Fatal("UDP connection leaked")
			}
		})
	}
}

func TestNativeCodecReusesBuffers(t *testing.T) {
	tx, rx := nativeTestCiphers(t, "chacha20-ietf-poly1305")
	var wire, plain [nativeMTU]byte
	payload := []byte("small packet")
	allocs := testing.AllocsPerRun(1000, func() {
		p, err := tx.seal(wire[:0], payload)
		if err != nil {
			panic(err)
		}
		if _, _, err := rx.open(plain[:0], p); err != nil {
			panic(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("per-packet codec allocations: %v", allocs)
	}
}
