package shadowaead

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
)

// Independent SS+ v1 wire encoder: the legacy framing is a two-byte big-endian
// length followed by payload, each sealed with consecutive little-endian nonces.
func referenceWire(c cipher.AEAD, frames ...[]byte) []byte {
	var result []byte
	nonce := make([]byte, c.NonceSize())
	for i, frame := range frames {
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], uint16(len(frame)))
		binary.LittleEndian.PutUint64(nonce, uint64(2*i))
		result = c.Seal(result, nonce, header[:], nil)
		binary.LittleEndian.PutUint64(nonce, uint64(2*i+1))
		result = c.Seal(result, nonce, frame, nil)
	}
	return result
}

type fragmentReader struct{ io.Reader }

func (r fragmentReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(len(p), 3)]) }

func TestLegacyWireCompatibility(t *testing.T) {
	for _, method := range []string{"aes", "chacha20"} {
		for _, size := range []int{1, 64, 4096, MaxPacketSize, MaxPacketSize*3 + 17} {
			t.Run(fmt.Sprintf("%s/%d", method, size), func(t *testing.T) {
				c := benchmarkCipher(method)
				p := bytes.Repeat([]byte{0x5a}, size)
				var frames [][]byte
				for rest := p; len(rest) > 0; {
					n := min(len(rest), MaxPacketSize)
					frames = append(frames, rest[:n])
					rest = rest[n:]
				}
				expected := referenceWire(c, frames...)
				var output bytes.Buffer
				writer := NewWriter(&output, c, MaxPacketSize)
				if n, err := writer.Write(p); err != nil || n != size {
					t.Fatalf("write: %d %v", n, err)
				}
				if !bytes.Equal(output.Bytes(), expected) {
					t.Fatal("wire changed")
				}
				for _, readSize := range []int{1, 97, MaxPacketSize + Overhead, 65536} {
					reader := NewReader(fragmentReader{bytes.NewReader(expected)}, c, MaxPacketSize)
					var decoded bytes.Buffer
					buffer := make([]byte, readSize)
					for {
						if n, err := reader.Read(nil); n != 0 || err != nil {
							t.Fatal("empty read consumed input")
						}
						n, err := reader.Read(buffer)
						decoded.Write(buffer[:n])
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					if !bytes.Equal(decoded.Bytes(), p) {
						t.Fatalf("read size %d mismatch", readSize)
					}
				}
			})
		}
	}
}

func TestRejectOversizedAuthenticatedLength(t *testing.T) {
	for _, method := range []string{"aes", "chacha20"} {
		c := benchmarkCipher(method)
		for _, size := range []int{MaxPacketSize + 1, 65535} {
			var length [2]byte
			binary.BigEndian.PutUint16(length[:], uint16(size))
			wire := c.Seal(nil, make([]byte, c.NonceSize()), length[:], nil)
			for _, readSize := range []int{1, 65552} {
				r := NewReader(bytes.NewReader(wire), c, MaxPacketSize)
				for i := 0; i < 2; i++ {
					if n, err := r.Read(make([]byte, readSize)); n != 0 || !errors.Is(err, ErrPacketSize) {
						t.Fatalf("%s/%d: %d %v", method, size, n, err)
					}
				}
			}
		}
	}
}

func TestTruncatedAndTamperedFrames(t *testing.T) {
	for _, method := range []string{"aes", "chacha20"} {
		c := benchmarkCipher(method)
		wire := referenceWire(c, []byte("authenticated payload"))
		for size := 1; size < len(wire); size++ {
			r := NewReader(bytes.NewReader(wire[:size]), c, MaxPacketSize)
			if n, err := r.Read(make([]byte, 64)); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncation %d: %d %v", size, n, err)
			}
		}
		for index := range wire {
			bad := bytes.Clone(wire)
			bad[index] ^= 1
			r := NewReader(bytes.NewReader(bad), c, MaxPacketSize)
			if n, err := r.Read(make([]byte, 64)); n != 0 || err == nil {
				t.Fatalf("tamper %d accepted", index)
			}
		}
	}
}

func TestEmptyFramesAndAllocationBounds(t *testing.T) {
	c := benchmarkCipher("aes")
	r := NewReader(bytes.NewReader(referenceWire(c, nil, nil, []byte("ok"))), c, MaxPacketSize)
	if len(r.buffer) != 0 {
		t.Fatal("reader allocated eagerly")
	}
	p := make([]byte, 32)
	if n, err := r.Read(p); n != 2 || err != nil || string(p[:n]) != "ok" {
		t.Fatalf("empty frames: %d %v", n, err)
	}
	if len(r.buffer) != 0 {
		t.Fatal("direct read allocated a payload copy")
	}
	r = NewReader(bytes.NewReader(referenceWire(c, make([][]byte, maxEmptyPackets)...)), c, MaxPacketSize)
	if _, err := r.Read(p); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
	w := NewWriter(io.Discard, c, MaxPacketSize)
	if len(w.buffer) != 0 {
		t.Fatal("writer allocated eagerly")
	}
	if _, err := w.Write([]byte("small handshake")); err != nil {
		t.Fatal(err)
	}
	if len(w.buffer) > 256 {
		t.Fatal("small write reserved a full frame")
	}
	if _, err := w.Write(make([]byte, 65536)); err != nil {
		t.Fatal(err)
	}
	if len(w.buffer) > MaxPacketSize+34 {
		t.Fatal("unbounded buffer")
	}
}

type shortWriter struct{ calls int }

func (w *shortWriter) Write(p []byte) (int, error) { w.calls++; return len(p) - 1, nil }
func TestShortWriteIsTerminal(t *testing.T) {
	upstream := new(shortWriter)
	w := NewWriter(upstream, benchmarkCipher("aes"), MaxPacketSize)
	for i := 0; i < 2; i++ {
		if n, err := w.Write([]byte("hello")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("%d %v", n, err)
		}
	}
	if upstream.calls != 1 {
		t.Fatal("continued writing after framing failure")
	}
}

func FuzzAuthenticatedFrame(f *testing.F) {
	for _, size := range []uint16{0, 1, 16383, 16384, 65535} {
		f.Add(size, []byte("payload"), false, false)
	}
	f.Fuzz(func(t *testing.T, size uint16, payload []byte, tamper, direct bool) {
		if len(payload) > 65536 {
			return
		}
		c := benchmarkCipher("aes")
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], size)
		nonce := make([]byte, c.NonceSize())
		wire := c.Seal(nil, nonce, header[:], nil)
		nonce[0] = 1
		wire = c.Seal(wire, nonce, payload, nil)
		if tamper {
			wire[len(wire)-1] ^= 1
		}
		r := NewReader(bytes.NewReader(wire), c, MaxPacketSize)
		buffer := make([]byte, 17)
		if direct {
			buffer = make([]byte, 65552)
		}
		for i := 0; i < 4096; i++ {
			n, err := r.Read(buffer)
			if n < 0 || n > len(buffer) {
				t.Fatal("invalid read length")
			}
			if int(size) > MaxPacketSize && !errors.Is(err, ErrPacketSize) {
				t.Fatal("oversized length accepted")
			}
			if err != nil {
				return
			}
		}
		t.Fatal("reader made no bounded progress")
	})
}
