package shadowaead

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// SS AEAD framing, retained for SS+ v1 wire compatibility.
const (
	MaxPacketSize          = 16*1024 - 1
	PacketLengthBufferSize = 2
	Overhead               = 16
	maxEmptyPackets        = 100
)

var ErrPacketSize = errors.New("ssplus: invalid AEAD packet length")

// Reader and Writer are serialized by their owning streamConn. Keep only the
// framing paths used by SS+ so every incoming length passes the same checks.
type Reader struct {
	upstream      io.Reader
	cipher        cipher.AEAD
	maxPacketSize int
	header        [PacketLengthBufferSize + Overhead]byte
	buffer, nonce []byte
	index, cached int
	err           error
}

func NewReader(upstream io.Reader, cipher cipher.AEAD, maxPacketSize int) *Reader {
	return &Reader{upstream: upstream, cipher: cipher, maxPacketSize: min(maxPacketSize, MaxPacketSize), nonce: make([]byte, cipher.NonceSize())}
}

func (r *Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.cached > 0 {
		n := copy(p, r.buffer[r.index:r.index+r.cached])
		r.index += n
		r.cached -= n
		return n, nil
	}
	n, err := r.readPacket(p)
	if err != nil {
		r.err = err
	}
	return n, err
}

func (r *Reader) readPacket(p []byte) (int, error) {
	for empty := 0; empty < maxEmptyPackets; empty++ {
		if _, err := io.ReadFull(r.upstream, r.header[:]); err != nil {
			return 0, err
		}
		if _, err := r.cipher.Open(r.header[:0], r.nonce, r.header[:], nil); err != nil {
			return 0, err
		}
		increaseNonce(r.nonce)
		length := int(binary.BigEndian.Uint16(r.header[:PacketLengthBufferSize]))
		if length > r.maxPacketSize {
			return 0, ErrPacketSize
		}
		end := length + Overhead
		var data []byte
		if len(p) >= end {
			data = p[:end]
		} else {
			r.buffer = growBuffer(r.buffer, end, r.maxPacketSize+Overhead)
			data = r.buffer[:end]
		}
		if _, err := io.ReadFull(r.upstream, data); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if _, err := r.cipher.Open(data[:0], r.nonce, data, nil); err != nil {
			return 0, err
		}
		increaseNonce(r.nonce)
		// Empty authenticated records carry no application data. Bound consecutive
		// empties so a keyed peer cannot keep one Read busy indefinitely.
		if length == 0 {
			continue
		}
		if len(p) >= end {
			return length, nil
		}
		n := copy(p, data[:length])
		r.index, r.cached = n, length-n
		return n, nil
	}
	return 0, io.ErrNoProgress
}

type Writer struct {
	upstream      io.Writer
	cipher        cipher.AEAD
	maxPacketSize int
	buffer, nonce []byte
	err           error
}

func NewWriter(upstream io.Writer, cipher cipher.AEAD, maxPacketSize int) *Writer {
	return &Writer{upstream: upstream, cipher: cipher, maxPacketSize: min(maxPacketSize, MaxPacketSize), nonce: make([]byte, cipher.NonceSize())}
}

func (w *Writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.maxPacketSize <= 0 {
		w.err = ErrPacketSize
		return 0, w.err
	}
	total := 0
	for len(p) > 0 {
		size := min(len(p), w.maxPacketSize)
		const offset = PacketLengthBufferSize + Overhead
		end := size + offset + Overhead
		w.buffer = growBuffer(w.buffer, end, w.maxPacketSize+offset+Overhead)
		binary.BigEndian.PutUint16(w.buffer[:PacketLengthBufferSize], uint16(size))
		w.cipher.Seal(w.buffer[:0], w.nonce, w.buffer[:PacketLengthBufferSize], nil)
		increaseNonce(w.nonce)
		w.cipher.Seal(w.buffer[offset:offset], w.nonce, p[:size], nil)
		increaseNonce(w.nonce)
		n, err := w.upstream.Write(w.buffer[:end])
		if err == nil && n != end {
			err = io.ErrShortWrite
		}
		if err != nil {
			w.err = err
			return total, err
		}
		total += size
		p = p[size:]
	}
	return total, nil
}

// Allocate for small handshakes first, then grow geometrically up to one frame.
// No global pool retains payload buffers after connections become unreachable.
func growBuffer(buffer []byte, size, limit int) []byte {
	if len(buffer) >= size {
		return buffer
	}
	capacity := max(256, len(buffer))
	for capacity < size {
		capacity *= 2
	}
	return make([]byte, min(capacity, limit))
}

func increaseNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
