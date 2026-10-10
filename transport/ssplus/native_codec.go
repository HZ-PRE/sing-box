package ssplus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"sync/atomic"
	"time"
)

// Native UDP v3 has a QUIC 1-RTT short-header shape, not a QUIC transport.
// It uses SS+ authentication/AEAD, with no QUIC Initial, TLS, ACKs, or PFS.
const (
	NativeUDPAddress       = "sp.v1.native-udp.ssplus.arpa"
	nativeMTU              = 1200
	nativeMaxMTU           = 1360
	nativeCompact     byte = 6
	nativeCIDOffset        = 1
	nativePNOffset         = nativeCIDOffset + 16
	nativeHeader           = nativePNOffset + 4
	nativeShortHeader      = 0x43 // Fixed bit, no spin/key phase, four-byte packet number.
	nativeMaxSequence      = uint64(1<<62 - 1)
	nativePaddingMax       = 31
	nativeEnvelope         = 2
	nativeFragment         = nativeMTU - nativeHeader - 16 - 14 - nativeEnvelope - nativePaddingMax
	nativeMaxMessage       = 65507 + 259
	nativeFragmentTTL      = 5 * time.Second
	nativeData        byte = 1
	nativeProbe       byte = 2
	nativeChallenge   byte = 3
	nativeConfirm     byte = 4
	nativeReady       byte = 5
)

var errNativePacket = errors.New("ssplus: invalid native UDP packet")

type nativeBudget struct {
	used  atomic.Int64
	limit int64
}

func (b *nativeBudget) take(n int) bool {
	for {
		old := b.used.Load()
		if old+int64(n) > b.limit {
			return false
		}
		if b.used.CompareAndSwap(old, old+int64(n)) {
			return true
		}
	}
}
func (b *nativeBudget) release(n int) { b.used.Add(-int64(n)) }

// The modulo bitmap is cleared only for newly entered sequence positions.
type nativeReplay struct {
	highest uint64
	bits    [16]uint64
}

func (r *nativeReplay) allows(seq uint64) bool {
	return seq != 0 && (seq > r.highest || (r.highest-seq < 1024 && r.bits[(seq%1024)/64]&(uint64(1)<<(seq%64)) == 0))
}
func (r *nativeReplay) commit(seq uint64) {
	if seq > r.highest {
		if seq-r.highest >= 1024 {
			r.bits = [16]uint64{}
		} else {
			for next := r.highest + 1; next <= seq; next++ {
				r.bits[(next%1024)/64] &^= uint64(1) << (next % 64)
				if next == math.MaxUint64 {
					break
				}
			}
		}
		r.highest = seq
	}
	r.bits[(seq%1024)/64] |= uint64(1) << (seq % 64)
}

type nativeCipher struct {
	id         [16]byte
	aead       cipher.AEAD
	header     cipher.Block
	padding    int
	random     [64]byte
	randomLeft int
	nonce      [12]byte
	mask       [16]byte
	aad        [nativeHeader]byte
	seq        uint64
	replay     nativeReplay
}

// SetNativePadding configures outgoing extra padding before the config is used.
// Receivers accept all valid limits, so the two directions need not match.
func (c *Config) SetNativePadding(limit int) error {
	if limit < 0 || limit > nativePaddingMax {
		return errors.New("ssplus: udp_padding must be between 0 and 31")
	}
	c.nativePadding = limit
	return nil
}

func newNativeCipher(config *Config, seed []byte, direction string) nativeCipher {
	var c nativeCipher
	c.padding = config.nativePadding
	label := "native-udp/v3/" + direction
	// Distinct destination connection IDs for each direction, stable for O(1) lookup.
	copy(c.id[:], deriveKey(seed[16:], seed[:16], label+"/cid"))
	c.aead = config.payloadCipher(seed[16:], seed[:16], label)
	c.header, _ = aes.NewCipher(deriveKey(seed[16:], seed[:16], label+"/header"))
	return c
}

func (c *nativeCipher) seal(dst, plain []byte) ([]byte, error) {
	return c.sealLimit(dst, plain, nativeMTU)
}

// limit caps control replies at the triggering packet's size, including padding.
// Padding is zero before AEAD encryption; its length comes from buffered CSPRNG.
func (c *nativeCipher) sealLimit(dst, plain []byte, limit int) ([]byte, error) {
	base := nativeHeader + nativeEnvelope + len(plain) + c.aead.Overhead()
	limit = min(limit, nativeMaxMTU)
	if c.seq >= nativeMaxSequence || len(plain) == 0 || base > limit {
		return nil, errNativePacket
	}
	padding := 0
	if available := min(c.padding, limit-base); available > 0 {
		if c.randomLeft == 0 {
			if _, err := rand.Read(c.random[:]); err != nil {
				return nil, err
			}
			c.randomLeft = len(c.random)
		}
		c.randomLeft--
		padding = int(c.random[c.randomLeft]) % (available + 1)
	}
	c.seq++
	if cap(dst) < base+padding {
		dst = make([]byte, base+padding)
	}
	dst = dst[:base+padding-c.aead.Overhead()]
	dst[0] = nativeShortHeader
	copy(dst[nativeCIDOffset:nativePNOffset], c.id[:])
	binary.BigEndian.PutUint32(dst[nativePNOffset:], uint32(c.seq))
	binary.BigEndian.PutUint16(dst[nativeHeader:], uint16(len(plain)))
	copy(dst[nativeHeader+nativeEnvelope:], plain)
	clear(dst[nativeHeader+nativeEnvelope+len(plain):])
	binary.BigEndian.PutUint64(c.nonce[4:], c.seq)
	packet := c.aead.Seal(dst[:nativeHeader], c.nonce[:], dst[nativeHeader:], dst[:nativeHeader])
	// QUIC short-header masking layout: sample at PN offset + 4, mask low five
	// bits of the first byte and the four truncated packet-number bytes.
	c.header.Encrypt(c.mask[:], packet[nativeHeader:nativeHeader+16])
	packet[0] ^= c.mask[0] & 0x1f
	for i := 0; i < 4; i++ {
		packet[nativePNOffset+i] ^= c.mask[1+i]
	}
	return packet, nil
}
func (c *nativeCipher) open(dst, packet []byte) ([]byte, uint64, error) {
	if len(packet) < nativeHeader+nativeEnvelope+17 || len(packet) > nativeMaxMTU || packet[0]&0xe0 != 0x40 || string(packet[nativeCIDOffset:nativePNOffset]) != string(c.id[:]) {
		return nil, 0, errNativePacket
	}
	copy(c.aad[:], packet[:nativeHeader])
	c.header.Encrypt(c.mask[:], packet[nativeHeader:nativeHeader+16])
	c.aad[0] ^= c.mask[0] & 0x1f
	if c.aad[0] != nativeShortHeader {
		return nil, 0, errNativePacket
	}
	for i := 0; i < 4; i++ {
		c.aad[nativePNOffset+i] ^= c.mask[1+i]
	}
	seq := nativePacketNumber(binary.BigEndian.Uint32(c.aad[nativePNOffset:]), c.replay.highest)
	if seq > nativeMaxSequence || !c.replay.allows(seq) {
		return nil, 0, errNativePacket
	}
	binary.BigEndian.PutUint64(c.nonce[4:], seq)
	plain, err := c.aead.Open(dst[:0], c.nonce[:], packet[nativeHeader:], c.aad[:])
	if err != nil {
		return nil, 0, errNativePacket
	}
	n := int(binary.BigEndian.Uint16(plain))
	if n == 0 || n > len(plain)-nativeEnvelope || len(plain)-nativeEnvelope-n > nativePaddingMax {
		return nil, 0, errNativePacket
	}
	c.replay.commit(seq)
	return plain[nativeEnvelope : nativeEnvelope+n], seq, nil
}

// RFC 9000 Appendix A.3 reconstruction with a fixed four-byte packet number.
// Full 62-bit numbers feed AEAD nonces and the replay window, including at wrap.
func nativePacketNumber(truncated uint32, highest uint64) uint64 {
	const window = uint64(1 << 32)
	const half = window / 2
	expected := highest + 1
	candidate := (expected & ^(window - 1)) | uint64(truncated)
	if candidate+half <= expected && candidate <= nativeMaxSequence-window {
		return candidate + window
	}
	if candidate > expected+half && candidate >= window {
		return candidate - window
	}
	return candidate
}

type nativePartial struct {
	data    []byte
	mask    uint64
	expires time.Time
}
type nativeAssembler struct {
	partial map[uint64]*nativePartial
	budget  *nativeBudget
	bytes   int
}

func (a *nativeAssembler) expire(now time.Time) {
	for id, p := range a.partial {
		if !now.Before(p.expires) {
			a.drop(id, p)
		}
	}
}
func (a *nativeAssembler) drop(id uint64, p *nativePartial) {
	a.budget.release(len(p.data))
	a.bytes -= len(p.data)
	delete(a.partial, id)
}
func (a *nativeAssembler) clear() {
	for id, p := range a.partial {
		a.drop(id, p)
	}
}

// The returned buffer retains its budget reservation until consumed or dropped.
func (a *nativeAssembler) feed(plain []byte, seq uint64, now time.Time) []byte {
	if len(plain) < 14 || plain[0] != nativeData {
		return nil
	}
	id := binary.BigEndian.Uint64(plain[1:9])
	total := int(binary.BigEndian.Uint32(plain[9:13]))
	index := int(plain[13])
	if total < 4 || total > nativeMaxMessage || index >= 64 || id == 0 || id > math.MaxUint64-uint64(index) || seq != id+uint64(index) {
		return nil
	}
	count := (total + nativeFragment - 1) / nativeFragment
	want := min(nativeFragment, total-index*nativeFragment)
	if index >= count || len(plain) != max(32, 14+want) {
		return nil
	}
	a.expire(now)
	p := a.partial[id]
	if p == nil {
		if len(a.partial) >= 8 || a.bytes+total > 256*1024 || !a.budget.take(total) {
			return nil
		}
		if count == 1 {
			return append([]byte(nil), plain[14:14+total]...)
		}
		if a.partial == nil {
			a.partial = make(map[uint64]*nativePartial)
		}
		p = &nativePartial{data: make([]byte, total), expires: now.Add(nativeFragmentTTL)}
		a.partial[id] = p
		a.bytes += total
	}
	if len(p.data) != total || p.mask&(uint64(1)<<index) != 0 {
		return nil
	}
	copy(p.data[index*nativeFragment:], plain[14:14+want])
	p.mask |= uint64(1) << index
	if p.mask != (uint64(1)<<count)-1 {
		return nil
	}
	delete(a.partial, id)
	a.bytes -= total
	return p.data
}
