package ssplus

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNativePacketNumberWrapAndReorder(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, boundary := range []uint64{1 << 32, 2 << 32, nativeMaxSequence - 4} {
			tx, rx := nativeTestCiphers(t, method)
			tx.seq, rx.replay.highest = boundary-3, boundary-3
			tx.epoch, rx.epoch = (tx.seq-1)/(1<<16), (tx.seq-1)/(1<<16)
			packets := make([][]byte, 7)
			for i := range packets {
				p, err := tx.seal(nil, []byte("wrap"))
				if err != nil {
					t.Fatal(err)
				}
				packets[i] = p
			}
			for _, index := range []int{0, 4, 2, 1, 3, 6, 5} {
				plain, seq, err := rx.open(nil, packets[index])
				if err != nil || string(plain) != "wrap" || seq != boundary-2+uint64(index) {
					t.Fatalf("reconstruction: seq=%d boundary=%d: %v", seq, boundary, err)
				}
				if _, _, err := rx.open(nil, packets[index]); err == nil {
					t.Fatal("replay across wrap accepted")
				}
			}
		}
		tx, _ := nativeTestCiphers(t, method)
		tx.seq = nativeMaxSequence
		if _, err := tx.seal(nil, []byte("overflow")); err == nil {
			t.Fatal("62-bit packet number limit exceeded")
		}
	}
}

func TestNativeShortHeaderProtectionLayout(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		tx, _ := nativeTestCiphers(t, method)
		tx.seq = 0x100000001
		tx.epoch = (tx.seq - 1) / (1 << 16)
		packet, err := tx.seal(nil, []byte("QUIC-shaped, SS+ encrypted"))
		if err != nil {
			t.Fatal(err)
		}
		// Independently recover the short-header fields at RFC 9001 offsets.
		var mask [16]byte
		tx.header.Encrypt(mask[:], packet[21:37])
		first := packet[0] ^ (mask[0] & 0x1f)
		if first != 0x43 || first&0x18 != 0 || int(first&3)+1 != 4 {
			t.Fatal("short-header bits invalid")
		}
		pn := bytes.Clone(packet[17:21])
		for i := range pn {
			pn[i] ^= mask[i+1]
		}
		if binary.BigEndian.Uint32(pn) != 2 {
			t.Fatal("wrong truncated packet number")
		}
		aad := append([]byte{first}, packet[1:17]...)
		aad = append(aad, pn...)
		var nonce [12]byte
		binary.BigEndian.PutUint64(nonce[4:], tx.seq)
		plain, err := tx.aead.Open(nil, nonce[:], packet[21:], aad)
		if err != nil || string(plain[2:2+binary.BigEndian.Uint16(plain[:2])]) != "QUIC-shaped, SS+ encrypted" {
			t.Fatal("header not authenticated", err)
		}
	}
}

func TestNativeDirectionalConnectionIDs(t *testing.T) {
	c := nativeTestConfig(t, "aes-256-gcm")
	seed := make([]byte, 48)
	request := newNativeCipher(c, seed, "request")
	response := newNativeCipher(c, seed, "response")
	if request.id == response.id || request.id == [16]byte{} {
		t.Fatal("connection IDs not separated")
	}
	seed[47] = 1
	next := newNativeCipher(c, seed, "request")
	if request.id == next.id {
		t.Fatal("session IDs reused")
	}
	packet, err := request.seal(nil, []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := response.open(nil, packet); err == nil {
		t.Fatal("direction reflection accepted")
	}
}

func TestNativeTruncatedNumberNeverReusesNonce(t *testing.T) {
	tx, rx := nativeTestCiphers(t, "aes-256-gcm")
	tx.padding = 0
	first, err := tx.seal(nil, []byte("same payload"))
	if err != nil {
		t.Fatal(err)
	}
	tx.seq = 1 << 32
	tx.epoch, rx.epoch = (tx.seq-1)/(1<<16), (tx.seq-1)/(1<<16)
	second, err := tx.seal(nil, []byte("same payload"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[nativeHeader:], second[nativeHeader:]) {
		t.Fatal("nonce reused after truncation")
	}
	rx.replay.highest = 1 << 32
	if _, _, err := rx.open(nil, first); err == nil {
		t.Fatal("old packet accepted in a later sequence epoch")
	}
	if rx.replay.highest != 1<<32 {
		t.Fatal("old packet advanced replay state")
	}
	if _, seq, err := rx.open(nil, second); err != nil || seq != (1<<32)+1 {
		t.Fatal("current epoch rejected", err)
	}
}

func TestNativePacketNumberReference(t *testing.T) {
	for _, tc := range []struct {
		truncated     uint32
		highest, want uint64
	}{
		{1, 0, 1}, {0, 0xffffffff, 0x100000000},
		{0xfffffffe, 0x100000001, 0xfffffffe},
		{0, 0x17fffffff, 0x200000000},
		{0xffffffff, 0x100000000, 0xffffffff},
		{0xffffffff, nativeMaxSequence - 1, nativeMaxSequence},
	} {
		if got := nativePacketNumber(tc.truncated, tc.highest); got != tc.want {
			t.Fatalf("got %x want %x", got, tc.want)
		}
	}
}
