package ssplus

import (
	"bytes"
	"encoding/binary"
	"github.com/flynn/noise"
	"testing"
)

func testStates(t *testing.T) (*noise.CipherState, *noise.CipherState) {
	t.Helper()
	cfg := configFor(t, "")
	key := [32]byte{42}
	return noise.UnsafeNewCipherState(cfg.suite, key, 0), noise.UnsafeNewCipherState(cfg.suite, key, 0)
}
func TestV2RecordsTamperingAndRekey(t *testing.T) {
	for _, counter := range []uint64{0, (1 << 17) - 2} {
		tx, rx := testStates(t)
		tx.SetNonce(counter)
		rx.SetNonce(counter)
		cfg := configFor(t, "")
		_ = cfg.SetPadding("off", 0)
		raw := &memoryConn{}
		w := newStream(raw, tx, nil, cfg, cfg.newPaddingAllowance())
		for i := 0; i < 2; i++ {
			if _, err := w.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
		}
		data := bytes.Clone(raw.output.Bytes())
		r := newStream(&memoryConn{input: bytes.NewReader(data)}, nil, rx, cfg, cfg.newPaddingAllowance())
		got := make([]byte, 5)
		for i := 0; i < 2; i++ {
			if n, err := r.Read(got); err != nil || n != 5 || string(got) != "hello" {
				t.Fatal("rekey", counter, n, err)
			}
		}
		if rx.Nonce() != counter+4 {
			t.Fatal("nonce reset")
		}
	}
	for _, offset := range []int{0, 17, 18, 39} {
		tx, rx := testStates(t)
		cfg := configFor(t, "")
		_ = cfg.SetPadding("off", 0)
		raw := &memoryConn{}
		w := newStream(raw, tx, nil, cfg, cfg.newPaddingAllowance())
		_, _ = w.Write([]byte("hello"))
		data := raw.output.Bytes()
		data[offset] ^= 1
		r := newStream(&memoryConn{input: bytes.NewReader(data)}, nil, rx, cfg, cfg.newPaddingAllowance())
		if _, err := r.Read(make([]byte, 32)); err == nil {
			t.Fatal("tamper accepted")
		}
		if _, err := r.Read(make([]byte, 32)); err == nil {
			t.Fatal("error not sticky")
		}
	}
}
func TestV2RecordLengthsAndBudget(t *testing.T) {
	cfg := configFor(t, "")
	_ = cfg.SetPadding("light", 257)
	tx, rx := testStates(t)
	raw := &memoryConn{}
	w := newStream(raw, tx, nil, cfg, cfg.newPaddingAllowance())
	total := 0
	for i := 0; i < 100; i++ {
		before := raw.output.Len()
		_, err := w.Write(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		total += raw.output.Len() - before - 64 - 36
	}
	if total != 257 {
		t.Fatal("padding budget", total)
	}
	tx, rx = testStates(t)
	raw = &memoryConn{}
	w = newStream(raw, tx, nil, cfg, cfg.newPaddingAllowance())
	_, _ = w.Write(make([]byte, 1201))
	before := raw.output.Len()
	_, _ = w.Write(make([]byte, 64))
	if raw.output.Len()-before != 100 {
		t.Fatal("bulk padding continued")
	}
	// Authenticated but invalid record lengths are rejected before allocation.
	for _, n := range []uint16{0, 2, 16385, 65535} {
		tx, rx = testStates(t)
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], n)
		enc, _ := tx.Encrypt(nil, nil, header[:])
		r := newStream(&memoryConn{input: bytes.NewReader(enc)}, nil, rx, cfg, cfg.newPaddingAllowance())
		if _, err := r.Read(make([]byte, 1)); err == nil {
			t.Fatal("invalid length", n)
		}
	}
}
