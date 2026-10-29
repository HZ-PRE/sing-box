package ssplus

import (
	"bytes"
	"github.com/flynn/noise"
	"testing"
)

func TestV2LongSessionRekeyBothSuites(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		cfg := configFor(t, method)
		_ = cfg.SetPadding("off", 0)
		key := [32]byte{42}
		tx := noise.UnsafeNewCipherState(cfg.suite, key, 0)
		rx := noise.UnsafeNewCipherState(cfg.suite, key, 0)
		raw := &memoryConn{}
		incoming := &memoryConn{}
		w := newStream(raw, tx, nil, cfg, cfg.newPaddingAllowance())
		r := newStream(incoming, nil, rx, cfg, cfg.newPaddingAllowance())
		nt, nr := nativeTestCiphers(t, method)
		var got [1]byte
		for i := 0; i < 65540; i++ {
			p := []byte{byte(i)}
			if _, err := w.Write(p); err != nil {
				t.Fatal(err)
			}
			incoming.input = bytes.NewReader(raw.output.Bytes())
			if n, err := r.Read(got[:]); err != nil || n != 1 || got[0] != p[0] {
				t.Fatal("stream rekey", i, err)
			}
			raw.output.Reset()
			encrypted, err := nt.seal(nil, p)
			if err != nil {
				t.Fatal(err)
			}
			plain, _, err := nr.open(nil, encrypted)
			if err != nil || !bytes.Equal(plain, p) {
				t.Fatal("datagram rekey", i, err)
			}
		}
		if tx.Nonce() != 131080 || rx.Nonce() != 131080 || nt.epoch != 1 || nr.epoch != 1 {
			t.Fatal("incorrect final epoch")
		}
	}
}
