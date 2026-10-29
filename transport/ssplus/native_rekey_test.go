package ssplus

import (
	"bytes"
	"testing"
)

func TestNativeRekeyReorderAndForgery(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		tx, rx := nativeTestCiphers(t, method)
		tx.seq = 65534
		rx.replay.highest = 65534
		old, _ := tx.seal(nil, []byte("old"))
		boundary, _ := tx.seal(nil, []byte("boundary"))
		next, _ := tx.seal(nil, []byte("next"))
		bad := bytes.Clone(next)
		bad[len(bad)-1] ^= 1
		if _, _, err := rx.open(nil, bad); err == nil || rx.epoch != 0 {
			t.Fatal("forgery advanced epoch")
		}
		for i, p := range [][]byte{next, old, boundary} {
			want := []string{"next", "old", "boundary"}[i]
			plain, _, err := rx.open(nil, p)
			if err != nil || string(plain) != want {
				t.Fatal("epoch/reorder", err)
			}
		}
		if tx.epoch != 1 || rx.epoch != 1 || tx.seq != 65537 {
			t.Fatal("epoch or nonce reset")
		}
		if _, _, err := rx.open(nil, old); err == nil {
			t.Fatal("replay across epoch")
		}
	}
}
