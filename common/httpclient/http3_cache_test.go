//go:build with_quic

package httpclient

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

func TestHTTP3FailureCacheBoundedAndExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}
		for i := range maxHTTP3BrokenAuthorities * 3 {
			transport.markH3Broken(fmt.Sprintf("host-%d:443", i))
			if len(transport.broken) > maxHTTP3BrokenAuthorities {
				t.Fatal("failure cache grew beyond its limit")
			}
		}
		time.Sleep(6 * time.Minute)
		transport.markH3Broken("new:443")
		if len(transport.broken) != 1 || !transport.h3Broken("new:443") {
			t.Fatal("expired authorities were retained")
		}
	})
}
