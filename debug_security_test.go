package box

import (
	"github.com/sagernet/sing-box/option"
	"testing"
)

func TestDebugHTTPRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "192.0.2.1:6060", "localhost:6060"} {
		if err := applyDebugListenOption(option.DebugOptions{Listen: addr}); err == nil {
			t.Fatal("accepted debug listener", addr)
		}
	}
}
