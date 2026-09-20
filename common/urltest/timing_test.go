package urltest

import (
	"context"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type timingDialer struct {
	N.Dialer
	dialDelay, handshakeDelay time.Duration
	early                     bool
}
type earlyMarker struct{ net.Conn }

func (*earlyMarker) NeedHandshake() bool { return true }
func (d timingDialer) DialContext(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
	timer := time.NewTimer(d.dialDelay + d.handshakeDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, target.String())
	if err == nil && d.early {
		return &earlyMarker{conn}, nil
	}
	return conn, err
}

// Isolates URLTest's timing boundary with a local HTTP endpoint. Delays are
// deliberately injected, not measurements of a production proxy or Internet RTT.
func TestURLTestTimingBoundary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	for _, tc := range []struct {
		name      string
		early     bool
		handshake time.Duration
	}{{"SS-style-early", true, 0}, {"SSPlus-style-eager", false, 250 * time.Millisecond}} {
		start := time.Now()
		delay, err := URLTest(context.Background(), server.URL, timingDialer{dialDelay: 250 * time.Millisecond, handshakeDelay: tc.handshake, early: tc.early})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: simulated TCP connect=250ms, simulated obfs handshake=%s, displayed=%dms, actual elapsed=%s", tc.name, tc.handshake, delay, time.Since(start))
	}
}
