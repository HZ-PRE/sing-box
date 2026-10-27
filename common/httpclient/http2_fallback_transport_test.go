package httpclient

import (
	"context"
	"crypto/tls"
	"github.com/sagernet/sing-box/option"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Intentionally not a *tls.Conn: proxy TLS implementations wrap this interface.
type wrappedTLSConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c *wrappedTLSConn) ConnectionState() tls.ConnectionState { return c.state }
func TestCustomTLSALPNSelectsProtocolWithoutRedial(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "h1", true: "h2"}[h2], func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			transport, err := newHTTP2FallbackTransport(nil, nil, option.HTTP2Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			var dials atomic.Int32
			transport.transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				dialer := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}}
				conn, err := dialer.DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return &wrappedTLSConn{Conn: conn, state: conn.(*tls.Conn).ConnectionState()}, nil
			}
			client := &http.Client{Transport: transport}
			for range 2 {
				response, err := client.Get(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if (response.ProtoMajor == 2) != h2 {
					t.Fatalf("negotiated %s", response.Proto)
				}
			}
			if dials.Load() != 1 {
				t.Fatalf("expected one reused negotiated connection, got %d", dials.Load())
			}
		})
	}
}
