package httpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var errHTTP2Fallback = errors.New("server did not negotiate HTTP/2")

// Go 1.27 negotiates ALPN on custom TLS connections exposing ConnectionState.
// One handshake selects H1/H2, without a per-authority fallback cache.
type http2FallbackTransport struct {
	transport   *http.Transport
	h1Transport *http1Transport
}

func newHTTP2FallbackTransport(rawDialer N.Dialer, baseTLSConfig tls.Config, options option.HTTP2Options) (*http2FallbackTransport, error) {
	h1 := newHTTP1Transport(rawDialer, baseTLSConfig)
	transport := h1.transport.Clone()
	transport.ForceAttemptHTTP2 = true
	transport.HTTP2 = &http.HTTP2Config{
		MaxReceiveBufferPerStream:     int(options.StreamReceiveWindow.Value()),
		MaxReceiveBufferPerConnection: int(options.ConnectionReceiveWindow.Value()),
		MaxConcurrentStreams:          options.MaxConcurrentStreams,
		SendPingTimeout:               time.Duration(options.KeepAlivePeriod),
		PingTimeout:                   time.Duration(options.IdleTimeout),
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialTLS(ctx, rawDialer, baseTLSConfig, M.ParseSocksaddr(address), []string{"h2", "http/1.1"}, "")
	}
	return &http2FallbackTransport{transport: transport, h1Transport: h1}, nil
}
func (t *http2FallbackTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if requestRequiresHTTP1(r) {
		return t.h1Transport.RoundTrip(r)
	}
	return t.transport.RoundTrip(r)
}
func (t *http2FallbackTransport) CloseIdleConnections() {
	t.transport.CloseIdleConnections()
	t.h1Transport.CloseIdleConnections()
}
func (t *http2FallbackTransport) Close() error { t.CloseIdleConnections(); return nil }
