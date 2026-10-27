//go:build with_quic

package httpclient

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type http3Transport struct {
	h3Transport *http3.Transport
}

type http3BrokenEntry struct {
	until   time.Time
	backoff time.Duration
}

const maxHTTP3BrokenAuthorities = 256

type http3FallbackTransport struct {
	h3Transport   *http3.Transport
	h2Fallback    innerTransport
	fallbackDelay time.Duration
	brokenAccess  sync.Mutex
	broken        map[string]http3BrokenEntry
}

func newHTTP3RoundTripper(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	options option.QUICOptions,
) *http3.Transport {
	var handshakeTimeout time.Duration
	if baseTLSConfig != nil {
		handshakeTimeout = baseTLSConfig.HandshakeTimeout()
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     options.StreamReceiveWindow.Value(),
		MaxStreamReceiveWindow:         options.StreamReceiveWindow.Value(),
		InitialConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
		MaxConnectionReceiveWindow:     options.ConnectionReceiveWindow.Value(),
		KeepAlivePeriod:                time.Duration(options.KeepAlivePeriod),
		MaxIdleTimeout:                 time.Duration(options.IdleTimeout),
		DisablePathMTUDiscovery:        options.DisablePathMTUDiscovery,
	}
	if options.InitialPacketSize > 0 {
		quicConfig.InitialPacketSize = uint16(options.InitialPacketSize)
	}
	if options.MaxConcurrentStreams > 0 {
		quicConfig.MaxIncomingStreams = int64(options.MaxConcurrentStreams)
	}
	if handshakeTimeout > 0 {
		quicConfig.HandshakeIdleTimeout = handshakeTimeout
	}
	h3Transport := &http3.Transport{
		TLSClientConfig: &stdTLS.Config{},
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, addr string, tlsConfig *stdTLS.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			if handshakeTimeout > 0 && quicConfig.HandshakeIdleTimeout == 0 {
				quicConfig = quicConfig.Clone()
				quicConfig.HandshakeIdleTimeout = handshakeTimeout
			}
			if baseTLSConfig != nil {
				var err error
				tlsConfig, err = buildSTDTLSConfig(baseTLSConfig, M.ParseSocksaddr(addr), []string{http3.NextProtoH3})
				if err != nil {
					return nil, err
				}
			} else {
				tlsConfig = tlsConfig.Clone()
				tlsConfig.NextProtos = []string{http3.NextProtoH3}
			}
			conn, err := rawDialer.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(addr))
			if err != nil {
				return nil, err
			}
			quicConn, err := quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsConfig, quicConfig)
			if err != nil {
				conn.Close()
				return nil, err
			}
			return quicConn, nil
		},
	}
	return h3Transport
}

func newHTTP3Transport(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	options option.QUICOptions,
) (innerTransport, error) {
	return &http3Transport{
		h3Transport: newHTTP3RoundTripper(rawDialer, baseTLSConfig, options),
	}, nil
}

func newHTTP3FallbackTransport(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	h2Fallback innerTransport,
	options option.QUICOptions,
	fallbackDelay time.Duration,
) (innerTransport, error) {
	return &http3FallbackTransport{
		h3Transport:   newHTTP3RoundTripper(rawDialer, baseTLSConfig, options),
		h2Fallback:    h2Fallback,
		fallbackDelay: fallbackDelay,
		broken:        make(map[string]http3BrokenEntry),
	}, nil
}

func (t *http3Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.h3Transport.RoundTrip(request)
}

func (t *http3Transport) CloseIdleConnections() {
	t.h3Transport.CloseIdleConnections()
}

func (t *http3Transport) Close() error {
	t.CloseIdleConnections()
	return t.h3Transport.Close()
}

func (t *http3FallbackTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || requestRequiresHTTP1(request) {
		return t.h2Fallback.RoundTrip(request)
	}
	return t.roundTripHTTP3(request)
}

func (t *http3FallbackTransport) roundTripHTTP3(request *http.Request) (*http.Response, error) {
	authority := requestAuthority(request)
	if t.h3Broken(authority) {
		return t.h2FallbackRoundTrip(request)
	}
	response, err := t.h3Transport.RoundTripOpt(request, http3.RoundTripOpt{OnlyCachedConn: true})
	if err == nil {
		t.clearH3Broken(authority)
		return response, nil
	}
	if !errors.Is(err, http3.ErrNoCachedConn) {
		t.markH3Broken(authority)
		if !requestCanRace(request) {
			return nil, err
		}
		retry, retryErr := cloneRequestForRetry(request)
		if retryErr != nil {
			return nil, retryErr
		}
		return t.h2FallbackRoundTrip(retry)
	}
	if !requestCanRace(request) {
		response, err = t.h3Transport.RoundTrip(request)
		if err == nil {
			t.clearH3Broken(authority)
			return response, nil
		}
		t.markH3Broken(authority)
		return nil, err
	}
	return t.roundTripHTTP3Race(request, authority)
}

func (t *http3FallbackTransport) roundTripHTTP3Race(request *http.Request, authority string) (*http.Response, error) {
	response, h3, err := raceRoundTrip(request, t.fallbackDelay, t.h3Transport.RoundTrip, t.h2FallbackRoundTrip, func() { t.markH3Broken(authority) })
	if err == nil && h3 {
		t.clearH3Broken(authority)
	}
	return response, err
}
func (t *http3FallbackTransport) h2FallbackRoundTrip(request *http.Request) (*http.Response, error) {
	return t.h2Fallback.RoundTrip(request)
}

func (t *http3FallbackTransport) CloseIdleConnections() {
	t.h3Transport.CloseIdleConnections()
	t.h2Fallback.CloseIdleConnections()
}

func (t *http3FallbackTransport) Close() error {
	t.CloseIdleConnections()
	return t.h3Transport.Close()
}

func (t *http3FallbackTransport) h3Broken(authority string) bool {
	if authority == "" {
		return false
	}
	t.brokenAccess.Lock()
	defer t.brokenAccess.Unlock()
	entry, found := t.broken[authority]
	if !found {
		return false
	}
	if entry.until.IsZero() || !time.Now().Before(entry.until) {
		delete(t.broken, authority)
		return false
	}
	return true
}

func (t *http3FallbackTransport) clearH3Broken(authority string) {
	if authority == "" {
		return
	}
	t.brokenAccess.Lock()
	delete(t.broken, authority)
	t.brokenAccess.Unlock()
}

func (t *http3FallbackTransport) markH3Broken(authority string) {
	if authority == "" {
		return
	}
	t.brokenAccess.Lock()
	defer t.brokenAccess.Unlock()
	now := time.Now()
	if _, exists := t.broken[authority]; !exists && len(t.broken) >= maxHTTP3BrokenAuthorities {
		var oldest string
		var oldestUntil time.Time
		for key, value := range t.broken {
			if !now.Before(value.until) {
				delete(t.broken, key)
				continue
			}
			if oldestUntil.IsZero() || value.until.Before(oldestUntil) {
				oldest, oldestUntil = key, value.until
			}
		}
		if len(t.broken) >= maxHTTP3BrokenAuthorities {
			delete(t.broken, oldest)
		}
	}
	entry := t.broken[authority]
	if entry.backoff == 0 {
		entry.backoff = 5 * time.Minute
	} else {
		entry.backoff *= 2
		if entry.backoff > 48*time.Hour {
			entry.backoff = 48 * time.Hour
		}
	}
	entry.until = now.Add(entry.backoff)
	t.broken[authority] = entry
}
