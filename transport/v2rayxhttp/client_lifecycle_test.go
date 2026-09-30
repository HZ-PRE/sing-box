package xhttp

import (
	"bytes"
	"context"
	"github.com/sagernet/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type localTestDialer struct{ net.Dialer }

func (d localTestDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, address.String())
}
func (localTestDialer) ListenPacket(ctx context.Context, address M.Socksaddr) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
}

func TestPacketUploadReusesConnectionsAndChecksStatus(t *testing.T) {
	var accepted atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil || string(data) != "packet" {
			t.Error("corrupt upload", err)
		}
		if r.URL.Path == "/reject/0" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte("ack"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	client := createHTTPClient(M.ParseSocksaddr(server.Listener.Addr().String()), localTestDialer{}, &option.V2RayXHTTPBaseOptions{}, nil)
	defer client.Close()
	for i := 0; i < 64; i++ {
		if err := client.PostPacket(context.Background(), server.URL, "session", strconv.Itoa(i), bytes.NewBufferString("packet"), 6); err != nil {
			t.Fatal(err)
		}
	}
	if accepted.Load() != 1 {
		t.Fatalf("64 uploads opened %d connections", accepted.Load())
	}
	if err := client.PostPacket(context.Background(), server.URL, "reject", "0", bytes.NewBufferString("packet"), 6); err == nil {
		t.Fatal("non-200 upload accepted")
	}
}

func TestPacketUploadCancellation(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(strconv.FormatBool(h2), func(t *testing.T) {
			started := make(chan struct{})
			finished := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				close(started)
				<-r.Context().Done()
				close(finished)
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			client := &DefaultDialerClient{options: &option.V2RayXHTTPBaseOptions{}, client: server.Client()}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- client.PostPacket(ctx, server.URL, "session", "0", bytes.NewBufferString("data"), 4) }()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("request did not arrive")
			}
			cancel()
			if awaitResult(t, result) == nil {
				t.Fatal("cancelled request succeeded")
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("server request survived cancellation")
			}
			if client.IsClosed() {
				t.Fatal("cancelling one request invalidated shared transport")
			}
		})
	}
}

func TestStreamCloseCancelsPendingResponse(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(finished)
	}))
	defer server.Close()
	client := createHTTPClient(M.ParseSocksaddr(server.Listener.Addr().String()), localTestDialer{}, &option.V2RayXHTTPBaseOptions{}, nil)
	defer client.Close()
	stream, _, _, err := client.OpenStream(context.Background(), server.URL, "s", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not arrive")
	}
	stream.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel pending response")
	}
}

func TestClientCloseReleasesAllModes(t *testing.T) {
	for _, mode := range []string{"auto", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			var sockets atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					io.Copy(io.Discard, r.Body)
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				if r.Method == http.MethodGet {
					<-r.Context().Done()
				}
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					sockets.Add(1)
				}
				if state == http.StateClosed {
					sockets.Add(-1)
				}
			}
			server.Start()
			defer server.Close()
			for i := 0; i < 10; i++ {
				client, err := NewClient(context.Background(), localTestDialer{}, M.ParseSocksaddr(server.Listener.Addr().String()), option.V2RayXHTTPOptions{Mode: mode}, nil)
				if err != nil {
					t.Fatal(err)
				}
				conn, err := client.DialContext(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				client.Close()
				result := make(chan error, 1)
				go func() { _, err := conn.Read(make([]byte, 1)); result <- err }()
				if awaitResult(t, result) == nil {
					t.Fatal("read survived client close")
				}
				conn.Close()
				if _, err := client.DialContext(context.Background()); err == nil {
					t.Fatal("dial after close succeeded")
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for sockets.Load() != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if sockets.Load() != 0 {
				t.Fatalf("%d sockets survived client shutdown", sockets.Load())
			}
		})
	}
}

type countedMuxConn struct{ closes atomic.Int32 }

func (c *countedMuxConn) IsClosed() bool { return c.closes.Load() > 0 }
func (c *countedMuxConn) Close() error   { c.closes.Add(1); return nil }

func TestExpiredMuxLivesUntilLastRequestCompletes(t *testing.T) {
	m := NewXmuxManager(option.V2RayXHTTPXmuxOptions{}, func() XmuxConn { return &countedMuxConn{} })
	defer m.Close()
	c := m.GetXmuxClient(context.Background())
	c.Retain()
	c.LeftRequests.Store(0)
	replacement := m.GetXmuxClient(context.Background())
	defer replacement.Release()
	if replacement == c {
		t.Fatal("expired client reused")
	}
	c.Release()
	if c.XmuxConn.IsClosed() {
		t.Fatal("in-flight request transport closed")
	}
	c.ReleaseReference()
	if c.XmuxConn.(*countedMuxConn).closes.Load() != 1 {
		t.Fatal("retired transport not closed exactly once")
	}
}

func TestMuxConcurrentAcquireReleaseAndClose(t *testing.T) {
	m := NewXmuxManager(option.V2RayXHTTPXmuxOptions{}, func() XmuxConn { return &countedMuxConn{} })
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c := m.GetXmuxClient(context.Background())
				if c == nil {
					return
				}
				c.Retain()
				c.ReleaseReference()
				c.Release()
			}
		}()
	}
	m.Close()
	wg.Wait()
	if m.GetXmuxClient(context.Background()) != nil {
		t.Fatal("closed manager allocated a transport")
	}
}

func TestMuxConcurrencyCountsSessionsNotPackets(t *testing.T) {
	m := NewXmuxManager(option.V2RayXHTTPXmuxOptions{MaxConcurrency: Xbadoption.Range{From: 2, To: 2}}, func() XmuxConn { return &countedMuxConn{} })
	defer m.Close()
	first := m.GetXmuxClient(context.Background())
	for i := 0; i < 8; i++ {
		first.Retain()
	}
	second := m.GetXmuxClient(context.Background())
	if first != second {
		t.Fatal("packet references inflated session concurrency")
	}
	third := m.GetXmuxClient(context.Background())
	if third == first {
		t.Fatal("session concurrency limit exceeded")
	}
	for i := 0; i < 8; i++ {
		first.ReleaseReference()
	}
	first.Release()
	second.Release()
	third.Release()
	if first.OpenUsage.Load() != 0 || third.OpenUsage.Load() != 0 {
		t.Fatal("unbalanced session leases")
	}
}

func TestHTTP2ClientCloseReleasesSocket(t *testing.T) {
	var sockets atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			sockets.Add(1)
		}
		if state == http.StateClosed {
			sockets.Add(-1)
		}
	}
	server.StartTLS()
	defer server.Close()
	ctx := context.Background()
	tlsConfig, err := boxTLS.NewClient(ctx, logger.NOP(), "localhost", option.OutboundTLSOptions{Enabled: true, Insecure: true, ALPN: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, localTestDialer{}, M.ParseSocksaddr(server.Listener.Addr().String()), option.V2RayXHTTPOptions{Mode: "auto"}, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	conn.Close()
	deadline := time.Now().Add(time.Second)
	for sockets.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sockets.Load() != 0 {
		t.Fatal("HTTP/2 socket survived transport close")
	}
}

func TestHTTP3StreamAndClose(t *testing.T) {
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	tlsServer := certServer.TLS.Clone()
	certServer.Close()
	tlsServer.NextProtos = []string{"h3"}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	server := &http3.Server{TLSConfig: tlsServer, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := make([]byte, 1024)
		if _, err := io.ReadFull(r.Body, payload); err != nil {
			return
		}
		w.Write(payload)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(packetConn) }()
	defer func() { server.Close(); awaitResult(t, serverDone) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tlsConfig, err := boxTLS.NewClient(ctx, logger.NOP(), "localhost", option.OutboundTLSOptions{Enabled: true, Insecure: true, ALPN: []string{"h3"}})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewClient(ctx, localTestDialer{}, M.ParseSocksaddr(packetConn.LocalAddr().String()), option.V2RayXHTTPOptions{Mode: "stream-one"}, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	conn, err := transport.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte{42}, 1024)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, actual); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, actual) {
		t.Fatal("HTTP/3 payload corrupted")
	}
	sockets := transport.(*Client).managers[0].xmuxClients[0].XmuxConn.(*DefaultDialerClient).sockets
	transport.Close()
	sockets.mu.Lock()
	remaining := len(sockets.connections)
	sockets.mu.Unlock()
	if remaining != 0 {
		t.Fatal("HTTP/3 socket survived transport close")
	}
}
