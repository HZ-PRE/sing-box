package xhttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/buf"
	"github.com/sagernet/sing-box/common/xray/net"
	"github.com/sagernet/sing-box/common/xray/pipe"
	"github.com/sagernet/sing-box/common/xray/signal/done"
	"github.com/sagernet/sing-box/common/xray/uuid"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/http2"
)

type Client struct {
	ctx             context.Context
	cancel          context.CancelFunc
	managers        []*XmuxManager
	options         *option.V2RayXHTTPOptions
	baseRequestURL  url.URL
	baseRequestURL2 url.URL
	getHTTPClient   func() (DialerClient, *XmuxClient)
	getHTTPClient2  func() (DialerClient, *XmuxClient)
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if options.Mode == "" {
		return nil, E.New("mode is not set")
	}
	dest := serverAddr
	baseRequestURL, err := getBaseRequestURL(&options.V2RayXHTTPBaseOptions, dest, tlsConfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	success := false
	defer func() {
		if !success {
			cancel()
		}
	}()
	var xmuxOptions option.V2RayXHTTPXmuxOptions
	if options.Xmux != nil {
		xmuxOptions = *options.Xmux
	}
	xmuxManager := NewXmuxManager(xmuxOptions, func() XmuxConn {
		return createHTTPClient(dest, dialer, &options.V2RayXHTTPBaseOptions, tlsConfig)
	})
	managers := []*XmuxManager{xmuxManager}
	getHTTPClient := func() (DialerClient, *XmuxClient) {
		xmuxClient := xmuxManager.GetXmuxClient(ctx)
		if xmuxClient == nil {
			return nil, nil
		}
		return xmuxClient.XmuxConn.(DialerClient), xmuxClient
	}
	baseRequestURL2 := baseRequestURL
	getHTTPClient2 := getHTTPClient
	if options.Download != nil {
		options2 := options.Download
		dialer2 := dialer
		if options2.Detour != "" {
			var ok bool
			dialer2, ok = service.FromContext[adapter.OutboundManager](ctx).Outbound(options2.Detour)
			if !ok {
				return nil, E.New("outbound detour not found: ", options2.Detour)
			}
		}
		dest2 := options2.ServerOptions.Build()
		var tlsConfig2 tls.Config
		if options2.TLS != nil {
			tlsConfig2, err = tls.NewClient(ctx, logger.NOP(), options2.Server, common.PtrValueOrDefault(options2.TLS))
			if err != nil {
				return nil, err
			}
		}
		baseRequestURL2, err = getBaseRequestURL(&options2.V2RayXHTTPBaseOptions, dest2, tlsConfig2)
		if err != nil {
			return nil, err
		}
		var xmuxOptions2 option.V2RayXHTTPXmuxOptions
		if options2.Xmux != nil {
			xmuxOptions2 = *options2.Xmux
		}
		xmuxManager2 := NewXmuxManager(xmuxOptions2, func() XmuxConn {
			return createHTTPClient(dest2, dialer2, &options2.V2RayXHTTPBaseOptions, tlsConfig2)
		})
		managers = append(managers, xmuxManager2)
		getHTTPClient2 = func() (DialerClient, *XmuxClient) {
			xmuxClient2 := xmuxManager2.GetXmuxClient(ctx)
			if xmuxClient2 == nil {
				return nil, nil
			}
			return xmuxClient2.XmuxConn.(DialerClient), xmuxClient2
		}
	}
	success = true
	return &Client{
		cancel:          cancel,
		managers:        managers,
		ctx:             ctx,
		options:         &options,
		getHTTPClient:   getHTTPClient,
		getHTTPClient2:  getHTTPClient2,
		baseRequestURL:  baseRequestURL,
		baseRequestURL2: baseRequestURL2,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (_ net.Conn, retErr error) {
	if c.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	ctx, cancel := context.WithCancel(ctx)
	stopCoreCancel := context.AfterFunc(c.ctx, cancel)
	defer func() {
		if retErr != nil {
			stopCoreCancel()
			cancel()
		}
	}()
	options := c.options
	mode := c.options.Mode
	sessionId := ""
	if c.options.Mode != "stream-one" {
		sessionIdUuid := uuid.New()
		sessionId = sessionIdUuid.String()
	}
	requestURL := c.baseRequestURL
	requestURL2 := c.baseRequestURL2
	httpClient, xmuxClient := c.getHTTPClient()
	httpClient2, xmuxClient2 := httpClient, xmuxClient
	if options.Download != nil && mode != "stream-one" {
		httpClient2, xmuxClient2 = c.getHTTPClient2()
	}
	if xmuxClient == nil || xmuxClient2 == nil {
		if xmuxClient != nil {
			xmuxClient.Release()
		}
		if xmuxClient2 != nil && xmuxClient2 != xmuxClient {
			xmuxClient2.Release()
		}
		return nil, io.ErrClosedPipe
	}
	reader, writer := io.Pipe()
	conn := splitConn{
		writer: writer,
		onClose: func() {
			stopCoreCancel()
			cancel()
			xmuxClient.Release()
			if xmuxClient2 != xmuxClient {
				xmuxClient2.Release()
			}
		},
	}
	defer func() {
		if retErr != nil {
			reader.Close()
			conn.Close()
		}
	}()
	// Install the close callback only after both ends of the split connection
	// are initialized; cancellation may otherwise race with setup.
	watchConnection := func() { context.AfterFunc(ctx, func() { conn.Close() }) }
	var err error
	if mode == "stream-one" {
		requestURL.Path = options.GetNormalizedPath()
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient.OpenStream(ctx, requestURL.String(), sessionId, reader, false)
		if err != nil { // browser dialer only
			return nil, err
		}
		watchConnection()
		return &conn, nil
	} else { // stream-down
		if xmuxClient2 != nil {
			xmuxClient2.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient2.OpenStream(ctx, requestURL2.String(), sessionId, nil, false)
		if err != nil { // browser dialer only
			return nil, err
		}
	}
	if mode == "stream-up" {
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		_, _, _, err = httpClient.OpenStream(ctx, requestURL.String(), sessionId, reader, true)
		if err != nil { // browser dialer only
			return nil, err
		}
		watchConnection()
		return &conn, nil
	}
	scMaxEachPostBytes := options.GetNormalizedScMaxEachPostBytes()
	scMinPostsIntervalMs := options.GetNormalizedScMinPostsIntervalMs()
	if scMaxEachPostBytes.From <= buf.Size {
		panic("`scMaxEachPostBytes` should be bigger than " + strconv.Itoa(buf.Size))
	}
	maxUploadSize := scMaxEachPostBytes.Rand()
	// WithSizeLimit(0) will still allow single bytes to pass, and a lot of
	// code relies on this behavior. Subtract 1 so that together with
	// uploadWriter wrapper, exact size limits can be enforced
	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - buf.Size))
	reader.Close()
	writer.Close()
	conn.writer = uploadWriter{
		uploadPipeWriter,
		maxUploadSize,
	}
	xmuxClient.Retain()
	watchConnection()
	go func() {
		uploadClient, uploadMux := httpClient, xmuxClient
		uploadSessionLease := false
		releaseUpload := func() {
			if uploadMux == nil {
				return
			}
			if uploadSessionLease {
				uploadMux.Release()
			} else {
				uploadMux.ReleaseReference()
			}
		}
		// Keep an independent lease while the upload loop is alive.
		defer func() {
			releaseUpload()
			uploadPipeReader.Interrupt()
		}()
		var seq int64
		var lastWrite time.Time
		for {
			wroteRequest := done.New()
			ctx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				WroteRequest: func(httptrace.WroteRequestInfo) {
					wroteRequest.Close()
				},
			})
			// this intentionally makes a shallow-copy of the struct so we
			// can reassign Path (potentially concurrently)
			url := requestURL
			seqStr := strconv.FormatInt(seq, 10)
			seq += 1
			if scMinPostsIntervalMs.From > 0 {
				timer := time.NewTimer(time.Duration(scMinPostsIntervalMs.Rand())*time.Millisecond - time.Since(lastWrite))
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
			// by offloading the uploads into a buffered pipe, multiple conn.Write
			// calls get automatically batched together into larger POST requests.
			// without batching, bandwidth is extremely limited.
			chunk, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}
			lastWrite = time.Now()
			if uploadMux.LeftRequests.Add(-1) < 0 ||
				(!uploadMux.UnreusableAt.IsZero() && lastWrite.After(uploadMux.UnreusableAt)) {
				releaseUpload()
				uploadClient, uploadMux = c.getHTTPClient()
				uploadSessionLease = true
				if uploadMux == nil {
					buf.ReleaseMulti(chunk)
					return
				}
				uploadMux.LeftRequests.Add(-1)
			}
			uploadMux.Retain()
			go func(client DialerClient, lease *XmuxClient) {
				defer lease.ReleaseReference()
				err := client.PostPacket(ctx, url.String(), sessionId, seqStr,
					&uploadBody{buffer: buf.MultiBufferContainer{MultiBuffer: chunk}}, int64(chunk.Len()))
				wroteRequest.Close()
				if err != nil {
					cancel()
				}
			}(uploadClient, uploadMux)
			if _, ok := uploadClient.(*DefaultDialerClient); ok {
				select {
				case <-ctx.Done():
				case <-wroteRequest.Wait():
				}

			}
		}
	}()
	return &conn, nil
}

func (c *Client) Close() error {
	c.cancel()
	for _, manager := range c.managers {
		manager.Close()
	}
	return nil
}

func decideHTTPVersion(tlsConfig tls.Config) string {
	if tlsConfig == nil || len(tlsConfig.NextProtos()) == 0 || tlsConfig.NextProtos()[0] == "http/1.1" {
		return "1.1"
	}
	if tlsConfig.NextProtos()[0] == "h3" {
		return "3"
	}
	return "2"
}

func getBaseRequestURL(options *option.V2RayXHTTPBaseOptions, dest M.Socksaddr, tlsConfig tls.Config) (url.URL, error) {
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = options.Host
	if requestURL.Host == "" && tlsConfig != nil {
		requestURL.Host = tlsConfig.ServerName()
	}
	if requestURL.Host == "" {
		requestURL.Host = dest.AddrString()
	}
	requestURL.Path = options.Path
	if err := sHTTP.URLSetPath(&requestURL, options.Path); err != nil {
		return requestURL, E.New(err, "parse path")
	}
	if !strings.HasPrefix(requestURL.Path, "/") {
		requestURL.Path = "/" + requestURL.Path
	}
	requestURL.Path = options.GetNormalizedPath()
	requestURL.RawQuery = options.GetNormalizedQuery()
	return requestURL, nil
}

func createHTTPClient(dest M.Socksaddr, dialer N.Dialer, options *option.V2RayXHTTPBaseOptions, tlsConfig tls.Config) DialerClient {
	httpVersion := decideHTTPVersion(tlsConfig)
	sockets := &clientSockets{}
	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		conn, err := dialer.DialContext(ctxInner, "tcp", dest)
		if err != nil {
			return nil, err
		}
		conn, err = sockets.add(conn)
		if err != nil {
			return nil, err
		}
		if httpVersion != "3" && tlsConfig != nil {
			tlsConn, err := tls.ClientHandshake(ctxInner, conn, tlsConfig)
			if err != nil {
				conn.Close()
			}
			return tlsConn, err
		}
		return conn, nil
	}
	var keepAlivePeriod time.Duration
	if options.Xmux != nil {
		keepAlivePeriod = time.Duration(options.Xmux.HKeepAlivePeriod) * time.Second
	}
	var transport http.RoundTripper
	switch httpVersion {
	case "3":
		if keepAlivePeriod == 0 {
			keepAlivePeriod = net.QuicgoH3KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		quicConfig := &quic.Config{
			MaxIdleTimeout: net.ConnIdleTimeout,
			// these two are defaults of quic-go/http3. the default of quic-go (no
			// http3) is different, so it is hardcoded here for clarity.
			// https://github.com/quic-go/quic-go/blob/b8ea5c798155950fb5bbfdd06cad1939c9355878/http3/client.go#L36-L39
			MaxIncomingStreams: -1,
			KeepAlivePeriod:    keepAlivePeriod,
		}
		transport = &http3.Transport{
			QUICConfig: quicConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udpConn, dErr := dialer.DialContext(ctx, N.NetworkUDP, dest)
				if dErr != nil {
					return nil, dErr
				}
				udpConn, dErr = sockets.add(udpConn)
				if dErr != nil {
					return nil, dErr
				}
				conn, err := qtls.DialEarly(ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), tlsConfig, cfg)
				if err != nil {
					udpConn.Close()
				}
				return conn, err
			},
		}
	case "2":
		if keepAlivePeriod == 0 {
			keepAlivePeriod = net.ChromeH2KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		transport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
	default:
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}
		transport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: net.ConnIdleTimeout,
			// chunked transfer download with KeepAlives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}
	}
	client := &DefaultDialerClient{
		options: options,
		sockets: sockets,
		client: &http.Client{
			Transport: transport,
		},
	}
	if h1, ok := transport.(*http.Transport); ok {
		// Downloads use a dedicated streaming connection. Packet uploads use a
		// bounded, drainable keep-alive pool which consumes every HTTP response.
		upload := h1.Clone()
		upload.DisableKeepAlives = false
		upload.MaxIdleConns = 8
		upload.MaxIdleConnsPerHost = 8
		upload.MaxConnsPerHost = 8
		client.uploadClient = &http.Client{Transport: upload}
	}
	return client
}
