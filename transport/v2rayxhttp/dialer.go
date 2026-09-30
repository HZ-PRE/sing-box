package xhttp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/option"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	IsClosed() bool
	Close() error

	// ctx, url, sessionId, body, uploadOnly
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)

	// ctx, url, sessionId, seqStr, body, contentLength
	PostPacket(context.Context, string, string, string, io.Reader, int64) error
}

// implements xhttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	options      *option.V2RayXHTTPBaseOptions
	client       *http.Client
	closed       atomic.Bool
	uploadClient *http.Client
	sockets      *clientSockets
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *DefaultDialerClient) Close() error {
	c.closed.Store(true)
	if c.sockets != nil {
		c.sockets.close()
	}
	c.client.CloseIdleConnections()
	if closer, ok := c.client.Transport.(io.Closer); ok {
		closer.Close()
	}
	if c.uploadClient != nil {
		c.uploadClient.CloseIdleConnections()
	}
	return nil
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	ctx, cancel := context.WithCancel(ctx)
	type dialResult struct {
		remote, local net.Addr
		err           error
	}
	gotConn := make(chan dialResult, 1)
	var signalOnce sync.Once
	signal := func(result dialResult) { signalOnce.Do(func() { gotConn <- result }) }
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			signal(dialResult{remote: info.Conn.RemoteAddr(), local: info.Conn.LocalAddr()})
		},
	})
	method := "GET" // stream-down
	if body != nil {
		method = c.options.GetNormalizedUplinkHTTPMethod() // stream-up/one
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	req.Header = c.options.GetRequestHeader()
	length := int(c.options.GetNormalizedXPaddingBytes().Rand())
	config := XPaddingConfig{Length: length}
	if c.options.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.options.XPaddingPlacement,
			Key:       c.options.XPaddingKey,
			Header:    c.options.XPaddingHeader,
			RawURL:    url,
		}
		config.Method = PaddingMethod(c.options.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: option.PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    url,
		}
	}
	ApplyXPaddingToRequest(req, config)
	ApplyMetaToRequest(c.options, req, sessionId, "")
	if method == c.options.GetNormalizedUplinkHTTPMethod() && !c.options.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}
	wrc = &WaitReadCloser{ctx: ctx, cancel: cancel, Wait: make(chan struct{})}
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly && ctx.Err() == nil { // stream-down is enough
				c.closed.Store(true)
			}
			signal(dialResult{err: err})
			wrc.Close()
			return
		}
		if resp.StatusCode != 200 || uploadOnly { // stream-up
			if resp.StatusCode == 200 {
				io.Copy(io.Discard, resp.Body)
			}
			resp.Body.Close() // if it is called immediately, the upload will be interrupted also
			wrc.Close()
			return
		}
		wrc.(*WaitReadCloser).Set(resp.Body)
	}()
	select {
	case result := <-gotConn:
		remoteAddr, localAddr, err = result.remote, result.local, result.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		wrc.Close()
	}
	return
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, body io.Reader, contentLength int64) error {
	var encodedData string
	dataPlacement := c.options.GetNormalizedUplinkDataPlacement()
	if dataPlacement != option.PlacementBody {
		data, err := io.ReadAll(body)
		if closer, ok := body.(io.Closer); ok {
			closer.Close()
		}
		if err != nil {
			return err
		}
		encodedData = base64.RawURLEncoding.EncodeToString(data)
		body = nil
		contentLength = 0
	}
	method := c.options.GetNormalizedUplinkHTTPMethod()
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		if closer, ok := body.(io.Closer); ok {
			closer.Close()
		}
		return err
	}
	req.ContentLength = contentLength
	req.Header = c.options.GetRequestHeader()
	if dataPlacement != option.PlacementBody {
		key := c.options.UplinkDataKey
		chunkSize := int(c.options.UplinkChunkSize)
		switch dataPlacement {
		case option.PlacementHeader:
			for i := 0; i < len(encodedData); i += chunkSize {
				end := i + chunkSize
				if end > len(encodedData) {
					end = len(encodedData)
				}
				chunk := encodedData[i:end]
				headerKey := fmt.Sprintf("%s-%d", key, i/chunkSize)
				req.Header.Set(headerKey, chunk)
			}

			req.Header.Set(key+"-Length", fmt.Sprintf("%d", len(encodedData)))
			req.Header.Set(key+"-Upstream", "1")
		case option.PlacementCookie:
			for i := 0; i < len(encodedData); i += chunkSize {
				end := i + chunkSize
				if end > len(encodedData) {
					end = len(encodedData)
				}
				chunk := encodedData[i:end]
				cookieName := fmt.Sprintf("%s_%d", key, i/chunkSize)
				req.AddCookie(&http.Cookie{Name: cookieName, Value: chunk})
			}

			req.AddCookie(&http.Cookie{Name: key + "_upstream", Value: "1"})
		}
	}
	length := int(c.options.GetNormalizedXPaddingBytes().Rand())
	config := XPaddingConfig{Length: length}
	if c.options.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.options.XPaddingPlacement,
			Key:       c.options.XPaddingKey,
			Header:    c.options.XPaddingHeader,
			RawURL:    url,
		}
		config.Method = PaddingMethod(c.options.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: option.PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    url,
		}
	}
	ApplyXPaddingToRequest(req, config)
	ApplyMetaToRequest(c.options, req, sessionId, seqStr)
	client := c.uploadClient
	if client == nil {
		client = c.client
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			c.closed.Store(true)
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected XHTTP upload status: %d", resp.StatusCode)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

type WaitReadCloser struct {
	ctx    context.Context
	cancel context.CancelFunc
	Wait   chan struct{}
	mu     sync.Mutex
	reader io.ReadCloser
	closed bool
	ready  sync.Once
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.mu.Lock()
	if w.closed || w.reader != nil {
		w.mu.Unlock()
		rc.Close()
		return
	}
	w.reader = rc
	w.ready.Do(func() { close(w.Wait) })
	w.mu.Unlock()
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	select {
	case <-w.ctx.Done():
		return 0, w.ctx.Err()
	case <-w.Wait:
	}
	w.mu.Lock()
	reader, closed := w.reader, w.closed
	w.mu.Unlock()
	if closed || reader == nil {
		return 0, io.ErrClosedPipe
	}
	return reader.Read(b)
}

func (w *WaitReadCloser) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	if w.cancel != nil {
		w.cancel()
	}
	reader := w.reader
	w.ready.Do(func() { close(w.Wait) })
	w.mu.Unlock()
	if reader != nil {
		return reader.Close()
	}
	return nil
}

func ApplyMetaToRequest(options *option.V2RayXHTTPBaseOptions, req *http.Request, sessionId string, seqStr string) {
	sessionPlacement := options.GetNormalizedSessionPlacement()
	seqPlacement := options.GetNormalizedSeqPlacement()
	sessionKey := options.GetNormalizedSessionKey()
	seqKey := options.GetNormalizedSeqKey()
	if sessionId != "" {
		switch sessionPlacement {
		case option.PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, sessionId)
		case option.PlacementQuery:
			q := req.URL.Query()
			q.Set(sessionKey, sessionId)
			req.URL.RawQuery = q.Encode()
		case option.PlacementHeader:
			req.Header.Set(sessionKey, sessionId)
		case option.PlacementCookie:
			req.AddCookie(&http.Cookie{Name: sessionKey, Value: sessionId})
		}
	}
	if seqStr != "" {
		switch seqPlacement {
		case option.PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, seqStr)
		case option.PlacementQuery:
			q := req.URL.Query()
			q.Set(seqKey, seqStr)
			req.URL.RawQuery = q.Encode()
		case option.PlacementHeader:
			req.Header.Set(seqKey, seqStr)
		case option.PlacementCookie:
			req.AddCookie(&http.Cookie{Name: seqKey, Value: seqStr})
		}
	}
}

func appendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}
