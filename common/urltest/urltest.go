package urltest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

var _ adapter.URLTestHistoryStorage = (*HistoryStorage)(nil)

type HistoryStorage struct {
	access       sync.RWMutex
	delayHistory map[string]*adapter.URLTestHistory
	updateHook   *observable.Subscriber[struct{}]
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		delayHistory: make(map[string]*adapter.URLTestHistory),
	}
}

func (s *HistoryStorage) SetHook(hook *observable.Subscriber[struct{}]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHook = hook
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return cloneHistory(s.delayHistory[tag])
}

func cloneHistory(history *adapter.URLTestHistory) *adapter.URLTestHistory {
	if history == nil {
		return nil
	}
	copy := *history
	if history.IpInfo != nil {
		ip := *history.IpInfo
		copy.IpInfo = &ip
	}
	return &copy
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.StoreURLTestHistory(tag, &adapter.URLTestHistory{
		Delay: 65535,
		Time:  time.Now(),
	})
	// s.access.Lock()
	// // delete(s.delayHistory, tag)
	// s.access.Unlock()
	// s.notifyUpdated()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) *adapter.URLTestHistory {
	s.access.Lock()
	next := cloneHistory(history)
	if old := s.delayHistory[tag]; old != nil && next != nil && next.IpInfo == nil {
		next.IpInfo = cloneHistory(old).IpInfo
	}
	s.delayHistory[tag] = next
	history = cloneHistory(next)
	s.access.Unlock()
	s.notifyUpdated()
	return history
}

func (s *HistoryStorage) AddOnlyIpToHistory(tag string, history *adapter.URLTestHistory) {
	s.access.Lock()
	next := cloneHistory(history)
	if old := s.delayHistory[tag]; old != nil && next != nil {
		updated := cloneHistory(old)
		updated.IpInfo = next.IpInfo
		s.delayHistory[tag] = updated
	} else {
		s.delayHistory[tag] = next
	}
	s.access.Unlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) notifyUpdated() {
	s.access.RLock()
	updateHook := s.updateHook
	s.access.RUnlock()
	if updateHook != nil {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHook = nil
	return nil
}

func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if detour == nil {
		err = fmt.Errorf("urltest dialer is nil")
		return
	}
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	if hostname == "" || (linkURL.Scheme != "http" && linkURL.Scheme != "https") {
		return 0, fmt.Errorf("urltest requires an HTTP(S) URL with a host")
	}
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	start := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	if N.NeedHandshakeForWrite(instance) {
		start = time.Now()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, link, nil)
	if err != nil {
		return
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	var connectionUsed atomic.Bool
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if connectionUsed.CompareAndSwap(false, true) {
					return instance, nil
				}
				// A server may close keep-alive after the first HEAD. Redial through
				// the same proxy instead of handing http.Transport a closed socket.
				return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: C.TCPTimeout,
	}
	defer client.CloseIdleConnections()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	resp.Body.Close()

	t = delayMilliseconds(time.Since(start))

	if IsUnifiedDelayFromContext(ctx) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		second := time.Now()
		resp, err = client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
		t = delayMilliseconds(time.Since(second))
	}
	return
}

func delayMilliseconds(elapsed time.Duration) uint16 {
	// 0 means untested and 65535 means timeout throughout the node UI.
	return uint16(max(1, min(elapsed.Milliseconds(), 65534)))
}
