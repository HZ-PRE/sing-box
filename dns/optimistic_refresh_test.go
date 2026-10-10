package dns

import (
	"context"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type delayedRefreshTransport struct {
	adapter.DNSTransport
	calls   atomic.Int32
	release chan struct{}
}

func (t *delayedRefreshTransport) Tag() string { return "refresh" }
func (t *delayedRefreshTransport) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	t.calls.Add(1)
	select {
	case <-t.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(1, 1, 1, 2)}}
	return r, nil
}

func TestOptimisticRefreshCoalescesAndExpires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewClient(ClientOptions{Context: ctx, OptimisticTimeout: 5 * time.Minute, Timeout: time.Second})
	transport := &delayedRefreshTransport{release: make(chan struct{})}
	request := new(dns.Msg)
	request.SetQuestion("cache.example.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(1, 1, 1, 1)}}
	key := dnsCacheKey{Question: request.Question[0], transportTag: transport.Tag()}
	c.cache.AddWithLifetime(key, response, -time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := c.Exchange(ctx, transport, request.Copy(), adapter.DNSQueryOptions{}, nil)
			if err != nil || r.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
				t.Errorf("stale response: %v %v", r, err)
			}
		}()
	}
	wg.Wait()
	close(transport.release)
	deadline := time.Now().Add(time.Second)
	for {
		r, _, stale := c.loadResponse(key.Question, transport)
		if r != nil && !stale && r.Answer[0].(*dns.A).A.String() == "1.1.1.2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh did not update cache")
		}
		time.Sleep(time.Millisecond)
	}
	if transport.calls.Load() != 1 {
		t.Fatalf("duplicate refreshes: %d", transport.calls.Load())
	}
	c.cache.AddWithLifetime(key, response, -6*time.Minute)
	if r, _, _ := c.loadResponse(key.Question, transport); r != nil {
		t.Fatal("stale value exceeded grace period")
	}
}
