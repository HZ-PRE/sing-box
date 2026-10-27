package httpclient

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type lifecycleTransport struct {
	round  func(*http.Request) (*http.Response, error)
	closed atomic.Int32
	idle   atomic.Int32
}

func (t *lifecycleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return t.round(r) }
func (t *lifecycleTransport) CloseIdleConnections()                             { t.idle.Add(1) }
func (t *lifecycleTransport) Close() error                                      { t.closed.Add(1); return nil }

func TestManagedTransportRetirementAndClose(t *testing.T) {
	inner := &lifecycleTransport{round: func(r *http.Request) (*http.Response, error) {
		return &http.Response{Body: io.NopCloser(strings.NewReader("data"))}, nil
	}}
	m := &ManagedTransport{factory: func() (innerTransport, error) { return inner, nil }}
	r, _ := http.NewRequest("GET", "https://example.invalid", nil)
	response, err := m.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	m.Reset()
	if inner.closed.Load() != 0 || inner.idle.Load() != 1 {
		t.Fatal("reset closed active response or retained idle connections")
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if inner.closed.Load() != 1 {
		t.Fatal("EOF did not release retired epoch")
	}
	response.Body.Close()
	response.Body.Close()
	if inner.closed.Load() != 1 {
		t.Fatal("epoch closed multiple times")
	}
	m.close()
	m.Reset()
	if _, err := m.RoundTrip(r); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed transport resurrected: %v", err)
	}
}

func TestManagedTransportCloseCancelsRetiredRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		client := server.Client()
		inner := &lifecycleTransport{round: client.Transport.RoundTrip}
		m := &ManagedTransport{factory: func() (innerTransport, error) { return inner, nil }}
		request, _ := http.NewRequest("GET", "http://test.invalid", nil)
		done := make(chan error, 1)
		go func() { _, err := m.RoundTrip(request); done <- err }()
		synctest.Sleep(time.Second)
		m.Reset()
		m.close()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("request survived manager close: %v", err)
		}
		if inner.closed.Load() != 1 {
			t.Fatal("retired transport not released")
		}
	})
}

func TestManagedTransportConcurrentLifecycle(t *testing.T) {
	m := &ManagedTransport{cheapRebuild: true, factory: func() (innerTransport, error) {
		return &lifecycleTransport{round: func(r *http.Request) (*http.Response, error) {
			return &http.Response{Body: io.NopCloser(strings.NewReader("ok"))}, nil
		}}, nil
	}}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 50 {
				r, _ := http.NewRequest("GET", "http://test.invalid", nil)
				response, err := m.RoundTrip(r)
				if err == nil {
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
				m.Reset()
				m.CloseIdleConnections()
			}
		})
	}
	workers.Wait()
	m.close()
}
