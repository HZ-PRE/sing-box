package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestRaceKeepsWinnerBodyAliveAndCancelsLoser(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			time.Sleep(time.Second)
			io.WriteString(w, "complete body")
		}))
		client := server.Client()
		loserDone := make(chan struct{})
		loser := func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			close(loserDone)
			return nil, r.Context().Err()
		}
		request, _ := http.NewRequest("GET", "http://test.invalid", nil)
		response, first, err := raceRoundTrip(request, 250*time.Millisecond, loser, client.Transport.RoundTrip, nil)
		if err != nil || first {
			t.Fatalf("fallback failed: %v", err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(data) != "complete body" {
			t.Fatalf("winner was canceled at headers: %q %v", data, err)
		}
		synctest.Wait()
		select {
		case <-loserDone:
		default:
			t.Fatal("loser not canceled")
		}
	})
}

func TestRaceRequestCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		request, _ := http.NewRequestWithContext(ctx, "GET", "http://test.invalid", nil)
		blocked := func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() }
		done := make(chan error, 1)
		go func() { _, _, err := raceRoundTrip(request, time.Second, blocked, blocked, nil); done <- err }()
		synctest.Sleep(2 * time.Second)
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

func TestDoNotHedgeMutatingRequests(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		r, _ := http.NewRequest(method, "https://test.invalid", nil)
		if requestCanRace(r) {
			t.Fatalf("hedged %s", method)
		}
	}
}

func TestRetryBodyErrorIsReturned(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://test.invalid", nil)
	r.Body = io.NopCloser(strings.NewReader("body"))
	want := errors.New("body no longer available")
	r.GetBody = func() (io.ReadCloser, error) { return nil, want }
	if _, err := cloneRequestForRetry(r); !errors.Is(err, want) {
		t.Fatalf("retry error = %v", err)
	}
}
