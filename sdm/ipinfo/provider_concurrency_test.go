package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestSharedProviderDefaultUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != C.DefaultBrowserAgent {
			t.Errorf("unexpected User-Agent: %q", r.UserAgent())
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ip":"127.0.0.1"}`))
	}))
	defer server.Close()
	provider := &BaseProvider{URL: server.URL}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := provider.fetchData(context.Background(), nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if provider.UserAgent != "" {
		t.Fatal("request mutated shared provider")
	}
}
