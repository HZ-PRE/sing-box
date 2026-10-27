package box

import (
	"encoding/json"
	"github.com/sagernet/sing-box/option"
	"net/http/httptest"
	"runtime/pprof"
	"testing"
)

func TestRuntimeReport(t *testing.T) {
	w := httptest.NewRecorder()
	writeRuntimeReport(w, httptest.NewRequest("GET", "http://localhost/debug/report", nil))
	var report struct {
		GoVersion string `json:"go_version"`
		Memory    struct {
			Bytes uint64 `json:"go_committed_bytes"`
		} `json:"memory"`
		Tasks map[string]int64 `json:"tracked_background_tasks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.GoVersion == "" || report.Memory.Bytes == 0 || len(report.Tasks) != 3 {
		t.Fatalf("incomplete report: %s", w.Body.String())
	}
	if pprof.Lookup("goroutineleak") == nil {
		t.Fatal("Go 1.27 leak profiler missing")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("diagnostic report may be cached")
	}
}

func TestDebugHTTPRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "192.0.2.1:6060", "localhost:6060"} {
		if err := applyDebugListenOption(option.DebugOptions{Listen: addr}); err == nil {
			t.Fatal("accepted debug listener", addr)
		}
	}
}
