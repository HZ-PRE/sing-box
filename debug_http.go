package box

import (
	stdjson "encoding/json/v2"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/diagnostics"
	"github.com/sagernet/sing-box/common/memorystats"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/go-chi/chi/v5"
)

var debugHTTPServer *http.Server
var debugHTTPAccess sync.Mutex

func applyDebugListenOption(options option.DebugOptions) error {
	debugHTTPAccess.Lock()
	defer debugHTTPAccess.Unlock()
	if options.Listen != "" {
		host, _, err := net.SplitHostPort(options.Listen)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			return E.New("debug HTTP must listen on a numeric loopback address")
		}
	}
	if debugHTTPServer != nil {
		debugHTTPServer.Close()
		debugHTTPServer = nil
	}
	if options.Listen == "" {
		return nil
	}
	r := chi.NewMux()
	r.Route("/debug", func(r chi.Router) {
		r.Get("/gc", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
			go debug.FreeOSMemory()
		})
		r.Get("/memory", writeRuntimeReport)
		r.Get("/report", writeRuntimeReport)
		r.Route("/pprof", func(r chi.Router) {
			r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
				if !strings.HasSuffix(request.URL.Path, "/") {
					http.Redirect(writer, request, request.URL.Path+"/", http.StatusMovedPermanently)
				} else {
					pprof.Index(writer, request)
				}
			})
			r.HandleFunc("/*", pprof.Index)
			r.HandleFunc("/cmdline", pprof.Cmdline)
			r.HandleFunc("/profile", pprof.Profile)
			r.HandleFunc("/symbol", pprof.Symbol)
			r.HandleFunc("/trace", pprof.Trace)
		})
	})
	server := &http.Server{
		Addr:                options.Listen,
		Handler:             r,
		ReadHeaderTimeout:   5 * time.Second,
		IdleTimeout:         30 * time.Second,
		MaxHeaderBytes:      16 << 10,
		MaxHeaderValueCount: 128,
	}
	debugHTTPServer = server
	go func() {
		err := server.ListenAndServe()
		if err != nil && !E.IsClosed(err) {
			log.Error(E.Cause(err, "serve debug HTTP server"))
		}
	}()
	return nil
}

// Explicitly requested, loopback-only report. Reuse the UI sample without
// walking connections, invoking ReadMemStats, or forcing a garbage collection.
func writeRuntimeReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	report := struct {
		GoVersion    string               `json:"go_version"`
		Memory       memorystats.Snapshot `json:"memory"`
		TrackedTasks map[string]int64     `json:"tracked_background_tasks"`
		LeakProfile  string               `json:"goroutine_leak_profile"`
	}{runtime.Version(), memorystats.Read(), diagnostics.ActiveTasks(), "/debug/pprof/goroutineleak"}
	_ = stdjson.MarshalWrite(w, report)
}
