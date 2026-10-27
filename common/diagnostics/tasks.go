// Package diagnostics tracks background setup/refresh work, not traffic packets.
package diagnostics

import (
	"context"
	"runtime/pprof"
	"sync/atomic"
)

type Module uint8

const (
	DNSRefresh Module = iota
	XHTTP
	SSPlus
	moduleCount
)

var names = [moduleCount]string{"dns_refresh", "xhttp", "ssplus"}
var active [moduleCount]atomic.Int64
var labels = [moduleCount]pprof.LabelSet{
	pprof.Labels("module", "dns_refresh"),
	pprof.Labels("module", "xhttp"),
	pprof.Labels("module", "ssplus"),
}

// Go uses constant labels only: destination names and subscription credentials
// must never enter goroutine labels (included in Go 1.27 tracebacks).
func Go(ctx context.Context, module Module, task func(context.Context)) {
	active[module].Add(1)
	go func() {
		defer active[module].Add(-1)
		pprof.Do(ctx, labels[module], task)
	}()
}

func ActiveTasks() map[string]int64 {
	result := make(map[string]int64, moduleCount)
	for i, name := range names {
		result[name] = active[i].Load()
	}
	return result
}
