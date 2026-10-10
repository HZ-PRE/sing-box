// Package memorystats shares a low-frequency Go memory sample across UI APIs.
package memorystats

import (
	"runtime/metrics"
	"sync"
	"time"
)

var sample struct {
	sync.Mutex
	at    time.Time
	bytes uint64
}

// Inuse returns Go-managed committed memory, not process RSS or a memory cap.
func Inuse() uint64 {
	sample.Lock()
	defer sample.Unlock()
	if time.Since(sample.at) >= time.Second {
		values := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
		metrics.Read(values)
		sample.bytes = values[0].Value.Uint64() - values[1].Value.Uint64()
		sample.at = time.Now()
	}
	return sample.bytes
}
