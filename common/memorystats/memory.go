// Package memorystats shares a low-frequency Go memory sample across UI APIs.
package memorystats

import (
	"runtime/metrics"
	"sync"
	"time"
)

var sample struct {
	sync.Mutex
	at      time.Time
	value   Snapshot
	metrics [7]metrics.Sample
}

type Snapshot struct {
	GoCommittedBytes uint64  `json:"go_committed_bytes"`
	HeapObjectsBytes uint64  `json:"heap_objects_bytes"`
	HeapLiveBytes    uint64  `json:"heap_live_bytes"`
	Goroutines       uint64  `json:"goroutines"`
	GCCycles         uint64  `json:"gc_cycles"`
	GCCPUSeconds     float64 `json:"gc_cpu_seconds"`
}

func init() {
	for i, name := range []string{"/memory/classes/total:bytes", "/memory/classes/heap/released:bytes", "/memory/classes/heap/objects:bytes", "/gc/heap/live:bytes", "/sched/goroutines:goroutines", "/gc/cycles/total:gc-cycles", "/cpu/classes/gc/total:cpu-seconds"} {
		sample.metrics[i].Name = name
	}
}

// Inuse returns Go-managed committed memory, not process RSS or a memory cap.
func Inuse() uint64 {
	return Read().GoCommittedBytes
}

// Read reuses one sample per second. It neither forces GC nor stops the world
// with runtime.ReadMemStats, and does not allocate a metrics slice per poll.
func Read() Snapshot {
	sample.Lock()
	defer sample.Unlock()
	if time.Since(sample.at) >= time.Second {
		values := sample.metrics[:]
		metrics.Read(values)
		sample.value = Snapshot{
			GoCommittedBytes: values[0].Value.Uint64() - values[1].Value.Uint64(),
			HeapObjectsBytes: values[2].Value.Uint64(),
			HeapLiveBytes:    values[3].Value.Uint64(),
			Goroutines:       values[4].Value.Uint64(),
			GCCycles:         values[5].Value.Uint64(),
			GCCPUSeconds:     values[6].Value.Float64(),
		}
		sample.at = time.Now()
	}
	return sample.value
}
