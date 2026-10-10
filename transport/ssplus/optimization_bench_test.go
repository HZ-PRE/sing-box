package ssplus

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type benchmarkConn struct {
	net.Conn
	reader io.Reader
}

func (c benchmarkConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c benchmarkConn) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkTicketWrite(b *testing.B) {
	p := bytes.Repeat([]byte{1}, 16384)
	c := &ticketConn{Conn: benchmarkConn{}}
	b.ReportAllocs()
	b.SetBytes(int64(len(p)))
	for b.Loop() {
		if _, err := c.Write(p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTicketRead(b *testing.B) {
	p := bytes.Repeat([]byte{1}, 4096)
	wire := tlsRecord(0x17, 0x0303, p)
	r := bytes.NewReader(wire)
	c := &ticketConn{Conn: benchmarkConn{reader: r}}
	b.ReportAllocs()
	b.SetBytes(int64(len(p)))
	for b.Loop() {
		r.Reset(wire)
		if _, err := io.ReadFull(c, p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReplayDuplicate(b *testing.B) {
	config, _ := NewConfig("", "origin", testKey(1))
	s, _ := NewManagedServer(config, nil)
	now := time.Now()
	var iv [IVSize]byte
	for i := 0; i < 32768; i++ {
		binary.BigEndian.PutUint64(iv[:8], uint64(i))
		s.remember(iv[:], now)
	}
	i := 0
	b.ReportAllocs()
	for b.Loop() {
		// Isolate duplicate rejection with a live cache, without map growth.
		i = (i + 1) % 200
		if s.remember(iv[:], now.Add(time.Duration(i)*time.Second)) {
			b.Fatal("replay accepted")
		}
	}
}

// Keep the previous full-scan algorithm here only as a benchmark reference.
// Simulated traffic is 1000 requests/second cycling over 32768 distinct tokens,
// so both rejection and expiry/re-admission are measured over long runs.
func BenchmarkReplayTraffic(b *testing.B) {
	for _, legacy := range []bool{true, false} {
		name := "buckets"
		if legacy {
			name = "legacy_scan"
		}
		b.Run(name, func(b *testing.B) {
			var cache replayCache
			remember := cache.remember
			if legacy {
				entries := make(map[[IVSize]byte]time.Time)
				var mutex sync.Mutex
				var lastSweep time.Time
				remember = func(iv []byte, now time.Time) bool {
					mutex.Lock()
					defer mutex.Unlock()
					if now.Sub(lastSweep) >= time.Second {
						for token, expiry := range entries {
							if !now.Before(expiry) {
								delete(entries, token)
							}
						}
						lastSweep = now
					}
					token := [IVSize]byte(iv)
					if _, exists := entries[token]; exists {
						return false
					}
					if len(entries) >= maxReplayEntries {
						return false
					}
					entries[token] = now.Add(replayRetention)
					return true
				}
			}
			now := time.Now()
			var iv [IVSize]byte
			for i := 0; i < 32768; i++ {
				binary.BigEndian.PutUint64(iv[:8], uint64(i))
				remember(iv[:], now)
			}
			i := 0
			b.ReportAllocs()
			for b.Loop() {
				i++
				binary.BigEndian.PutUint64(iv[:8], uint64(i%32768))
				remember(iv[:], now.Add(time.Duration(i)*time.Millisecond))
			}
		})
	}
}
