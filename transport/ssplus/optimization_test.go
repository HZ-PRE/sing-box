package ssplus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTicketRecordCompatibility(t *testing.T) {
	p := bytes.Repeat([]byte("data"), 10000)
	var expected []byte
	for rest := p; len(rest) > 0; {
		n := min(len(rest), 4096)
		expected = append(expected, tlsRecord(0x17, 0x0303, rest[:n])...)
		rest = rest[n:]
	}
	upstream := &memoryConn{}
	w := &ticketConn{Conn: fragmentedConn{upstream}}
	if n, err := w.Write(p); n != len(p) || err != nil {
		t.Fatalf("write %d %v", n, err)
	}
	if !bytes.Equal(upstream.output.Bytes(), expected) {
		t.Fatal("legacy TLS-shaped records changed")
	}
	for _, size := range []int{1, 13, 4096, 65536} {
		r := &ticketConn{Conn: fragmentedConn{&memoryConn{input: bytes.NewReader(expected)}}}
		buffer := make([]byte, size)
		var output bytes.Buffer
		for {
			n, err := r.Read(buffer)
			output.Write(buffer[:n])
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(output.Bytes(), p) {
			t.Fatalf("read size %d changed data", size)
		}
	}
	// A peer may send the full permitted TLS record even though our writer
	// retains the legacy 4096-byte record size.
	p = bytes.Repeat([]byte{9}, maxTLSRecord)
	r := &ticketConn{Conn: &memoryConn{input: bytes.NewReader(tlsRecord(0x17, 0x0303, p))}}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(p, got) {
		t.Fatal("maximum record", err)
	}
}

func TestTicketInvalidRecordsAndStickyFailure(t *testing.T) {
	cases := [][]byte{{0x17, 3, 3, 0, 0}, {0x17, 3, 3, 0x40, 1}, {0x16, 3, 3, 0, 1, 0}, {0x17, 3, 1, 0, 1, 0}, {0x17, 3, 3, 0, 5, 1, 2}}
	for _, wire := range cases {
		r := &ticketConn{Conn: &memoryConn{input: bytes.NewReader(wire)}}
		_, err := r.Read(make([]byte, 64))
		if err == nil {
			t.Fatal("invalid record accepted")
		}
		if _, again := r.Read(make([]byte, 64)); again != err {
			t.Fatal("failure not sticky")
		}
	}
	w := &ticketConn{Conn: &memoryConn{}}
	if n, err := w.Write(nil); n != 0 || err != nil || len(w.writeBuffer) != 0 {
		t.Fatal("empty write allocated")
	}
}

func TestReplayExpiryAndClockChanges(t *testing.T) {
	var c replayCache
	now := time.Now()
	a, b := bytes.Repeat([]byte{1}, IVSize), bytes.Repeat([]byte{2}, IVSize)
	if !c.remember(a, now) || !c.remember(b, now.Add(time.Second*2)) {
		t.Fatal("first use rejected")
	}
	if c.remember(a, now.Add(replayRetention-time.Nanosecond)) {
		t.Fatal("entry expired early")
	}
	if !c.remember(a, now.Add(replayRetention+time.Second)) {
		t.Fatal("expired entry not reclaimed")
	}
	if c.remember(b, now.Add(replayRetention+time.Second)) {
		t.Fatal("newer live bucket evicted")
	}
	if c.remember(a, now.Add(-time.Hour)) {
		t.Fatal("backward clock reopened replay")
	}
	d := bytes.Repeat([]byte{3}, IVSize)
	if !c.remember(d, now.Add(-time.Hour)) {
		t.Fatal("new token rejected after rollback")
	}
	if c.remember(d, now) {
		t.Fatal("rollback shortened retention")
	}
	if !c.remember(a, now.Add(24*time.Hour)) {
		t.Fatal("idle cache not reclaimed")
	}
	if len(c.entries) != 1 || len(c.buckets) != 1 {
		t.Fatal("expired tokens retained")
	}
	if c.remember(a[:2], now) {
		t.Fatal("invalid token accepted")
	}
}

func TestReplayConcurrentAndBounded(t *testing.T) {
	var c replayCache
	now := time.Now()
	iv := bytes.Repeat([]byte{3}, IVSize)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.remember(iv, now) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d duplicate requests", accepted.Load())
	}
	for i := 1; i < maxReplayEntries; i++ {
		binary.BigEndian.PutUint64(iv[:8], uint64(i))
		if !c.remember(iv, now) {
			t.Fatal("premature cache exhaustion")
		}
	}
	binary.BigEndian.PutUint64(iv[:8], uint64(maxReplayEntries))
	if c.remember(iv, now.Add(replayRetention-time.Nanosecond)) {
		t.Fatal("evicted a live entry")
	}
	if len(c.entries) != maxReplayEntries {
		t.Fatal("capacity limit changed")
	}
	if !c.remember(iv, now.Add(replayRetention+time.Second)) {
		t.Fatal("full expired cache not reclaimed")
	}
}

func TestReplayBucketCompaction(t *testing.T) {
	var c replayCache
	now := time.Now()
	var iv [IVSize]byte
	for i := 0; i < 2000; i++ {
		binary.BigEndian.PutUint64(iv[:8], uint64(i))
		at := now.Add(time.Duration(i) * time.Second)
		if !c.remember(iv[:], at) || c.remember(iv[:], at) {
			t.Fatal("admission failed")
		}
		if len(c.buckets) > 500 || len(c.entries) > 244 {
			t.Fatal("expiration storage grew unbounded")
		}
	}
}

func FuzzTicketRecords(f *testing.F) {
	f.Add(tlsRecord(0x17, 0x0303, []byte("hello")), uint16(2))
	f.Add([]byte{0x17, 3, 3, 0xff, 0xff}, uint16(1))
	f.Fuzz(func(t *testing.T, wire []byte, size uint16) {
		if len(wire) > 65536 {
			return
		}
		r := &ticketConn{Conn: &memoryConn{input: bytes.NewReader(wire)}}
		p := make([]byte, int(size)%4096+1)
		for i := 0; i <= len(wire)+1; i++ {
			n, err := r.Read(p)
			if n < 0 || n > len(p) {
				t.Fatal("invalid size")
			}
			if err != nil {
				return
			}
			if n == 0 {
				t.Fatal(errors.New("record made no progress"))
			}
		}
		t.Fatal("unbounded read")
	})
}
