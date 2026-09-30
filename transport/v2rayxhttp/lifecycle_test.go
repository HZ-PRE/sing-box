package xhttp

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func awaitResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("operation remained blocked after close")
		return nil
	}
}

func TestUploadQueueCloseUnblocks(t *testing.T) {
	t.Run("reader", func(t *testing.T) {
		q := NewUploadQueue(1)
		result := make(chan error, 1)
		go func() { _, err := q.Read(make([]byte, 1)); result <- err }()
		q.Close()
		if !errors.Is(awaitResult(t, result), io.EOF) {
			t.Fatal("expected EOF")
		}
	})
	t.Run("full queue", func(t *testing.T) {
		q := NewUploadQueue(1)
		q.Push(Packet{Payload: []byte("a")})
		result := make(chan error, 1)
		go func() { result <- q.Push(Packet{Payload: []byte("b"), Seq: 1}) }()
		closed := make(chan error, 1)
		go func() { closed <- q.Close() }()
		awaitResult(t, closed)
		if awaitResult(t, result) == nil {
			t.Fatal("push succeeded after queue close")
		}
	})
	t.Run("active stream", func(t *testing.T) {
		q := NewUploadQueue(1)
		reader, writer := io.Pipe()
		defer writer.Close()
		q.Push(Packet{Reader: reader})
		result := make(chan error, 1)
		go func() { _, err := q.Read(make([]byte, 1)); result <- err }()
		q.Close()
		if awaitResult(t, result) == nil {
			t.Fatal("stream remained open")
		}
	})
}

func TestUploadQueueReordersAndPartiallyReads(t *testing.T) {
	q := NewUploadQueue(4)
	defer q.Close()
	for _, packet := range []Packet{{Seq: 2, Payload: []byte("ef")}, {Seq: 0, Payload: []byte("ab")}, {Seq: 1, Payload: []byte("cd")}} {
		if err := q.Push(packet); err != nil {
			t.Fatal(err)
		}
	}
	var result []byte
	for i := 0; i < 6; i++ {
		b := make([]byte, 1)
		if _, err := io.ReadFull(q, b); err != nil {
			t.Fatal(err)
		}
		result = append(result, b...)
	}
	if string(result) != "abcdef" {
		t.Fatalf("bad order: %s", result)
	}
}

type closeCounter struct{ closed atomic.Int32 }

func (c *closeCounter) Read([]byte) (int, error) { return 0, io.EOF }
func (c *closeCounter) Close() error             { c.closed.Add(1); return io.ErrUnexpectedEOF }

func TestWaitReadCloserConcurrentSetClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		w := &WaitReadCloser{ctx: context.Background(), Wait: make(chan struct{})}
		reader := new(closeCounter)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); w.Set(reader) }()
		go func() { defer wg.Done(); w.Close() }()
		go func() { defer wg.Done(); w.Read(make([]byte, 1)) }()
		wg.Wait()
		w.Close()
		if reader.closed.Load() != 1 {
			t.Fatal("reader not closed exactly once")
		}
	}
}

func TestSplitConnCloseReturnsReaderErrorOnce(t *testing.T) {
	reader := new(closeCounter)
	_, writer := io.Pipe()
	conn := &splitConn{reader: reader, writer: writer}
	for i := 0; i < 2; i++ {
		if !errors.Is(conn.Close(), io.ErrUnexpectedEOF) {
			t.Fatal("reader close error lost")
		}
	}
	if reader.closed.Load() != 1 {
		t.Fatal("closed reader twice")
	}
}
