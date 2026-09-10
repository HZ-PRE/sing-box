package log

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
)

const asyncWriterBufferSize = 1024

type asyncWriter struct {
	writer io.Writer
	queue  chan []byte
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	dropped atomic.Uint64
}

func newAsyncWriter(writer io.Writer) *asyncWriter {
	w := &asyncWriter{
		writer: writer,
		queue:  make(chan []byte, asyncWriterBufferSize),
		done:   make(chan struct{}),
	}
	w.wg.Add(1)
	go w.drain()
	return w
}

func (w *asyncWriter) Write(p []byte) (int, error) {
	if w == nil || w.writer == nil {
		return len(p), nil
	}

	entry := append([]byte(nil), p...)
	select {
	case <-w.done:
		return len(p), os.ErrClosed
	default:
	}

	select {
	case w.queue <- entry:
	default:
		w.dropped.Add(1)
	}
	return len(p), nil
}

func (w *asyncWriter) Close() error {
	if w == nil {
		return nil
	}
	w.once.Do(func() {
		close(w.done)
	})
	return nil
}

func (w *asyncWriter) drain() {
	defer w.wg.Done()
	for {
		select {
		case <-w.done:
			w.flushPending()
			return
		case entry := <-w.queue:
			w.writeDroppedNotice()
			_, _ = w.writer.Write(entry)
		}
	}
}

func (w *asyncWriter) flushPending() {
	for {
		select {
		case entry := <-w.queue:
			w.writeDroppedNotice()
			_, _ = w.writer.Write(entry)
		default:
			w.writeDroppedNotice()
			return
		}
	}
}

func (w *asyncWriter) writeDroppedNotice() {
	if dropped := w.dropped.Swap(0); dropped > 0 {
		_, _ = w.writer.Write([]byte("dropped log messages because the async log writer queue is full\n"))
	}
}
