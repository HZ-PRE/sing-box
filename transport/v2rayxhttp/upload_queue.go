package xhttp

// upload_queue is a specialized priorityqueue + channel to reorder generic
// packets by a sequence number

import (
	"container/heap"
	"io"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

type Packet struct {
	Reader  io.ReadCloser
	Payload []byte
	Seq     uint64
}

type uploadQueue struct {
	reader          io.ReadCloser
	nomore          bool
	pushedPackets   chan Packet
	writeCloseMutex sync.Mutex
	stateMutex      sync.Mutex
	done            chan struct{}
	closeOnce       sync.Once
	heap            uploadHeap
	nextSeq         uint64
	closed          bool
	maxPackets      int
}

func NewUploadQueue(maxPackets int) *uploadQueue {
	return &uploadQueue{
		pushedPackets: make(chan Packet, maxPackets),
		done:          make(chan struct{}),
		heap:          uploadHeap{},
		nextSeq:       0,
		closed:        false,
		maxPackets:    maxPackets,
	}
}

func (h *uploadQueue) Push(p Packet) error {
	h.writeCloseMutex.Lock()
	defer h.writeCloseMutex.Unlock()
	select {
	case <-h.done:
		return E.New("packet queue closed")
	default:
	}
	if h.nomore {
		return E.New("h.reader already exists")
	}
	if p.Reader != nil {
		h.nomore = true
	}
	select {
	case h.pushedPackets <- p:
		return nil
	case <-h.done:
		return E.New("packet queue closed")
	}
}

func (h *uploadQueue) Close() error {
	h.closeOnce.Do(func() {
		close(h.done)
		h.stateMutex.Lock()
		h.closed = true
		reader := h.reader
		h.stateMutex.Unlock()
		if reader != nil {
			reader.Close()
		}
		// Wake blocked producers before taking their lock. The data channel
		// stays open, so a concurrent sender can never panic during shutdown.
		h.writeCloseMutex.Lock()
		defer h.writeCloseMutex.Unlock()
		for {
			select {
			case p := <-h.pushedPackets:
				if p.Reader != nil {
					p.Reader.Close()
				}
			default:
				return
			}
		}
	})
	return nil
}

func (h *uploadQueue) receive() (Packet, bool) {
	select {
	case <-h.done:
		return Packet{}, false
	case packet := <-h.pushedPackets:
		return packet, true
	}
}

func (h *uploadQueue) Read(b []byte) (int, error) {
	h.stateMutex.Lock()
	reader, closed := h.reader, h.closed
	h.stateMutex.Unlock()
	if closed {
		return 0, io.EOF
	}
	if reader != nil {
		return reader.Read(b)
	}
	if len(h.heap) == 0 {
		packet, more := h.receive()
		if !more {
			return 0, io.EOF
		}
		if packet.Reader != nil {
			h.stateMutex.Lock()
			if h.closed {
				h.stateMutex.Unlock()
				packet.Reader.Close()
				return 0, io.EOF
			}
			h.reader = packet.Reader
			h.stateMutex.Unlock()
			return packet.Reader.Read(b)
		}
		heap.Push(&h.heap, packet)
	}
	for len(h.heap) > 0 {
		packet := heap.Pop(&h.heap).(Packet)
		n := 0

		if packet.Seq == h.nextSeq {
			copy(b, packet.Payload)
			n = min(len(b), len(packet.Payload))

			if n < len(packet.Payload) {
				// partial read
				packet.Payload = packet.Payload[n:]
				heap.Push(&h.heap, packet)
			} else {
				h.nextSeq = packet.Seq + 1
			}

			return n, nil
		}
		// misordered packet
		if packet.Seq > h.nextSeq {
			if len(h.heap) > h.maxPackets {
				// the "reassembly buffer" is too large, and we want to
				// constrain memory usage somehow. let's tear down the
				// connection, and hope the application retries.
				return 0, E.New("packet queue is too large")
			}
			heap.Push(&h.heap, packet)
			packet2, more := h.receive()
			if !more {
				return 0, io.EOF
			}
			heap.Push(&h.heap, packet2)
		}
	}
	return 0, nil
}

// heap code directly taken from https://pkg.go.dev/container/heap
type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = Packet{}
	*h = old[0 : n-1]
	return x
}
