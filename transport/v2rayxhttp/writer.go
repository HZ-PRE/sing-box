package xhttp

import (
	common "github.com/sagernet/sing-box/common/xray"
	"github.com/sagernet/sing-box/common/xray/buf"
	"github.com/sagernet/sing-box/common/xray/pipe"
	"sync"
)

// A wrapper around pipe that ensures the size limit is exactly honored.
//
// The MultiBuffer pipe accepts any single WriteMultiBuffer call even if that
// single MultiBuffer exceeds the size limit, and then starts blocking on the
// next WriteMultiBuffer call. This means that ReadMultiBuffer can return more
// bytes than the size limit. We work around this by splitting a potentially
// too large write up into multiple.
type uploadWriter struct {
	*pipe.Writer
	maxLen int32
}

func (w uploadWriter) Write(b []byte) (int, error) {

	buffer := buf.MultiBufferContainer{}
	common.Must2(buffer.Write(b))

	var writed int
	for i, buff := range buffer.MultiBuffer {
		length := int(buff.Len())
		err := w.WriteMultiBuffer(buf.MultiBuffer{buff})
		if err != nil {
			buf.ReleaseMulti(buffer.MultiBuffer[i+1:])
			return writed, err
		}
		writed += length
	}
	return writed, nil
}

// net/http may close a request body concurrently with a read on cancellation.
// Serialize access to the pooled buffers so they are released exactly once.
type uploadBody struct {
	mu     sync.Mutex
	buffer buf.MultiBufferContainer
}

func (b *uploadBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Read(p)
}
func (b *uploadBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Close()
}
