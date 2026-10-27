package httpclient

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type innerTransport interface {
	http.RoundTripper
	CloseIdleConnections()
	Close() error
}

var _ adapter.HTTPTransport = (*ManagedTransport)(nil)

type ManagedTransport struct {
	epoch         atomic.Pointer[transportEpoch]
	rebuildAccess sync.Mutex
	factory       func() (innerTransport, error)
	cheapRebuild  bool
	closed        atomic.Bool
	lifetime      context.Context
	cancel        context.CancelFunc

	dialer  N.Dialer
	headers http.Header
	host    string
	tag     string
}

type transportEpoch struct {
	transport innerTransport
	active    atomic.Int64
	marked    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

type managedResponseBody struct {
	body      io.ReadCloser
	release   func()
	once      sync.Once
	closeOnce sync.Once
	closeErr  error
}

func (e *transportEpoch) tryClose() error {
	e.closeOnce.Do(func() {
		e.closeErr = e.transport.Close()
	})
	return e.closeErr
}

func (b *managedResponseBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}

func (b *managedResponseBody) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.body.Close() })
	b.once.Do(b.release)
	return b.closeErr
}

func (t *ManagedTransport) getEpoch() (*transportEpoch, error) {
	if t.closed.Load() {
		return nil, net.ErrClosed
	}
	epoch := t.epoch.Load()
	if epoch != nil {
		return epoch, nil
	}
	t.rebuildAccess.Lock()
	defer t.rebuildAccess.Unlock()
	if t.closed.Load() {
		return nil, net.ErrClosed
	}
	epoch = t.epoch.Load()
	if epoch != nil {
		return epoch, nil
	}
	if t.lifetime == nil {
		t.lifetime, t.cancel = context.WithCancel(context.Background())
	}
	inner, err := t.factory()
	if err != nil {
		return nil, err
	}
	epoch = &transportEpoch{transport: inner}
	t.epoch.Store(epoch)
	return epoch, nil
}

func (t *ManagedTransport) acquireEpoch() (*transportEpoch, error) {
	for {
		epoch, err := t.getEpoch()
		if err != nil {
			return nil, err
		}
		epoch.active.Add(1)
		if epoch == t.epoch.Load() && !t.closed.Load() {
			return epoch, nil
		}
		t.releaseEpoch(epoch)
	}
}

func (t *ManagedTransport) releaseEpoch(epoch *transportEpoch) {
	if epoch.active.Add(-1) == 0 && epoch.marked.Load() {
		epoch.tryClose()
	}
}

func (t *ManagedTransport) retireEpoch(epoch *transportEpoch) {
	if epoch == nil {
		return
	}
	epoch.marked.Store(true)
	if epoch.active.Load() == 0 {
		epoch.tryClose()
	}
}

func (t *ManagedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	epoch, err := t.acquireEpoch()
	if err != nil {
		return nil, E.Cause(err, "rebuild http transport")
	}
	// Cancel active requests, including retired epochs, when the manager closes.
	// Reset only retires a pool and leaves already active responses usable.
	ctx, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(t.lifetime, cancel)
	release := func() { stop(); cancel(); t.releaseEpoch(epoch) }
	if t.tag != "" {
		if transportTag, loaded := transportTagFromContext(request.Context()); loaded && transportTag == t.tag {
			release()
			return nil, E.New("HTTP request loopback in transport[", t.tag, "]")
		}
		ctx = contextWithTransportTag(ctx, t.tag)
	}
	if len(t.headers) > 0 {
		request = request.Clone(ctx)
		if request.Header == nil {
			request.Header = make(http.Header)
		}
	} else {
		request = request.WithContext(ctx)
	}
	applyHeaders(request, t.headers, t.host)
	response, roundTripErr := epoch.transport.RoundTrip(request)
	if roundTripErr != nil || response == nil || response.Body == nil {
		release()
		return response, roundTripErr
	}
	response.Body = &managedResponseBody{
		body:    response.Body,
		release: release,
	}
	return response, roundTripErr
}

func (t *ManagedTransport) CloseIdleConnections() {
	t.rebuildAccess.Lock()
	oldEpoch := t.epoch.Swap(nil)
	t.rebuildAccess.Unlock()
	if oldEpoch == nil {
		return
	}
	oldEpoch.transport.CloseIdleConnections()
	t.retireEpoch(oldEpoch)
}

func (t *ManagedTransport) Reset() {
	t.rebuildAccess.Lock()
	if t.closed.Load() {
		t.rebuildAccess.Unlock()
		return
	}
	oldEpoch := t.epoch.Swap(nil)
	if t.cheapRebuild {
		if t.epoch.Load() == nil {
			if t.lifetime == nil {
				t.lifetime, t.cancel = context.WithCancel(context.Background())
			}
			inner, err := t.factory()
			if err == nil {
				t.epoch.Store(&transportEpoch{transport: inner})
			}
		}
	}
	t.rebuildAccess.Unlock()
	if oldEpoch != nil {
		oldEpoch.transport.CloseIdleConnections()
	}
	t.retireEpoch(oldEpoch)
}

func (t *ManagedTransport) close() error {
	t.rebuildAccess.Lock()
	defer t.rebuildAccess.Unlock()
	t.closed.Store(true)
	if t.cancel != nil {
		t.cancel()
	}
	epoch := t.epoch.Swap(nil)
	if epoch != nil {
		return epoch.tryClose()
	}
	return nil
}

var _ adapter.HTTPTransport = (*sharedRef)(nil)

type sharedRef struct {
	managed *ManagedTransport
	shared  *sharedState
	idle    atomic.Bool
}

type sharedState struct {
	activeRefs atomic.Int32
}

func newSharedRef(managed *ManagedTransport, shared *sharedState) *sharedRef {
	shared.activeRefs.Add(1)
	return &sharedRef{
		managed: managed,
		shared:  shared,
	}
}

func (r *sharedRef) RoundTrip(request *http.Request) (*http.Response, error) {
	if r.idle.CompareAndSwap(true, false) {
		r.shared.activeRefs.Add(1)
	}
	return r.managed.RoundTrip(request)
}

func (r *sharedRef) CloseIdleConnections() {
	if r.idle.CompareAndSwap(false, true) {
		if r.shared.activeRefs.Add(-1) == 0 {
			r.managed.CloseIdleConnections()
		}
	}
}

func (r *sharedRef) Reset() {
	r.managed.Reset()
}
