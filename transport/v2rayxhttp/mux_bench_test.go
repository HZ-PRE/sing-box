package xhttp

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
)

type benchmarkMuxConn struct{}

func (benchmarkMuxConn) IsClosed() bool { return false }
func (benchmarkMuxConn) Close() error   { return nil }

func BenchmarkXmuxSelection(b *testing.B) {
	m := NewXmuxManager(option.V2RayXHTTPXmuxOptions{}, func() XmuxConn { return benchmarkMuxConn{} })
	b.ReportAllocs()
	for b.Loop() {
		m.GetXmuxClient(context.Background()).Release()
	}
}
