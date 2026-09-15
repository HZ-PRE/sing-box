package v2rayhttp

import (
	"context"
	"github.com/sagernet/sing-box/log"
	"testing"
)

func TestHijackedContextKeepsTransportCancellation(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	defer stop()
	request, cancelRequest := context.WithCancel(log.ContextWithNewID(parent))
	connection := DupContext(parent, request)
	cancelRequest()
	if connection.Err() != nil {
		t.Fatal("HTTP handler completion canceled the tunnel")
	}
	want, _ := log.IDFromContext(request)
	got, ok := log.IDFromContext(connection)
	if !ok || got != want {
		t.Fatal("request log ID was lost")
	}
	stop()
	if connection.Err() != context.Canceled {
		t.Fatal("transport shutdown did not cancel the tunnel")
	}
}
