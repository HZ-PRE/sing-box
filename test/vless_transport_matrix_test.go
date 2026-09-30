package main

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestRetainedVLESSTransportMatrix(t *testing.T) {
	for _, test := range []struct{ name, transport string }{
		{"websocket", `{"type":"ws","path":"/audit"}`},
		{"xhttp-auto", `{"type":"xhttp","mode":"auto","path":"/audit"}`},
		{"xhttp-stream-up", `{"type":"xhttp","mode":"stream-up","path":"/audit"}`},
		{"xhttp-stream-one", `{"type":"xhttp","mode":"stream-one","path":"/audit"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var transport option.V2RayTransportOptions
			if err := transport.UnmarshalJSON([]byte(test.transport)); err != nil {
				t.Fatal(err)
			}
			testV2RayTransportSelf(t, &transport)
		})
	}
}
