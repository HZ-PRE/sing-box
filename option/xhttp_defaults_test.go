package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"
)

func TestXHTTPPaddingDefaultsRoundTrip(t *testing.T) {
	for _, raw := range []string{`{"mode":"auto"}`, `{"mode":"auto","download":{"server":"example.com","server_port":443}}`} {
		var opts V2RayXHTTPOptions
		if err := json.Unmarshal([]byte(raw), &opts); err != nil {
			t.Fatal(err)
		}
		if opts.XPaddingBytes.From != 100 || opts.XPaddingBytes.To != 1000 {
			t.Fatal("missing default padding")
		}
		if opts.Download != nil && (opts.Download.XPaddingBytes.From != 100 || opts.Download.XPaddingBytes.To != 1000) {
			t.Fatal("missing download defaults")
		}
	}
	// Matches options built by the VLESS URI converter before saving a profile.
	opts := V2RayXHTTPOptions{Mode: "auto", Download: &V2RayXHTTPDownloadOptions{ServerOptions: ServerOptions{Server: "example.com", ServerPort: 443}}}
	encoded, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	var restored V2RayXHTTPOptions
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if opts.Download.XPaddingBytes.From != 0 {
		t.Fatal("serialization mutated caller options")
	}
	if restored.XPaddingBytes.From != 100 || restored.Download.XPaddingBytes.From != 100 {
		t.Fatal("roundtrip lost defaults")
	}
}

func TestXHTTPExplicitlyDisabledPaddingRejected(t *testing.T) {
	for _, raw := range []string{`{"x_padding_bytes":0}`, `{"x_padding_bytes":"0-100"}`, `{"download":{"x_padding_bytes":0}}`} {
		var opts V2RayXHTTPOptions
		if err := json.Unmarshal([]byte(raw), &opts); err == nil {
			t.Fatalf("disabled padding accepted: %s", raw)
		}
	}
}
