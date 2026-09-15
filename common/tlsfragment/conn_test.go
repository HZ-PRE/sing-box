package tf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/stretchr/testify/require"
)

func TestTLSFragmentRoundTrip(t *testing.T) {
	for _, mode := range []struct {
		name           string
		packet, record bool
	}{
		{"packet", true, false}, {"record", false, true}, {"both", true, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "fragment-ok") }))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
			client := tls.Client(tf.NewConn(conn, context.Background(), mode.packet, mode.record, 0), &tls.Config{RootCAs: roots, ServerName: "example.com"})
			require.NoError(t, client.Handshake())
			_, err = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			require.NoError(t, err)
			body, err := io.ReadAll(client)
			require.NoError(t, err)
			require.Contains(t, string(body), "fragment-ok")
		})
	}
}
