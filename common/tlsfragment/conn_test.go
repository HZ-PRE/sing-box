package tf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/stretchr/testify/require"
)

func TestTLSFragment(t *testing.T) {
	for _, tc := range []struct {
		name           string
		packet, record bool
	}{
		{"packet", true, false}, {"record", false, true}, {"both", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(nil)
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tcpConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			require.NoError(t, err)
			defer tcpConn.Close()
			require.NoError(t, tcpConn.SetDeadline(time.Now().Add(5*time.Second)))
			tlsConn := tls.Client(tf.NewConn(tcpConn, ctx, tc.packet, tc.record, 0), &tls.Config{
				RootCAs: roots, ServerName: "example.com",
			})
			defer tlsConn.Close()
			require.NoError(t, tlsConn.HandshakeContext(ctx))
		})
	}
}
