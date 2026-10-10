package ssplus

import (
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type countedConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *countedConn) Write(p []byte) (int, error) { c.writes.Add(1); return c.Conn.Write(p) }

func TestHandshakeWriteCoalescing(t *testing.T) {
	for _, obfs := range []string{"plain", "tls1.2_ticket_auth"} {
		config, err := NewConfigWithObfs("aes-256-gcm", "auth_aes128_md5", testKey(1), obfs, "")
		if err != nil {
			t.Fatal(err)
		}
		user := User{ID: 1, Key: testKey(2)}
		server, _ := NewServer(config, []User{user})
		client, _ := NewClient(config, user)
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(3 * time.Second))
		b.SetDeadline(time.Now().Add(3 * time.Second))
		conn := &countedConn{Conn: a}
		done := make(chan error, 1)
		go func() { _, _, _, err := server.Accept(b); done <- err }()
		_, err = client.DialConn(conn, M.ParseSocksaddr("example.com:443"))
		if err != nil {
			t.Fatal(err)
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
		want := int32(1)
		if obfs != "plain" {
			want = 2
		}
		if conn.writes.Load() != want {
			t.Fatalf("%s: writes %d want %d", obfs, conn.writes.Load(), want)
		}
		a.Close()
		b.Close()
	}
}
