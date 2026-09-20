package ssplus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"testing"
	"time"
)

func TestAESMD5TicketRoundTrip(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, obfs := range []string{"plain", "tls1.2_ticket_auth"} {
			t.Run(method+"/"+obfs, func(t *testing.T) {
				config, err := NewConfigWithObfs(method, "auth_aes128_md5", testKey(1), obfs, "")
				if err != nil {
					t.Fatal(err)
				}
				server, err := NewServer(config, []User{{ID: 1, Key: testKey(2)}, {ID: 2, Key: testKey(3)}})
				if err != nil {
					t.Fatal(err)
				}
				for _, id := range []uint32{1, 2} {
					client, _ := NewClient(config, User{ID: id, Key: testKey(byte(id + 1))})
					a, b := net.Pipe()
					defer a.Close()
					defer b.Close()
					a.SetDeadline(time.Now().Add(10 * time.Second))
					b.SetDeadline(time.Now().Add(10 * time.Second))
					done := make(chan error, 1)
					go func() {
						conn, target, user, err := server.Accept(fragmentedConn{b})
						if err == nil && (user.ID != id || target.String() != "example.com:443") {
							err = fmt.Errorf("wrong user/target")
						}
						if err == nil {
							_, err = conn.Write([]byte("ready"))
							if err == nil {
								_, err = io.Copy(conn, conn)
							}
						}
						done <- err
					}()
					conn, err := client.DialConn(fragmentedConn{a}, M.ParseSocksaddr("example.com:443"))
					if err != nil {
						t.Fatal(err)
					}
					greeting := make([]byte, 5)
					if _, err := io.ReadFull(conn, greeting); err != nil || string(greeting) != "ready" {
						t.Fatal("server-first", err)
					}
					payload := bytes.Repeat([]byte("authenticated multi-frame data"), 4000)
					written := make(chan error, 1)
					go func() { written <- writeFull(conn, payload) }()
					reply := make([]byte, len(payload))
					if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
						t.Fatal("roundtrip", err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
					conn.Close()
					b.Close()
					<-done
				}
			})
		}
	}
}

func TestAESMD5FrameValidation(t *testing.T) {
	key, iv := bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 48)
	now := time.Now()
	auth, err := encodeAESAuth([]byte("target"), key, iv, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 1, 7, 11, 27, len(auth) - 1} {
		bad := bytes.Clone(auth)
		bad[index] ^= 1
		if _, err := readAESAuth(bytes.NewReader(bad), key, iv, now); err == nil {
			t.Fatalf("auth tamper at %d", index)
		}
	}
	if _, err := readAESAuth(bytes.NewReader(auth), key, iv, now.Add(3*time.Minute)); err == nil {
		t.Fatal("expired auth")
	}
	for _, sequence := range []uint32{1, 2, 0xffffffff} {
		frame, _ := encodeAESData([]byte("data"), key, sequence)
		if p, err := readAESData(bytes.NewReader(frame), key, sequence); err != nil || string(p) != "data" {
			t.Fatal(err)
		}
		if _, err := readAESData(bytes.NewReader(frame), key, sequence+1); err == nil {
			t.Fatal("wrong sequence")
		}
		for _, padding := range []byte{0, 254, 255} {
			bad := bytes.Clone(frame)
			bad[4] = padding
			if padding == 255 {
				binary.LittleEndian.PutUint16(bad[5:7], 0xffff)
			}
			copy(bad[len(bad)-4:], md5MAC(aesFrameKey(key, sequence), bad[:len(bad)-4])[:4])
			if _, err := readAESData(bytes.NewReader(bad), key, sequence); err == nil {
				t.Fatal("invalid padding")
			}
		}
	}
}

func TestTicketAuthenticationAndReplay(t *testing.T) {
	config, _ := NewConfigWithObfs("", "auth_aes128_md5", testKey(1), "tls1.2_ticket_auth", "example.com")
	server, _ := NewManagedServer(config, nil)
	sessionID := bytes.Repeat([]byte{7}, 32)
	hello, _ := makeClientHello(config.ivKey, sessionID, "example.com")
	finished, _ := makeFinished(config.ivKey, sessionID, nil)
	input := append(bytes.Clone(hello), finished...)
	for _, index := range []int{0, 5, 6, 11, 33, 44, len(input) - 1} {
		bad := bytes.Clone(input)
		bad[index] ^= 1
		s, _ := NewManagedServer(config, nil)
		if _, err := s.serverTicketHandshake(&memoryConn{input: bytes.NewReader(bad)}); err == nil {
			t.Fatalf("ticket tamper %d", index)
		}
	}
	if _, err := server.serverTicketHandshake(&memoryConn{input: bytes.NewReader(input)}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.serverTicketHandshake(&memoryConn{input: bytes.NewReader(input)}); err == nil {
		t.Fatal("replayed ClientHello")
	}
	for n := 0; n < len(input); n++ {
		s, _ := NewManagedServer(config, nil)
		if _, err := s.serverTicketHandshake(&memoryConn{input: bytes.NewReader(input[:n])}); err == nil {
			t.Fatalf("truncated ticket %d", n)
		}
	}
	for _, fields := range [][2]string{{"unknown", ""}, {"plain", "example.com"}, {"tls1.2_ticket_auth", "bad\r\nhost"}} {
		if _, err := NewConfigWithObfs("", "", testKey(1), fields[0], fields[1]); err == nil {
			t.Fatal("bad obfs config")
		}
	}
}

func FuzzAESMD5AndTLSDecoders(f *testing.F) {
	key, iv := make([]byte, 32), make([]byte, 48)
	f.Add([]byte{0x17, 3, 3, 0, 1, 42})
	frame, _ := encodeAESData([]byte("test"), key, 1)
	f.Add(frame)
	f.Fuzz(func(t *testing.T, input []byte) {
		readAESAuth(bytes.NewReader(input), key, iv, time.Unix(1700000000, 0))
		readAESData(bytes.NewReader(input), key, 1)
		readTLSRecord(bytes.NewReader(input))
		parseHello(input, 1)
	})
}
