package ssplus

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

func testKey(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func testConfig(t *testing.T, method, plugin string) *Config {
	t.Helper()
	c, err := NewConfig(method, plugin, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testPeers(t *testing.T, method, plugin string, id uint32) (*Client, *Server) {
	t.Helper()
	c := testConfig(t, method, plugin)
	users := []User{{ID: 1, Name: "alice", Key: testKey(2)}, {ID: 2, Name: "bob", Key: testKey(3)}}
	server, err := NewServer(c, users)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(c, users[id-1])
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

type fragmentedConn struct{ net.Conn }

func (c fragmentedConn) Read(p []byte) (int, error)  { return c.Conn.Read(p[:min(len(p), 13)]) }
func (c fragmentedConn) Write(p []byte) (int, error) { return c.Conn.Write(p[:min(len(p), 17)]) }

func TestRoundTrip(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, plugin := range []string{"origin", "auth_sha1_v4"} {
			for _, id := range []uint32{1, 2} {
				t.Run(fmt.Sprintf("%s/%s/%d", method, plugin, id), func(t *testing.T) {
					client, server := testPeers(t, method, plugin, id)
					left, right := net.Pipe()
					defer left.Close()
					defer right.Close()
					left.SetDeadline(time.Now().Add(10 * time.Second))
					right.SetDeadline(time.Now().Add(10 * time.Second))
					destination := M.ParseSocksaddr("example.com:443")
					result := make(chan error, 1)
					go func() {
						conn, dest, user, err := server.Accept(fragmentedConn{right})
						if err == nil && (dest != destination || user.ID != id || user.Key != "") {
							err = errors.New("incorrect destination/user or leaked key")
						}
						if err == nil {
							_, err = io.Copy(conn, conn)
						}
						result <- err
					}()
					conn, err := client.DialConn(fragmentedConn{left}, destination)
					if err != nil {
						t.Fatal(err)
					}
					payload := bytes.Repeat([]byte("ssplus multi-frame TCP\x00"), 4096)
					written := make(chan error, 1)
					go func() { written <- writeFull(conn, payload) }()
					reply := make([]byte, len(payload))
					if _, err = io.ReadFull(conn, reply); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(reply, payload) {
						t.Fatal("payload mismatch")
					}
					if err = <-written; err != nil {
						t.Fatal(err)
					}
					conn.Close()
					if err = <-result; err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestServerFirst(t *testing.T) {
	client, server := testPeers(t, "", "", 1)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(5 * time.Second))
	right.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		conn, _, _, err := server.Accept(right)
		if err == nil {
			err = writeFull(conn, []byte("220 ready\r\n"))
		}
		done <- err
	}()
	conn, err := client.DialConn(left, M.ParseSocksaddr("127.0.0.1:25"))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 11)
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "220 ready\r\n" {
		t.Fatalf("unexpected greeting %q", got)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

// memoryConn permits capturing and mutating actual encrypted wire requests.
type memoryConn struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *memoryConn) Read(p []byte) (int, error)     { return c.input.Read(p) }
func (c *memoryConn) Write(p []byte) (int, error)    { return c.output.Write(p) }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

func captureRequest(t *testing.T, client *Client) []byte {
	t.Helper()
	wire := &memoryConn{}
	if _, err := client.DialConn(wire, M.ParseSocksaddr("[::1]:443")); err != nil {
		t.Fatal(err)
	}
	return wire.output.Bytes()
}

func TestAuthenticationAndReplay(t *testing.T) {
	client, server := testPeers(t, "", "", 1)
	request := captureRequest(t, client)
	accept := func(data []byte) error {
		_, _, _, err := server.Accept(&memoryConn{input: bytes.NewReader(data)})
		return err
	}
	for _, index := range []int{0, 15, 16, IVSize - 1, IVSize, len(request) - 1} {
		bad := bytes.Clone(request)
		bad[index] ^= 1
		if err := accept(bad); err == nil {
			t.Fatalf("accepted modified byte %d", index)
		}
	}
	for _, length := range []int{0, 15, IVSize - 1, IVSize, len(request) - 1} {
		if err := accept(request[:length]); err == nil {
			t.Fatalf("accepted truncated length %d", length)
		}
	}
	if len(server.replay.entries) != 0 {
		t.Fatal("unauthenticated data populated replay cache")
	}
	if err := accept(request); err != nil {
		t.Fatal(err)
	}
	if err := accept(request); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("replay accepted: %v", err)
	}
	for _, user := range []User{{ID: 1, Key: testKey(9)}, {ID: 99, Key: testKey(2)}} {
		badClient, _ := NewClient(client.config, user)
		if err := accept(captureRequest(t, badClient)); err == nil {
			t.Fatal("accepted wrong key or unknown user")
		}
	}
	for _, fields := range [][3]string{{"", "origin", testKey(1)}, {"chacha20-ietf-poly1305", "", testKey(1)}, {"", "", testKey(9)}} {
		config, _ := NewConfig(fields[0], fields[1], fields[2])
		badClient, _ := NewClient(config, User{ID: 1, Key: testKey(2)})
		if err := accept(captureRequest(t, badClient)); err == nil {
			t.Fatal("accepted mismatched configuration")
		}
	}
}

func TestIVFreshnessAndUniqueness(t *testing.T) {
	config := testConfig(t, "", "")
	now := time.Now()
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		iv, err := config.makeIV(42, now)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(iv)] {
			t.Fatal("reused IV")
		}
		seen[string(iv)] = true
		if id, err := config.parseIV(iv, now); err != nil || id != 42 {
			t.Fatalf("IV roundtrip %d: %v", id, err)
		}
	}
	for _, shift := range []time.Duration{-3 * time.Minute, 3 * time.Minute} {
		iv, _ := config.makeIV(42, now.Add(shift))
		if _, err := config.parseIV(iv, now); !errors.Is(err, ErrAuthentication) {
			t.Fatal("accepted stale or future IV")
		}
	}
}

func TestConcurrentReplay(t *testing.T) {
	client, server := testPeers(t, "", "", 1)
	request := captureRequest(t, client)
	results := make(chan error, 16)
	var workers sync.WaitGroup
	for i := 0; i < cap(results); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _, _, err := server.Accept(&memoryConn{input: bytes.NewReader(request)})
			results <- err
		}()
	}
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d copies of one request", accepted)
	}
}

func TestResponseBoundToRequest(t *testing.T) {
	client, server := testPeers(t, "", "", 1)
	first := &memoryConn{}
	if _, err := client.DialConn(first, M.ParseSocksaddr("example.com:443")); err != nil {
		t.Fatal(err)
	}
	serverWire := &memoryConn{input: bytes.NewReader(first.output.Bytes())}
	conn, _, _, err := server.Accept(serverWire)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeFull(conn, []byte("response")); err != nil {
		t.Fatal(err)
	}
	second := &memoryConn{input: bytes.NewReader(serverWire.output.Bytes())}
	otherConn, err := client.DialConn(second, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = otherConn.Read(make([]byte, 8)); err == nil {
		t.Fatal("accepted response from another session")
	}
}

func TestUOT(t *testing.T) {
	for _, version := range []uint8{1, 2} {
		for _, connect := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/connect=%t", version, connect), func(t *testing.T) {
				client, server := testPeers(t, "", "", 2)
				left, right := net.Pipe()
				defer left.Close()
				defer right.Close()
				left.SetDeadline(time.Now().Add(5 * time.Second))
				right.SetDeadline(time.Now().Add(5 * time.Second))
				destination := M.ParseSocksaddr("[2001:db8::1]:53")
				payloads := [][]byte{nil, []byte("dns query"), bytes.Repeat([]byte{0x42}, 65000)}
				done := make(chan error, 1)
				go func() {
					conn, dest, user, err := server.Accept(right)
					if err != nil {
						done <- err
						return
					}
					if dest != uot.RequestDestination(version) || user.ID != 2 {
						done <- errors.New("wrong UoT destination or user")
						return
					}
					request := uot.Request{}
					if version == 2 {
						parsed, err := uot.ReadRequest(conn)
						if err != nil {
							done <- err
							return
						}
						request = *parsed
					}
					packets := uot.NewConn(conn, request)
					for range payloads {
						buffer := make([]byte, 65535)
						n, addr, err := packets.ReadFrom(buffer)
						if err != nil {
							done <- err
							return
						}
						if M.SocksaddrFromNet(addr) != destination {
							done <- fmt.Errorf("incorrect packet destination: %v", addr)
							return
						}
						if _, err = packets.WriteTo(buffer[:n], addr); err != nil {
							done <- err
							return
						}
					}
					done <- nil
				}()
				conn, err := client.DialConn(left, uot.RequestDestination(version))
				if err != nil {
					t.Fatal(err)
				}
				packets, err := (&uot.Client{Version: version}).DialEarlyConn(conn, connect, destination)
				if err != nil {
					t.Fatal(err)
				}
				for _, payload := range payloads {
					if _, err = packets.WriteTo(payload, destination); err != nil {
						t.Fatal(err)
					}
					reply := make([]byte, 65535)
					n, addr, err := packets.ReadFrom(reply)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(reply[:n], payload) || M.SocksaddrFromNet(addr) != destination {
						t.Fatal("UoT packet mismatch")
					}
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestConfigurationValidation(t *testing.T) {
	for _, fields := range [][3]string{{"none", "", testKey(1)}, {"aes-128-cfb", "", testKey(1)}, {"", "auth_chain_a", testKey(1)}, {"", "", "password"}} {
		if _, err := NewConfig(fields[0], fields[1], fields[2]); err == nil {
			t.Fatal("accepted invalid config")
		}
	}
	config := testConfig(t, "", "")
	for _, users := range [][]User{nil, {{ID: 0, Key: testKey(2)}}, {{ID: 1, Key: "bad"}}, {{ID: 1, Key: testKey(2)}, {ID: 1, Key: testKey(3)}}} {
		if _, err := NewServer(config, users); err == nil {
			t.Fatal("accepted invalid users")
		}
	}
}

func TestSSRRejectInvalidPadding(t *testing.T) {
	key := bytes.Repeat([]byte{2}, 32)
	for _, padding := range []byte{0, 254, 255} {
		frame, _ := encodeSSR([]byte("test"), key, make([]byte, IVSize), false, time.Now())
		frame[4] = padding
		if padding == 255 {
			binary.BigEndian.PutUint16(frame[5:7], 0xffff)
		}
		binary.LittleEndian.PutUint32(frame[len(frame)-4:], adler32.Checksum(frame[:len(frame)-4]))
		if _, err := readSSR(bytes.NewReader(frame), key, make([]byte, IVSize), false, time.Now()); err == nil {
			t.Fatal("accepted invalid padding")
		}
	}
}

func TestSSRReferenceFrames(t *testing.T) {
	data, err := os.ReadFile("testdata/auth_sha1_v4_clash.json")
	if err != nil {
		t.Fatal(err)
	}
	var reference struct {
		Timestamp   int64  `json:"timestamp"`
		Key         []byte `json:"key"`
		IV          []byte `json:"iv"`
		AuthFrames  []byte `json:"auth_frames"`
		AuthPayload []byte `json:"auth_payload"`
		DataFrame   []byte `json:"data_frame"`
		DataPayload []byte `json:"data_payload"`
	}
	if err = json.Unmarshal(data, &reference); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(reference.Timestamp, 0)
	reader := bytes.NewReader(reference.AuthFrames)
	decoded, err := readSSR(reader, reference.Key, reference.IV, true, now)
	for err == nil && reader.Len() > 0 {
		var part []byte
		part, err = readSSR(reader, reference.Key, reference.IV, false, now)
		decoded = append(decoded, part...)
	}
	if err != nil || !bytes.Equal(decoded, reference.AuthPayload) {
		t.Fatalf("reference auth: %v", err)
	}
	decoded, err = readSSR(bytes.NewReader(reference.DataFrame), reference.Key, reference.IV, false, now)
	if err != nil || !bytes.Equal(decoded, reference.DataPayload) {
		t.Fatalf("reference data: %v", err)
	}
}

func TestReplayCacheBoundAndExpiry(t *testing.T) {
	_, server := testPeers(t, "", "", 1)
	now := time.Now()
	for i := 0; i < maxReplayEntries; i++ {
		var token [IVSize]byte
		binary.BigEndian.PutUint64(token[:8], uint64(i))
		if !server.remember(token[:], now) {
			t.Fatal("entry rejected before capacity")
		}
	}
	iv := bytes.Repeat([]byte{0xff}, IVSize)
	if server.remember(iv, now) {
		t.Fatal("cache full must fail closed")
	}
	if !server.remember(iv, now.Add(3*clockWindow)) {
		t.Fatal("expired cache entries were not reclaimed")
	}
}

func FuzzSSRDecode(f *testing.F) {
	key, iv := bytes.Repeat([]byte{2}, 32), make([]byte, IVSize)
	for _, auth := range []bool{false, true} {
		frame, _ := encodeSSR([]byte("hello"), key, iv, auth, time.Unix(1700000000, 0))
		f.Add(frame, auth)
	}
	f.Fuzz(func(t *testing.T, frame []byte, auth bool) {
		_, _ = readSSR(bytes.NewReader(frame), key, iv, auth, time.Unix(1700000000, 0))
	})
}
