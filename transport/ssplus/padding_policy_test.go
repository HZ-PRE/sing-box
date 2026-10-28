package ssplus

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	shadowaead "github.com/sagernet/sing-box/transport/ssplus/internal/aead"
	M "github.com/sagernet/sing/common/metadata"
)

func TestPaddingPolicyBudgetAndBulk(t *testing.T) {
	for _, mode := range []string{"initial", "light", "off"} {
		config := testConfig(t, "", "")
		if err := config.SetPadding(mode, 257); err != nil {
			t.Fatal(err)
		}
		p := config.paddingState(config.newPaddingAllowance())
		total := 0
		for i := 0; i < 1000; i++ {
			n, err := p.next(64, 127)
			if err != nil || n < 0 || n > 127 {
				t.Fatal(n, err)
			}
			if (mode == "off" || mode == "initial" && i >= 8) && n != 0 {
				t.Fatal("padding after cutoff")
			}
			if mode == "light" && i >= 8 && n > 31 {
				t.Fatal("light padding too large")
			}
			total += n
		}
		if total > 257 {
			t.Fatalf("budget exceeded: %d", total)
		}
		if mode == "light" && total != 257 {
			t.Fatalf("light mode did not exhaust finite budget: %d", total)
		}
		p = config.paddingState(config.newPaddingAllowance())
		for _, size := range []int{1201, 64, 8192, 1} {
			if n, err := p.next(size, 127); err != nil || n != 0 {
				t.Fatal("bulk stream padded", n, err)
			}
		}
	}
}

func TestPaddingValidation(t *testing.T) {
	c := testConfig(t, "", "")
	for _, tc := range []struct {
		mode   string
		budget int
	}{{"invalid", 1}, {"light", -1}, {"initial", 65537}} {
		if c.SetPadding(tc.mode, tc.budget) == nil {
			t.Fatal("invalid padding accepted", tc)
		}
	}
}

func TestPaddingSharedBudgetConcurrent(t *testing.T) {
	c := testConfig(t, "", "")
	_ = c.SetPadding("light", 257)
	b := c.newPaddingAllowance()
	var wg sync.WaitGroup
	used := make(chan int, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := 0
			for j := 0; j < 100; j++ {
				n += b.take(7)
			}
			used <- n
		}()
	}
	wg.Wait()
	close(used)
	total := 0
	for n := range used {
		total += n
	}
	if total != 257 || b.remaining.Load() != 0 {
		t.Fatal("shared budget overspent", total)
	}
}

func TestPaddingTCPWireOverhead(t *testing.T) {
	for _, plugin := range []string{"auth_sha1_v4", "auth_aes128_md5"} {
		for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
			config := testConfig(t, method, plugin)
			_ = config.SetPadding("initial", 257)
			client, _ := NewClient(config, User{ID: 1, Key: testKey(2)})
			transport := &memoryConn{}
			conn, err := client.DialConn(transport, M.ParseSocksaddr("example.com:443"))
			if err != nil {
				t.Fatal(err)
			}
			allowance := conn.(paddingOwner).outgoingPadding()
			payload := bytes.Repeat([]byte{42}, 64)
			for i := 0; i < 40; i++ {
				before := transport.output.Len()
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				// Both plugin data frames have 9 mandatory bytes; AEAD adds 34.
				extra := transport.output.Len() - before - len(payload) - 9 - 34
				if extra < 0 || extra > 127 || i >= 7 && extra != 0 {
					t.Fatal("unexpected padding", plugin, i, extra)
				}
			}
			server, _ := NewServer(config, []User{{ID: 1, Key: testKey(2)}})
			serverTransport := &memoryConn{input: bytes.NewReader(transport.output.Bytes())}
			accepted, _, _, err := server.Accept(serverTransport)
			if err != nil {
				t.Fatal(err)
			}
			all := make([]byte, len(payload)*40)
			if _, err := io.ReadFull(accepted, all); err != nil || !bytes.Equal(all, bytes.Repeat(payload, 40)) {
				t.Fatal("payload mismatch", err)
			}
			// Authentication success is represented by the first response, without a new ACK/RTT.
			if _, err := accepted.Write(payload); err != nil {
				t.Fatal(err)
			}
			if len(serverTransport.output.Bytes()) <= 32+64+9+34 {
				t.Fatal("first response was not padded")
			}
			native := newNativeConn(config, conn, make([]byte, 48), true, &nativeBudget{limit: 1024})
			if native.tx.policy.allowance != allowance {
				t.Fatal("UDP did not share TCP allowance")
			}
			if allowance.remaining.Load() < 0 {
				t.Fatal("negative budget")
			}
		}
	}
}

func TestNativePaddingBudgetAndBulk(t *testing.T) {
	config := testConfig(t, "", "")
	_ = config.SetPadding("light", 73)
	tx := newNativeCipher(config, make([]byte, 48), "request")
	rx := newNativeCipher(config, make([]byte, 48), "request")
	plain := bytes.Repeat([]byte{99}, 64)
	total := 0
	for i := 0; i < 100; i++ {
		packet, err := tx.seal(nil, plain)
		if err != nil {
			t.Fatal(err)
		}
		total += len(packet) - nativeHeader - nativeEnvelope - 16 - len(plain)
		decoded, _, err := rx.open(nil, packet)
		if err != nil || !bytes.Equal(decoded, plain) {
			t.Fatal("UDP mismatch", err)
		}
	}
	if total != 73 {
		t.Fatal("UDP budget", total)
	}
	// A fragment's declared whole-message length, not its sequence ID, controls bulk cutoff.
	tx = newNativeCipher(config, make([]byte, 48), "request")
	fragment := make([]byte, 32)
	fragment[0], fragment[11], fragment[12] = nativeData, 0x10, 0
	if _, err := tx.seal(nil, fragment); err != nil {
		t.Fatal(err)
	}
	if !tx.policy.bulk {
		t.Fatal("fragmented bulk did not disable padding")
	}
}

func TestProbeFailuresHaveNoResponse(t *testing.T) {
	config := testConfig(t, "", "")
	server, _ := NewServer(config, []User{{ID: 1, Key: testKey(2)}})
	for _, user := range []User{{ID: 1, Key: testKey(9)}, {ID: 99, Key: testKey(2)}} {
		client, _ := NewClient(config, user)
		transport := &memoryConn{input: bytes.NewReader(captureRequest(t, client))}
		conn, _, _, err := server.Accept(transport)
		if !errors.Is(err, ErrAuthentication) || conn != nil || transport.output.Len() != 0 {
			t.Fatal("authentication leaked a response", err)
		}
		// Unknown IDs and wrong keys must both consume the authenticated AEAD length field.
		if transport.input.Size()-int64(transport.input.Len()) != IVSize+18 {
			t.Fatal("different authentication path")
		}
	}
	for _, obfs := range []string{"plain", "tls1.2_ticket_auth"} {
		config, _ := NewConfigWithObfs("", "", testKey(1), obfs, "")
		server, _ := NewServer(config, []User{{ID: 1, Key: testKey(2)}})
		for _, probe := range [][]byte{bytes.Repeat([]byte{0}, 100), []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), {0x16, 3, 1, 0xff, 0xff}} {
			transport := &memoryConn{input: bytes.NewReader(probe)}
			if _, _, _, err := server.Accept(transport); !errors.Is(err, ErrAuthentication) || transport.output.Len() != 0 {
				t.Fatal("probe response", err)
			}
		}
	}
}

func TestHandshakeReadCapAndTimeout(t *testing.T) {
	transport := &memoryConn{input: bytes.NewReader(make([]byte, maxHandshakeBytes+1))}
	g := newHandshakeGuard(transport, time.Second)
	_, err := io.Copy(io.Discard, g)
	if !errors.Is(err, errHandshakeLimit) || transport.input.Len() != 1 {
		t.Fatal("read budget not enforced", err)
	}
	g.finish()
	// The cap is removed after admission, preserving data already read ahead.
	if _, err := g.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	g = newHandshakeGuard(b, 20*time.Millisecond)
	if _, err := g.Read(make([]byte, 1)); err == nil || g.finish() {
		t.Fatal("slow handshake accepted")
	}
	a2, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	g2 := newHandshakeGuard(b2, 20*time.Millisecond)
	if !g2.finish() {
		t.Fatal("premature expiry")
	}
	time.Sleep(40 * time.Millisecond)
	_ = a2.SetDeadline(time.Now().Add(time.Second))
	go a2.Write([]byte{1})
	if _, err := g2.Read(make([]byte, 1)); err != nil {
		t.Fatal("timer closed authenticated connection", err)
	}
}

func TestHandshakeAdmissionLimit(t *testing.T) {
	_, server := testPeers(t, "", "", 1)
	for i := 0; i < maxPendingHandshakes; i++ {
		server.pending <- struct{}{}
	}
	transport := &memoryConn{input: bytes.NewReader(make([]byte, 100))}
	if _, _, _, err := server.Accept(transport); !errors.Is(err, ErrAuthentication) || transport.input.Len() != 100 || transport.output.Len() != 0 {
		t.Fatal("admission limit did work", err)
	}
	for i := 0; i < maxPendingHandshakes; i++ {
		<-server.pending
	}
}

// An attacker holding credentials still cannot send unbounded empty framing
// records before presenting a destination. No accepted connection escapes.
func TestHandshakeEmptyFrameFlood(t *testing.T) {
	config := testConfig(t, "", "auth_sha1_v4")
	key, _ := decodeKey(testKey(2))
	iv, _ := config.makeIV(1, time.Now())
	var request bytes.Buffer
	request.Write(iv)
	writer := shadowaead.NewWriter(fullWriter{&request}, config.payloadCipher(key, iv, "request"), shadowaead.MaxPacketSize)
	for i := 0; i < 2000; i++ {
		frame, err := encodeSSRPadding(nil, key, iv, i == 0, time.Now(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	server, _ := NewServer(config, []User{{ID: 1, Key: testKey(2)}})
	transport := &memoryConn{input: bytes.NewReader(request.Bytes())}
	if conn, _, _, err := server.Accept(transport); conn != nil || !errors.Is(err, ErrAuthentication) || transport.output.Len() != 0 {
		t.Fatal("empty flood accepted", err)
	}
	consumed := int(transport.input.Size()) - transport.input.Len()
	if consumed != maxHandshakeBytes {
		t.Fatal("unbounded handshake", consumed)
	}
	if len(server.pending) != 0 {
		t.Fatal("admission slot leaked")
	}
}

func TestNativeControlPreservesInitialApplicationPadding(t *testing.T) {
	config := testConfig(t, "", "")
	tx := newNativeCipher(config, make([]byte, 48), "request")
	control := make([]byte, 32)
	control[0] = nativeProbe
	for i := 0; i < 12; i++ {
		if _, err := tx.seal(nil, control); err != nil {
			t.Fatal(err)
		}
	}
	if tx.policy.records != 0 || tx.policy.allowance.remaining.Load() >= 1024 {
		t.Fatal("control must spend bytes but preserve application count")
	}
	for i := 0; i < 12; i++ {
		packet, err := tx.seal(nil, bytes.Repeat([]byte{99}, 64))
		if err != nil {
			t.Fatal(err)
		}
		extra := len(packet) - nativeHeader - nativeEnvelope - 16 - 64
		if i >= 8 && extra != 0 {
			t.Fatal("default UDP padding continued", extra)
		}
	}
}
