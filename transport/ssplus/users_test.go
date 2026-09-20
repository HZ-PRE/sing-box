package ssplus

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestManagedUsers(t *testing.T) {
	client, _ := testPeers(t, "", "", 1)
	s, err := NewManagedServer(client.config, nil)
	if err != nil {
		t.Fatal(err)
	}
	accept := func(request []byte) error {
		_, _, _, err := s.Accept(&memoryConn{input: bytes.NewReader(request)})
		return err
	}
	u := User{ID: 1, Key: testKey(2), Name: "alice"}
	req := captureRequest(t, client)
	if accept(req) == nil {
		t.Fatal("empty server accepted user")
	}
	if err := s.AddUser(u); err != nil {
		t.Fatal(err)
	}
	if err := accept(req); err != nil {
		t.Fatal(err)
	}
	s.RemoveUser(1)
	if accept(captureRequest(t, client)) == nil {
		t.Fatal("removed user accepted")
	}
	if err := s.AddUser(u); err != nil {
		t.Fatal(err)
	}
	if accept(req) == nil {
		t.Fatal("user synchronization reset replay cache")
	}
	s.RemoveUser(1)
	u.Key = testKey(3)
	if err := s.AddUser(u); err != nil {
		t.Fatal(err)
	}
	if accept(captureRequest(t, client)) == nil {
		t.Fatal("old key accepted")
	}
	newClient, _ := NewClient(client.config, u)
	if err := accept(captureRequest(t, newClient)); err != nil {
		t.Fatal(err)
	}
}

type pausedPayload struct {
	net.Conn
	ready, resume chan struct{}
	first         bool
}

func (c *pausedPayload) Read(p []byte) (int, error) {
	if !c.first {
		c.first = true
		return c.Conn.Read(p)
	}
	if c.ready != nil {
		close(c.ready)
		<-c.resume
		c.ready = nil
	}
	return c.Conn.Read(p)
}

func TestRemoveDuringHandshake(t *testing.T) {
	client, s := testPeers(t, "", "", 1)
	request := captureRequest(t, client)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	ready, resume := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() { _, _, _, err := s.Accept(&pausedPayload{Conn: b, ready: ready, resume: resume}); result <- err }()
	go func() { io.Copy(a, bytes.NewReader(request)); a.Close() }()
	<-ready
	s.RemoveUser(1)
	// Even re-adding identical credentials must invalidate the in-flight snapshot.
	if err := s.AddUser(User{ID: 1, Key: testKey(2)}); err != nil {
		t.Fatal(err)
	}
	close(resume)
	if err := <-result; err == nil {
		t.Fatal("removed in-flight account accepted")
	}
}

func TestConcurrentUserUpdates(t *testing.T) {
	client, s := testPeers(t, "", "", 1)
	request := captureRequest(t, client)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.RemoveUser(1)
				s.AddUser(User{ID: 1, Key: testKey(2)})
				s.Accept(&memoryConn{input: bytes.NewReader(request)})
			}
		}()
	}
	wg.Wait()
}
