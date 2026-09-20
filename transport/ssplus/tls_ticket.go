package ssplus

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// SSR tls1.2_ticket_auth is an authenticated TLS-shaped record wrapper, not TLS.
// Its key is SS+'s shared IVKey, available before multi-user IV authentication.
var errTicket = errors.New("ssplus: invalid tls1.2_ticket_auth handshake or record")

const maxTLSRecord = 16384

func ticketMAC(key, sessionID, data []byte) []byte {
	k := append(append([]byte(nil), key...), sessionID...)
	h := hmac.New(sha1.New, k)
	h.Write(data)
	return h.Sum(nil)[:10]
}

func ticketRandom(key, sessionID []byte) ([]byte, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data[:22]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(data, uint32(time.Now().Unix()))
	copy(data[22:], ticketMAC(key, sessionID, data[:22]))
	return data, nil
}

func validTicketRandom(key, sessionID, data []byte) bool {
	if len(data) != 32 || !hmac.Equal(data[22:], ticketMAC(key, sessionID, data[:22])) {
		return false
	}
	ts := int64(binary.BigEndian.Uint32(data))
	now := time.Now()
	return ts >= now.Add(-clockWindow).Unix() && ts <= now.Add(clockWindow).Unix()
}

func tlsRecord(kind byte, version uint16, payload []byte) []byte {
	data := make([]byte, 5+len(payload))
	data[0] = kind
	binary.BigEndian.PutUint16(data[1:], version)
	binary.BigEndian.PutUint16(data[3:], uint16(len(payload)))
	copy(data[5:], payload)
	return data
}

func readTLSRecord(r io.Reader) ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[3:]))
	if size == 0 || size > maxTLSRecord {
		return nil, errTicket
	}
	data := make([]byte, 5+size)
	copy(data, header[:])
	if _, err := io.ReadFull(r, data[5:]); err != nil {
		return nil, err
	}
	return data, nil
}

func handshakeRecord(kind byte, version uint16, body []byte) []byte {
	p := make([]byte, 4+len(body))
	p[0] = kind
	binary.BigEndian.PutUint16(p[2:], uint16(len(body)))
	copy(p[4:], body)
	return tlsRecord(0x16, version, p)
}

func fixedHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func makeClientHello(key, sessionID []byte, host string) ([]byte, error) {
	random, err := ticketRandom(key, sessionID)
	if err != nil {
		return nil, err
	}
	body := append([]byte{3, 3}, random...)
	body = append(body, 32)
	body = append(body, sessionID...)
	body = append(body, fixedHex("001cc02bc02fcca9cca8cc14cc13c00ac014c009c013009c0035002f000a0100")...)
	ext := fixedHex("ff01000100")
	if host != "" {
		sni := make([]byte, 9+len(host))
		binary.BigEndian.PutUint16(sni[2:], uint16(5+len(host)))
		binary.BigEndian.PutUint16(sni[4:], uint16(3+len(host)))
		binary.BigEndian.PutUint16(sni[7:], uint16(len(host)))
		copy(sni[9:], host)
		ext = append(ext, sni...)
	}
	ext = append(ext, 0, 0x17, 0, 0)
	ticket := make([]byte, 192)
	if _, err := rand.Read(ticket); err != nil {
		return nil, err
	}
	ext = append(ext, 0, 0x23, 0, 192)
	ext = append(ext, ticket...)
	ext = append(ext, fixedHex("000d0016001406010603050105030401040303010303020102030005000501000000000012000075500000000b00020100000a0006000400170018")...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	return handshakeRecord(1, 0x0301, body), nil
}

func parseHello(record []byte, kind byte) (random, sessionID []byte, err error) {
	version := uint16(0x0303)
	if kind == 1 {
		version = 0x0301
	}
	if len(record) < 76 || len(record) > 4096 || record[0] != 0x16 || binary.BigEndian.Uint16(record[1:]) != version ||
		record[5] != kind || record[6] != 0 || int(binary.BigEndian.Uint16(record[7:])) != len(record)-9 ||
		record[9] != 3 || record[10] != 3 || record[43] != 32 {
		return nil, nil, errTicket
	}
	return record[11:43], record[44:76], nil
}

func makeFinished(key, sessionID, transcript []byte) ([]byte, error) {
	ccs := []byte{0x14, 3, 3, 0, 1, 1}
	data := make([]byte, 32)
	if _, err := rand.Read(data[:22]); err != nil {
		return nil, err
	}
	flight := append(ccs, tlsRecord(0x16, 0x0303, data)...)
	macData := append(append([]byte(nil), transcript...), flight[:len(flight)-10]...)
	copy(flight[len(flight)-10:], ticketMAC(key, sessionID, macData))
	return flight, nil
}

func readFinished(conn net.Conn, key, sessionID, transcript, ccs []byte) error {
	if !bytes.Equal(ccs, []byte{0x14, 3, 3, 0, 1, 1}) {
		return errTicket
	}
	finished, err := readTLSRecord(conn)
	if err != nil {
		return err
	}
	if finished[0] != 0x16 || finished[1] != 3 || finished[2] != 3 || (len(finished) != 37 && len(finished) != 45) {
		return errTicket
	}
	macData := append(append(append([]byte(nil), transcript...), ccs...), finished[:len(finished)-10]...)
	if !hmac.Equal(finished[len(finished)-10:], ticketMAC(key, sessionID, macData)) {
		return errTicket
	}
	return nil
}

func clientTicketHandshake(conn net.Conn, key []byte, host string) (net.Conn, error) {
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, err
	}
	hello, err := makeClientHello(key, sessionID, host)
	if err != nil {
		return nil, err
	}
	if err := writeFull(conn, hello); err != nil {
		return nil, err
	}
	serverHello, err := readTLSRecord(conn)
	if err != nil {
		return nil, err
	}
	random, returnedID, err := parseHello(serverHello, 2)
	if err != nil || !bytes.Equal(sessionID, returnedID) || !validTicketRandom(key, sessionID, random) {
		return nil, errTicket
	}
	transcript := serverHello
	next, err := readTLSRecord(conn)
	if err != nil {
		return nil, err
	}
	// The original SSR server may emit one NewSessionTicket record.
	if next[0] == 0x16 {
		if next[1] != 3 || next[2] != 3 || len(next) > 1024 || len(next) < 11 || next[5] != 4 || next[6] != 0 {
			return nil, errTicket
		}
		transcript = append(transcript, next...)
		next, err = readTLSRecord(conn)
		if err != nil {
			return nil, err
		}
	}
	if err := readFinished(conn, key, sessionID, transcript, next); err != nil {
		return nil, err
	}
	finished, err := makeFinished(key, sessionID, nil)
	if err != nil {
		return nil, err
	}
	if err := writeFull(conn, finished); err != nil {
		return nil, err
	}
	return &ticketConn{Conn: conn}, nil
}

func (s *Server) serverTicketHandshake(conn net.Conn) (net.Conn, error) {
	hello, err := readTLSRecord(conn)
	if err != nil {
		return nil, err
	}
	random, sessionID, err := parseHello(hello, 1)
	if err != nil || !validTicketRandom(s.config.ivKey, sessionID, random) {
		return nil, errTicket
	}
	// Namespace the token and retain it across user synchronization, just like IVs.
	token := sha512.Sum384(append([]byte("ssplus/v1/tls-ticket/"), random...))
	if !s.remember(token[:], time.Now()) {
		return nil, ErrAuthentication
	}
	serverRandom, err := ticketRandom(s.config.ivKey, sessionID)
	if err != nil {
		return nil, err
	}
	body := append([]byte{3, 3}, serverRandom...)
	body = append(body, 32)
	body = append(body, sessionID...)
	body = append(body, fixedHex("c02f000005ff01000100")...)
	serverHello := handshakeRecord(2, 0x0303, body)
	finished, err := makeFinished(s.config.ivKey, sessionID, serverHello)
	if err != nil {
		return nil, err
	}
	if err := writeFull(conn, append(serverHello, finished...)); err != nil {
		return nil, err
	}
	ccs, err := readTLSRecord(conn)
	if err != nil {
		return nil, err
	}
	if err := readFinished(conn, s.config.ivKey, sessionID, nil, ccs); err != nil {
		return nil, err
	}
	return &ticketConn{Conn: conn}, nil
}

type ticketConn struct {
	net.Conn
	pending               []byte
	readMutex, writeMutex sync.Mutex
	readErr, writeErr     error
}

func (c *ticketConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(c.pending) == 0 {
		record, err := readTLSRecord(c.Conn)
		if err == nil && (record[0] != 0x17 || record[1] != 3 || record[2] != 3) {
			err = errTicket
		}
		if err != nil {
			c.readErr = err
			return 0, err
		}
		c.pending = record[5:]
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *ticketConn) Write(p []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	total := 0
	for len(p) > 0 {
		size := min(len(p), 4096)
		if err := writeFull(c.Conn, tlsRecord(0x17, 0x0303, p[:size])); err != nil {
			c.writeErr = err
			return total, err
		}
		total += size
		p = p[size:]
	}
	return total, nil
}
