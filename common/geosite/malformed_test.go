package geosite

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestReadStringRejectsOversizedAndTruncatedInput(t *testing.T) {
	var oversized bytes.Buffer
	var length [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(length[:], 1<<30)
	oversized.Write(length[:n])
	if _, err := readString(bufio.NewReader(&oversized)); err == nil {
		t.Fatal("accepted oversized string")
	}
	if _, err := readString(bufio.NewReader(bytes.NewReader([]byte{3, 'a'}))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected truncation error, got %v", err)
	}
}

type shortStringWriter struct{}

func (shortStringWriter) WriteByte(byte) error        { return nil }
func (shortStringWriter) Write(p []byte) (int, error) { return 0, nil }

func TestWriteStringRejectsShortWrites(t *testing.T) {
	if err := writeString(shortStringWriter{}, "example.com"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected short write error, got %v", err)
	}
}
