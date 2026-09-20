package geosite

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
	"sync"
	"sync/atomic"

	E "github.com/sagernet/sing/common/exceptions"
)

type Reader struct {
	access         sync.Mutex
	reader         io.ReadSeeker
	bufferedReader *bufio.Reader
	metadataIndex  int64
	domainIndex    map[string]int
	domainLength   map[string]int
}

func Open(path string) (*Reader, []string, error) {
	content, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	reader, codes, err := NewReader(content)
	if err != nil {
		content.Close()
		return nil, nil, err
	}
	return reader, codes, nil
}

func NewReader(readSeeker io.ReadSeeker) (*Reader, []string, error) {
	reader := &Reader{
		reader: readSeeker,
	}
	err := reader.readMetadata()
	if err != nil {
		return nil, nil, err
	}
	codes := make([]string, 0, len(reader.domainIndex))
	for code := range reader.domainIndex {
		codes = append(codes, code)
	}
	return reader, codes, nil
}

func (r *Reader) readMetadata() error {
	counter := &readCounter{Reader: r.reader}
	reader := bufio.NewReader(counter)
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if version != 0 {
		return E.New("unknown version")
	}
	entryLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	domainIndex := make(map[string]int)
	domainLength := make(map[string]int)
	for i := uint64(0); i < entryLength; i++ {
		var (
			code       string
			codeIndex  uint64
			codeLength uint64
		)
		code, err = readString(reader)
		if err != nil {
			return err
		}
		codeIndex, err = binary.ReadUvarint(reader)
		if err != nil {
			return err
		}
		codeLength, err = binary.ReadUvarint(reader)
		if err != nil {
			return err
		}
		if codeIndex > uint64(^uint(0)>>1) || codeLength > uint64(^uint(0)>>1) {
			return E.New("geosite index overflow")
		}
		domainIndex[code] = int(codeIndex)
		domainLength[code] = int(codeLength)
	}
	r.domainIndex = domainIndex
	r.domainLength = domainLength
	r.metadataIndex = counter.count - int64(reader.Buffered())
	r.bufferedReader = reader
	return nil
}

func (r *Reader) Read(code string) ([]Item, error) {
	r.access.Lock()
	defer r.access.Unlock()

	index, exists := r.domainIndex[code]
	if !exists {
		return nil, E.New("code ", code, " not exists!")
	}
	_, err := r.reader.Seek(r.metadataIndex+int64(index), io.SeekStart)
	if err != nil {
		return nil, err
	}
	r.bufferedReader.Reset(r.reader)
	itemList := make([]Item, 0)
	for i := 0; i < r.domainLength[code]; i++ {
		itemType, err := r.bufferedReader.ReadByte()
		if err != nil {
			return nil, err
		}
		value, err := readString(r.bufferedReader)
		if err != nil {
			return nil, err
		}
		itemList = append(itemList, Item{Type: itemType, Value: value})
	}
	return itemList, nil
}

func readString(reader *bufio.Reader) (string, error) {
	length, err := binary.ReadUvarint(reader)
	if err != nil {
		return "", err
	}
	// Domain names and regex rules are small. Bound untrusted lengths before allocation.
	if length > 1<<20 {
		return "", E.New("geosite string exceeds 1 MiB")
	}
	value := make([]byte, int(length))
	_, err = io.ReadFull(reader, value)
	return string(value), err
}

func (r *Reader) Upstream() any {
	return r.reader
}

type readCounter struct {
	io.Reader
	count int64
}

func (r *readCounter) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if n > 0 {
		atomic.AddInt64(&r.count, int64(n))
	}
	return
}
