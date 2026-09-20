package geosite

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/sagernet/sing/common/varbin"
)

func Write(writer varbin.Writer, domains map[string][]Item) error {
	keys := make([]string, 0, len(domains))
	for code := range domains {
		keys = append(keys, code)
	}
	sort.Strings(keys)

	content := &bytes.Buffer{}
	index := make(map[string]int)
	for _, code := range keys {
		index[code] = content.Len()
		for _, item := range domains[code] {
			err := content.WriteByte(item.Type)
			if err == nil {
				err = writeString(content, item.Value)
			}
			if err != nil {
				return err
			}
		}
	}

	err := writer.WriteByte(0)
	if err != nil {
		return err
	}

	_, err = varbin.WriteUvarint(writer, uint64(len(keys)))
	if err != nil {
		return err
	}

	for _, code := range keys {
		err = writeString(writer, code)
		if err != nil {
			return err
		}
		_, err = varbin.WriteUvarint(writer, uint64(index[code]))
		if err != nil {
			return err
		}
		_, err = varbin.WriteUvarint(writer, uint64(len(domains[code])))
		if err != nil {
			return err
		}
	}

	n, err := writer.Write(content.Bytes())
	if err != nil {
		return err
	}

	if n != content.Len() {
		return io.ErrShortWrite
	}
	return nil
}

func writeString(writer varbin.Writer, value string) error {
	if len(value) > 1<<20 {
		return fmt.Errorf("geosite string exceeds 1 MiB")
	}
	if _, err := varbin.WriteUvarint(writer, uint64(len(value))); err != nil {
		return err
	}
	n, err := writer.Write([]byte(value))
	if err == nil && n != len(value) {
		return io.ErrShortWrite
	}
	return err
}
