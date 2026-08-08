package sniff

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"

	"github.com/HZ-PRE/sing-box/adapter"
	C "github.com/HZ-PRE/sing-box/constant"
)

func SSH(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		return os.ErrInvalid
	}
	fistLine := scanner.Text()
	if !strings.HasPrefix(fistLine, "SSH-2.0-") {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolSSH
	metadata.Client = fistLine[8:]
	return nil
}
