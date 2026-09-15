package tf

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing/common/winiphlpapi"

	"golang.org/x/sys/windows"
)

func writeAndWaitAck(ctx context.Context, conn *net.TCPConn, payload []byte, fallbackDelay time.Duration) error {
	start := time.Now()
	err := winiphlpapi.WriteAndWaitAck(ctx, conn, payload)
	if err != nil {
		// EStats may be unavailable even for an administrator (for example on
		// loopback). Only retry failures before Write to avoid duplicating data.
		var syscallErr *os.SyscallError
		if errors.As(err, &syscallErr) && syscallErr.Syscall == "SetPerTcpConnectionEStatsSendBufferV0" &&
			(errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_NOT_SUPPORTED)) {
			if _, err := conn.Write(payload); err != nil {
				return err
			}
			time.Sleep(fallbackDelay)
			return nil
		}
		return err
	}
	if time.Since(start) <= 20*time.Millisecond {
		time.Sleep(fallbackDelay)
	}
	return nil
}
