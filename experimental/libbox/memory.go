package libbox

import (
	"math"
	runtimeDebug "runtime/debug"

	"github.com/sagernet/sing-box/common/conntrack"
	C "github.com/sagernet/sing-box/constant"
)

func SetMemoryLimit(enabled bool) {
	var memoryLimit uint64 = 45 * 1024 * 1024
	if !C.IsIos {
		memoryLimit = 1024 * 1024 * 1024
	}
	var memoryLimitGo = memoryLimit * 2 / 3
	if enabled {
		runtimeDebug.SetGCPercent(10)
		runtimeDebug.SetMemoryLimit(int64(memoryLimitGo))
		conntrack.KillerEnabled = true
		conntrack.MemoryLimit = memoryLimit
	} else {
		runtimeDebug.SetGCPercent(100)
		runtimeDebug.SetMemoryLimit(math.MaxInt64)
		conntrack.KillerEnabled = false
	}
}
