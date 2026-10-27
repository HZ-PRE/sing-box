package diagnostics

import (
	"context"
	"runtime/pprof"
	"testing"
	"testing/synctest"
)

func TestTasksReleaseAndUseConstantLabels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		Go(ctx, DNSRefresh, func(ctx context.Context) {
			if label, ok := pprof.Label(ctx, "module"); !ok || label != "dns_refresh" {
				t.Error("missing module label")
			}
			<-ctx.Done()
		})
		synctest.Wait()
		if ActiveTasks()["dns_refresh"] != 1 {
			t.Fatal("missing active task")
		}
		cancel()
		synctest.Wait()
		if ActiveTasks()["dns_refresh"] != 0 {
			t.Fatal("task counter leaked")
		}
	})
}
