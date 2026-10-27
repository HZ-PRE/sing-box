package memorystats

import "testing"

func TestSampleHasNoPerPollAllocation(t *testing.T) {
	snapshot := Read()
	if snapshot.GoCommittedBytes == 0 || snapshot.Goroutines == 0 {
		t.Fatal("empty runtime sample")
	}
	if snapshot.HeapObjectsBytes > snapshot.GoCommittedBytes {
		t.Fatal("heap exceeds Go committed memory")
	}
	if n := testing.AllocsPerRun(100, func() { Read() }); n != 0 {
		t.Fatalf("poll allocates: %v", n)
	}
}
