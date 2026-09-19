package l3

import (
	"testing"
	"time"
)

func TestStatsLoopStopsWithConntrack(t *testing.T) {
	tr := &L3Exit{ct: newConntrack()}
	done := make(chan struct{})
	go func() { tr.statsLoop(); close(done) }()
	tr.ct.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stats loop survived Stop")
	}
}
