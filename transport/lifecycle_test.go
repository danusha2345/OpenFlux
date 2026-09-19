package transport

import (
	"sync"
	"testing"
)

func TestBaseTransportStatsDuringRestart(t *testing.T) {
	tr := NewBaseTransport(DefaultConfig())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			tr.Start()
			tr.Stop()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if tr.Stats().Uptime < 0 {
				t.Error("negative uptime")
			}
		}
	}()
	wg.Wait()
}
