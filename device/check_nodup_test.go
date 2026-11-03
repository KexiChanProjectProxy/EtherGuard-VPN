package device

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fixed_time_cache "github.com/KusakabeSi/go-cache"
)

// Every peer's receiver goroutine calls CheckNoDup. A flooded packet that
// arrives from several peers at once must be accepted exactly once.
func TestCheckNoDupAcceptsConcurrentDuplicatesOnce(t *testing.T) {
	device := &Device{DupData: *fixed_time_cache.NewCache(time.Minute, false, 0)}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if device.CheckNoDup([]byte("flooded packet")) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted %d times, want 1", got)
	}
}
