package locksmith

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestDiskCacheConcurrency(t *testing.T) {
	mockKey := make([]byte, 32)
	cache, err := NewDiskCache(mockKey)
	if err != nil {
		t.Fatalf("Failed to create disk cache: %v", err)
	}

	const iterations = 50
	const workers = 10
	var wg sync.WaitGroup

	// Stress test concurrent writes to different keys
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				key := fmt.Sprintf("worker-%d-key-%d", workerID, j)
				secret := Secret{Value: []byte("v")}
				_ = cache.Set(key, secret, time.Hour)
				_, _ = cache.Get(key)
				_ = cache.Delete(key)
			}
		}(i)
	}

	wg.Wait()
}

func TestDiskCacheSharedKeyConcurrency(t *testing.T) {
	mockKey := make([]byte, 32)
	cache, _ := NewDiskCache(mockKey)
	key := "shared-key"
	const iterations = 100
	var wg sync.WaitGroup

	wg.Add(2)

	// One worker writes
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = cache.Set(key, Secret{Value: []byte(fmt.Sprintf("val-%d", i))}, time.Hour)
		}
	}()

	// Another worker reads
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_, _ = cache.Get(key)
		}
	}()

	wg.Wait()
	_ = cache.Delete(key)
}
