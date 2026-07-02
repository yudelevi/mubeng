package proxymanager

import (
	"os"
	"sync"
	"testing"
	"time"
)

func stickyManager(t *testing.T, proxies ...string) *ProxyManager {
	t.Helper()
	f, err := os.CreateTemp("", "mubeng-sticky-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range proxies {
		if _, err := f.WriteString(p + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	mgr, err := New(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func TestStickyReusesPinForSameKey(t *testing.T) {
	mgr := stickyManager(t, "http://a:1", "http://b:2", "http://c:3")
	s := NewSticky(mgr, "random", time.Minute)
	defer s.Close()

	first, err := s.Get("alice")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := s.Get("alice")
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatalf("pin drifted: first=%q got=%q", first, got)
		}
	}
}

func TestStickyEmptyKeyBypassesPin(t *testing.T) {
	mgr := stickyManager(t, "http://a:1")
	s := NewSticky(mgr, "sequent", time.Minute)
	defer s.Close()

	if _, err := s.Get(""); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Fatalf("empty key must not pin; Len=%d", s.Len())
	}
}

func TestStickyDropForcesReRotate(t *testing.T) {
	mgr := stickyManager(t, "http://a:1", "http://b:2")
	s := NewSticky(mgr, "sequent", time.Minute)
	defer s.Close()

	a, _ := s.Get("k")
	s.Drop("k")
	b, _ := s.Get("k")
	// sequent rotation advances, so a re-pin after Drop yields the next entry
	if a == b {
		t.Fatalf("Drop did not force re-rotate: %q==%q", a, b)
	}
}

func TestStickyExpiryReRotates(t *testing.T) {
	mgr := stickyManager(t, "http://a:1", "http://b:2")
	s := NewSticky(mgr, "sequent", 20*time.Millisecond)
	defer s.Close()

	a, _ := s.Get("k")
	time.Sleep(40 * time.Millisecond)
	b, _ := s.Get("k")
	if a == b {
		t.Fatalf("expired pin was not re-rotated: %q==%q", a, b)
	}
}

// Concurrent first use of one key (browser opening parallel connections for a
// fresh session) must converge on a single pinned upstream.
func TestStickyConcurrentSameKeyOnePin(t *testing.T) {
	mgr := stickyManager(t, "http://a:1", "http://b:2", "http://c:3", "http://d:4")
	s := NewSticky(mgr, "random", time.Minute)
	defer s.Close()

	const n = 64
	var wg sync.WaitGroup
	results := make([]string, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			got, err := s.Get("race")
			if err != nil {
				t.Errorf("Get: %s", err)
				return
			}
			results[idx] = got
		}(i)
	}
	close(start)
	wg.Wait()

	first := results[0]
	for i, got := range results {
		if got != first {
			t.Fatalf("goroutine %d saw %q, want %q — session split across upstreams", i, got, first)
		}
	}
	if s.Len() != 1 {
		t.Fatalf("want exactly 1 pin, got %d", s.Len())
	}
}

func TestStickyCloseIsIdempotent(t *testing.T) {
	mgr := stickyManager(t, "http://a:1")
	s := NewSticky(mgr, "sequent", time.Minute)
	s.Close()
	s.Close() // must not panic
}

func TestStickyDistinctKeysAndOnChange(t *testing.T) {
	mgr := stickyManager(t, "http://a:1", "http://b:2", "http://c:3")
	s := NewSticky(mgr, "random", time.Minute)
	defer s.Close()

	var last int
	s.SetOnChange(func(n int) { last = n })

	_, _ = s.Get("alice")
	_, _ = s.Get("bob")
	if s.Len() != 2 {
		t.Fatalf("want 2 pins, got %d", s.Len())
	}
	if last != 2 {
		t.Fatalf("onChange last=%d, want 2", last)
	}
	s.Drop("alice")
	if s.Len() != 1 || last != 1 {
		t.Fatalf("after Drop: Len=%d last=%d", s.Len(), last)
	}
}
