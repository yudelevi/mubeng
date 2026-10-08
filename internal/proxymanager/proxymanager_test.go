package proxymanager

import (
	"os"
	"sync"
	"testing"
	"time"
)

func writeTemp(t *testing.T, lines string) string {
	t.Helper()

	f, err := os.CreateTemp("", "mubeng-pm-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(lines); err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	return f.Name()
}

func TestNewReturnsIndependentPools(t *testing.T) {
	a := writeTemp(t, "http://127.0.0.1:8080\nhttp://127.0.0.1:8081\n")
	b := writeTemp(t, "socks5://127.0.0.1:1080\nsocks5://127.0.0.1:1081\nsocks5://127.0.0.1:1082\n")

	pmA, err := New(a)
	if err != nil {
		t.Fatal(err)
	}
	pmB, err := New(b)
	if err != nil {
		t.Fatal(err)
	}

	if pmA == pmB {
		t.Fatal("expected independent ProxyManager instances, got the same pointer")
	}
	if pmA.Count() != 2 {
		t.Fatalf("pool A: want 2 proxies, got %d", pmA.Count())
	}
	if pmB.Count() != 3 {
		t.Fatalf("pool B: want 3 proxies, got %d", pmB.Count())
	}

	if got, _ := pmA.Rotate("sequent"); got != "http://127.0.0.1:8080" {
		t.Fatalf("pool A first rotate: want http://127.0.0.1:8080, got %q", got)
	}
	if got, _ := pmB.Rotate("sequent"); got != "socks5://127.0.0.1:1080" {
		t.Fatalf("pool B first rotate: want socks5://127.0.0.1:1080, got %q", got)
	}
	if pmA.CurrentIndex != 0 {
		t.Fatalf("rotating pool B must not advance pool A: pool A index = %d", pmA.CurrentIndex)
	}
}

func TestReloadPicksUpFileChanges(t *testing.T) {
	f := writeTemp(t, "http://127.0.0.1:8080\n")

	pm, err := New(f)
	if err != nil {
		t.Fatal(err)
	}
	if pm.Count() != 1 {
		t.Fatalf("want 1 proxy, got %d", pm.Count())
	}

	if err := os.WriteFile(f, []byte("http://127.0.0.1:8080\nhttp://127.0.0.1:8081\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pm.Reload(); err != nil {
		t.Fatal(err)
	}
	if pm.Count() != 2 {
		t.Fatalf("after reload: want 2 proxies on the same instance, got %d", pm.Count())
	}
}

func TestConcurrentReloadAndRotation(t *testing.T) {
	file := writeTemp(t, "http://127.0.0.1:8080\nhttp://127.0.0.1:8081\n")
	pm, err := New(file)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				if _, err := pm.Rotate("sequent"); err != nil {
					t.Error(err)
				}
				pm.Count()
			}
		}()
	}
	for n := 0; n < 100; n++ {
		if err := pm.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestStickyInvalidatesRemovedProxy(t *testing.T) {
	pm, err := New(writeTemp(t, "http://127.0.0.1:8080\nhttp://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatal(err)
	}
	sticky := NewSticky(pm, "sequent", time.Minute)
	defer sticky.Close()
	first, err := sticky.Get("session")
	if err != nil {
		t.Fatal(err)
	}
	if err := pm.RemoveProxy(first); err != nil {
		t.Fatal(err)
	}
	next, err := sticky.Get("session")
	if err != nil {
		t.Fatal(err)
	}
	if first == next {
		t.Fatal("removed upstream remains pinned")
	}
}
