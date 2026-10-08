package server

import (
	"github.com/mubeng/mubeng/common"
	"github.com/mubeng/mubeng/internal/proxymanager"
	"testing"
)

func TestPoolRotationIsolation(t *testing.T) {
	makeProxy := func(proxies []string) *Proxy {
		return &Proxy{Options: &common.Options{Rotate: 2, Method: "sequent", ProxyManager: &proxymanager.ProxyManager{CurrentIndex: -1, Proxies: proxies}}}
	}
	a := makeProxy([]string{"http://127.0.0.1:9001", "http://127.0.0.1:9002"})
	b := makeProxy([]string{"http://127.0.0.1:9011", "http://127.0.0.1:9012"})
	for i, want := range []string{"http://127.0.0.1:9001", "http://127.0.0.1:9001", "http://127.0.0.1:9002"} {
		if got := a.rotateProxy(); got != want {
			t.Fatalf("request %d: got %s want %s", i, got, want)
		}
		if i == 0 {
			if got := b.rotateProxy(); got != "http://127.0.0.1:9011" {
				t.Fatal(got)
			}
		}
	}
	if got := b.rotateProxy(); got != "http://127.0.0.1:9011" {
		t.Fatal("other pool advanced", got)
	}
}

func TestPoolRotationInvalidatesRemovedProxy(t *testing.T) {
	pm := &proxymanager.ProxyManager{CurrentIndex: -1, Proxies: []string{"http://127.0.0.1:9001", "http://127.0.0.1:9002"}}
	p := &Proxy{Options: &common.Options{Rotate: 100, Method: "sequent", ProxyManager: pm}}
	first := p.rotateProxy()
	if err := pm.RemoveProxy(first); err != nil {
		t.Fatal(err)
	}
	if got := p.rotateProxy(); got == first || got == "" {
		t.Fatalf("invalid next proxy %q", got)
	}
	if err := pm.RemoveProxy("http://127.0.0.1:9002"); err != nil {
		t.Fatal(err)
	}
	if got := p.rotateProxy(); got != "" {
		t.Fatalf("empty pool returned %q", got)
	}
}

func TestEmptyPoolCannotDial(t *testing.T) {
	p := &Proxy{}
	if conn, err := p.dialUpstream("", "tcp", "example.com:443"); err == nil || conn != nil {
		t.Fatal("empty upstream must fail before attempting any dial")
	}
}
