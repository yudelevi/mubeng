package proxymanager

import (
	"fmt"
	"math/rand"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/mubeng/mubeng/common/errors"
	"github.com/mubeng/mubeng/pkg/helper"
)

// Count counts total proxies
func (p *ProxyManager) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Length = len(p.Proxies)

	return p.Length
}

// NextProxy will navigate the next proxy to use
func (p *ProxyManager) NextProxy() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var proxy string

	count := len(p.Proxies)
	p.Length = count
	if count <= 0 {
		return proxy, errors.ErrNoProxyLeft
	}

	p.CurrentIndex++
	if p.CurrentIndex > count-1 {
		p.CurrentIndex = 0
	}

	proxy = p.Proxies[p.CurrentIndex]

	return proxy, nil
}

// RandomProxy will choose a proxy randomly from the list
func (p *ProxyManager) RandomProxy() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var proxy string

	count := len(p.Proxies)
	p.Length = count
	if count <= 0 {
		return proxy, errors.ErrNoProxyLeft
	}

	proxy = p.Proxies[rand.Intn(count)]

	return proxy, nil
}

// RemoveProxy removes target proxy from proxy pool
func (p *ProxyManager) RemoveProxy(target string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, v := range p.Proxies {
		if v == target {
			p.Proxies = append(p.Proxies[:i], p.Proxies[i+1:]...)
			p.Length = len(p.Proxies)
			p.generation++

			return nil
		}
	}

	return fmt.Errorf("could not find %q in the proxy pool", target)
}

// Rotate proxy based on method
//
// Valid methods are "sequent" and "random", default return empty string.
func (p *ProxyManager) Rotate(method string) (string, error) {
	var proxy string
	var err error

	switch method {
	case "sequent":
		proxy, err = p.NextProxy()
	case "random":
		proxy, err = p.RandomProxy()
	}

	if proxy != "" {
		proxy = helper.EvalFunc(proxy)
	}

	return proxy, err
}

// Watch proxy file from events
func (p *ProxyManager) Watch() (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return watcher, err
	}

	if err := watcher.Add(filepath.Dir(p.filepath)); err != nil {
		_ = watcher.Close()
		return nil, err
	}

	return watcher, nil
}

// Reload proxy pool
func (p *ProxyManager) Reload() error {
	fresh, err := New(p.filepath)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.Proxies = fresh.Proxies
	p.Length = len(p.Proxies)
	p.CurrentIndex = -1
	p.generation++

	return nil
}

// Generation changes when the upstream list is replaced or a proxy is removed.
func (p *ProxyManager) Generation() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation
}
