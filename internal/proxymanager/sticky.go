package proxymanager

import (
	"sync"
	"time"
)

const defaultStickyTTL = 10 * time.Minute

// Sticky pins one upstream per session key so every connection carrying that
// key egresses through the same proxy. It wraps a ProxyManager: on a miss it
// rotates a fresh upstream and pins the concrete (already EvalFunc-expanded)
// URL, reusing it verbatim until the pin idles past ttl or is dropped.
type Sticky struct {
	mgr    *ProxyManager
	method string
	ttl    time.Duration

	mu       sync.Mutex
	pins     map[string]*stickyPin
	onChange func(n int)

	stop chan struct{}
}

type stickyPin struct {
	upstream string
	expires  time.Time
}

// NewSticky starts a store with a background janitor sweeping idle pins.
func NewSticky(mgr *ProxyManager, method string, ttl time.Duration) *Sticky {
	if ttl <= 0 {
		ttl = defaultStickyTTL
	}
	s := &Sticky{
		mgr:    mgr,
		method: method,
		ttl:    ttl,
		pins:   make(map[string]*stickyPin),
		stop:   make(chan struct{}),
	}
	go s.janitor()

	return s
}

// SetOnChange registers a callback fired with the live pin count whenever a pin
// is added, dropped, or swept. Used to drive the sticky_pins metric.
func (s *Sticky) SetOnChange(fn func(n int)) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

// Get returns the pinned upstream for key, rotating and pinning a fresh one on a
// miss or an expired pin. An empty key bypasses pinning entirely, preserving the
// rotate-every-connection default.
func (s *Sticky) Get(key string) (string, error) {
	if key == "" {
		return s.mgr.Rotate(s.method)
	}

	now := time.Now()

	s.mu.Lock()
	if pin, ok := s.pins[key]; ok && now.Before(pin.expires) {
		pin.expires = now.Add(s.ttl)
		upstream := pin.upstream
		s.mu.Unlock()
		return upstream, nil
	}
	s.mu.Unlock()

	upstream, err := s.mgr.Rotate(s.method)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.pins[key] = &stickyPin{upstream: upstream, expires: now.Add(s.ttl)}
	n := len(s.pins)
	cb := s.onChange
	s.mu.Unlock()

	if cb != nil {
		cb(n)
	}

	return upstream, nil
}

// Drop removes the pin for key so the next Get re-rotates — rotate-on-error per
// session.
func (s *Sticky) Drop(key string) {
	if key == "" {
		return
	}

	s.mu.Lock()
	_, existed := s.pins[key]
	delete(s.pins, key)
	n := len(s.pins)
	cb := s.onChange
	s.mu.Unlock()

	if existed && cb != nil {
		cb(n)
	}
}

// Len reports the current pin count.
func (s *Sticky) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.pins)
}

// Close stops the janitor.
func (s *Sticky) Close() {
	close(s.stop)
}

func (s *Sticky) janitor() {
	ticker := time.NewTicker(s.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

func (s *Sticky) sweep() {
	now := time.Now()

	s.mu.Lock()
	for key, pin := range s.pins {
		if now.After(pin.expires) {
			delete(s.pins, key)
		}
	}
	n := len(s.pins)
	cb := s.onChange
	s.mu.Unlock()

	if cb != nil {
		cb(n)
	}
}
