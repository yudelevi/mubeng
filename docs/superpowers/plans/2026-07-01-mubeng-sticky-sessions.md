# mubeng Sticky Sessions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opt-in `-sticky` mode that pins one upstream exit IP per session key, for the HTTP and SOCKS listeners and SOCKS UDP ASSOCIATE, so Cloudflare challenge→clearance keeps one egress IP.

**Architecture:** A new `proxymanager.Sticky` maps a session key → a pinned (already-evaluated) upstream URL with an idle TTL, rotate-on-error via `Drop`, and a background janitor. The SOCKS session key is the RFC1929 username (new `negotiate()` method `0x02` support); the HTTP key is the `Proxy-Authorization` username. Two independent stores (one per pool) hang off `common.Options`, built by the server when `-sticky` is set. Default (flag absent) leaves today's rotate-per-connection behavior byte-for-byte unchanged.

**Tech Stack:** Go, `h12.io/socks`, `elazarl/goproxy`, `prometheus/client_golang`.

## Global Constraints

- Session key = username (SOCKS RFC1929 / HTTP `Proxy-Authorization: Basic`). Password is read but **never validated** — it is only a routing tag.
- Pin the **evaluated** URL returned by `ProxyManager.Rotate` (which runs `helper.EvalFunc`) and reuse it verbatim.
- Empty key ⇒ no pin ⇒ plain `Rotate` (today's behavior).
- `-sticky` + `-A`/`-auth` is a startup error.
- When per-context creds are set, cloakbrowser's Chromium offers **only** SOCKS method `0x02` — `negotiate()` must accept `0x02` and must not *require* `0x00`. Credential-less clients still offer `0x00`.
- Preserve: proxy-file watch/reload, `/metrics` pool size, UDP ASSOCIATE, and all `MaxRetries`/`MaxErrors`/`RotateOnErr`/`RemoveOnErr` semantics.
- Go style already in repo: table tests, `io.ReadFull`, byte-literal protocol handling, no mid-func helpers.

**Backward-compat guarantee (load-bearing — explicitly tested):** a connection with **no session key** must behave exactly as today, whether `-sticky` is off OR on. Two cases:
  1. `-sticky` off ⇒ `HTTPSticky`/`SocksSticky` are `nil` ⇒ every path takes the original `Rotate`/`rotateProxy` branch untouched.
  2. `-sticky` on but the connection carries no username (SOCKS no-auth `0x00`; HTTP with no `Proxy-Authorization`) ⇒ key is `""` ⇒ selection uses `Rotate`/`rotateProxy`, **no pin is created** (`Sticky.Len()` stays 0), and no `Drop` fires.
  Enforced by: `sticky := SocksSticky != nil && key != ""` in `dialViaSocksPool`; `pickProxy` returns `rotateProxy()` for empty key; `Sticky.Get("")` returns `Rotate` without recording a pin. Regression assertions live in Tasks 4 and 6 (no-auth ⇒ threaded key `""`; empty-key pick ⇒ `Len()==0`).

---

### Task 1: `proxymanager.Sticky` store

**Files:**
- Create: `internal/proxymanager/sticky.go`
- Test: `internal/proxymanager/sticky_test.go`

**Interfaces:**
- Consumes: `(*ProxyManager).Rotate(method string) (string, error)`.
- Produces:
  - `func NewSticky(mgr *ProxyManager, method string, ttl time.Duration) *Sticky`
  - `func (s *Sticky) Get(key string) (string, error)`
  - `func (s *Sticky) Drop(key string)`
  - `func (s *Sticky) Len() int`
  - `func (s *Sticky) Close()`
  - `func (s *Sticky) SetOnChange(fn func(n int))`

- [ ] **Step 1: Write failing tests** in `internal/proxymanager/sticky_test.go`:

```go
package proxymanager

import (
	"os"
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
```

- [ ] **Step 2: Run tests, verify they fail** — `go test ./internal/proxymanager/ -run TestSticky -v` → FAIL (undefined: NewSticky).

- [ ] **Step 3: Implement** `internal/proxymanager/sticky.go`:

```go
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
// miss or an expired pin. An empty key bypasses pinning entirely.
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
```

- [ ] **Step 4: Run tests, verify pass** — `go test ./internal/proxymanager/ -run TestSticky -v` → PASS.
- [ ] **Step 5: Commit** — `git add internal/proxymanager/sticky.go internal/proxymanager/sticky_test.go && git commit -m "feat(proxymanager): sticky session pin store"`

---

### Task 2: Options fields, CLI flags, validator gate

**Files:**
- Modify: `common/options.go`
- Modify: `internal/runner/options.go:78-83`
- Modify: `internal/runner/validator.go`
- Test: `internal/runner/validator_test.go` (create)

**Interfaces:**
- Produces on `common.Options`: `Sticky bool`, `StickyTTL time.Duration`, `HTTPSticky *proxymanager.Sticky`, `SocksSticky *proxymanager.Sticky`.

- [ ] **Step 1: Add fields** to `common/options.go` `Options` struct (imports already include `time` and `proxymanager`):

```go
	Sticky      bool
	StickyTTL   time.Duration
	HTTPSticky  *proxymanager.Sticky
	SocksSticky *proxymanager.Sticky
```

- [ ] **Step 2: Add flags** in `internal/runner/options.go` right after the `-no-mitm` flag (line 82):

```go
	flag.BoolVar(&opt.Sticky, "sticky", false, "")
	flag.DurationVar(&opt.StickyTTL, "sticky-ttl", 10*time.Minute, "")
```

- [ ] **Step 3: Write failing validator test** `internal/runner/validator_test.go`:

```go
package runner

import (
	"testing"

	"github.com/mubeng/mubeng/common"
)

func TestStickyRejectsAuth(t *testing.T) {
	opt := &common.Options{File: "/nonexistent", Sticky: true, Auth: "user:pass"}
	err := validate(opt)
	if err == nil || !contains(err.Error(), "sticky") {
		t.Fatalf("want sticky+auth error, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 4: Run, verify fail** — `go test ./internal/runner/ -run TestStickyRejectsAuth -v` → FAIL (no error / wrong message).

- [ ] **Step 5: Add the gate** near the top of `validate()` in `internal/runner/validator.go`, right after the `hasStdin()` block (before the `opt.File == ""` check):

```go
	if opt.Sticky && opt.Auth != "" {
		return errors.New("-sticky cannot be combined with -A/--auth (the username is the session key)")
	}
```

- [ ] **Step 6: Run, verify pass** — `go test ./internal/runner/ -run TestStickyRejectsAuth -v` → PASS. Then `go build ./...`.
- [ ] **Step 7: Commit** — `git add common/options.go internal/runner/options.go internal/runner/validator.go internal/runner/validator_test.go && git commit -m "feat(runner): -sticky/-sticky-ttl flags and -A conflict gate"`

---

### Task 3: `sticky_pins` metric

**Files:**
- Modify: `internal/metrics/metrics.go`

**Interfaces:**
- Produces: `metrics.StickyPins *prometheus.GaugeVec` with label `pool` (`"http"`/`"socks"`).

- [ ] **Step 1: Add the gauge** to the `var (...)` block in `internal/metrics/metrics.go` and a `LabelPool` const in the const block:

```go
	LabelPool = "pool"
```

```go
	StickyPins = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "sticky_pins",
			Help:      "Current number of sticky session pins per pool",
		},
		[]string{LabelPool},
	)
```

- [ ] **Step 2: Build** — `go build ./...` → success (promauto registers on init).
- [ ] **Step 3: Commit** — `git add internal/metrics/metrics.go && git commit -m "feat(metrics): sticky_pins gauge"`

---

### Task 4: SOCKS `negotiate()` method `0x02` + key threading

**Files:**
- Modify: `internal/server/socks.go` (consts, `SocksServer.dial`/`rotate` signatures, `NewSocksServer`, `handle`, `negotiate`, new `readUserPassAuth`)
- Modify: `internal/server/socks_test.go:52` (dial closure signature) — and add a new test
- Modify: `internal/server/udp_associate_test.go:181` (rotate closure signature)

**Interfaces:**
- Produces:
  - consts `socksMethodUserPass = 0x02`, `socksAuthVersion = 0x01`, `socksAuthSuccess = 0x00`
  - `func (s *SocksServer) negotiate(conn net.Conn) (cmd byte, target string, sessionKey string, err error)`
  - `SocksServer.dial func(network, addr, key string) (net.Conn, error)`
  - `SocksServer.rotate func(key string) (string, error)`
  - `SocksServer.drop func(key string)` (nil-safe; nil in tests / when sticky off)

- [ ] **Step 1: Add a failing key-threading test** to `internal/server/socks_test.go`. It hand-rolls a `0x02` greeting with username `alice`, does RFC1929 auth, then CONNECT to an echo server, and asserts the `dial` closure received `key=="alice"`:

```go
func TestSocksServerUserPassKeyThreaded(t *testing.T) {
	echo := startEchoServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	keyCh := make(chan string, 1)
	s := &SocksServer{
		listener: ln,
		dial: func(network, addr, key string) (net.Conn, error) {
			select {
			case keyCh <- key:
			default:
			}
			return net.DialTimeout(network, addr, 5*time.Second)
		},
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// greeting offering ONLY username/password (0x02)
	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodUserPass}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatal(err)
	}
	if sel[1] != socksMethodUserPass {
		t.Fatalf("method: want 0x02, got %#x", sel[1])
	}

	// RFC1929 auth: VER=1, ULEN, "alice", PLEN, "pw"
	user, pass := []byte("alice"), []byte("pw")
	auth := []byte{socksAuthVersion, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatal(err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatal(err)
	}
	if authResp[0] != socksAuthVersion || authResp[1] != socksAuthSuccess {
		t.Fatalf("auth reply: got %#x %#x", authResp[0], authResp[1])
	}

	// CONNECT to echo (IPv4)
	host, port, _ := net.SplitHostPort(echo.Addr().String())
	ip := net.ParseIP(host).To4()
	p, _ := strconv.Atoi(port)
	req := []byte{socksVersion5, socksCmdConnect, 0x00, socksAtypIPv4}
	req = append(req, ip...)
	req = append(req, byte(p>>8), byte(p))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != socksReplySuccess {
		t.Fatalf("connect reply: got %#x", rep[1])
	}

	select {
	case got := <-keyCh:
		if got != "alice" {
			t.Fatalf("threaded key = %q, want alice", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial closure never called")
	}
}
```

Add `"strconv"` to the test imports.

- [ ] **Step 2: Update existing test closures** so the package compiles:
  - `internal/server/socks_test.go:52` — `dial: func(network, addr string)` → `dial: func(network, addr, key string) (net.Conn, error)` (body unchanged).
  - `internal/server/udp_associate_test.go:181` — `rotate: func() (string, error)` → `rotate: func(key string) (string, error)` (body unchanged).

- [ ] **Step 3: Run, verify fail** — `go test ./internal/server/ -run TestSocksServerUserPassKeyThreaded -v` → FAIL (compile error until Step 4 changes signatures).

- [ ] **Step 4: Implement** in `internal/server/socks.go`:

Add consts to the const block:

```go
	socksMethodUserPass = 0x02
	socksAuthVersion    = 0x01
	socksAuthSuccess    = 0x00
	socksAuthFailure    = 0x01
```

Change the struct field types:

```go
	dial   func(network, addr, key string) (net.Conn, error)
	rotate func(key string) (string, error)
	drop   func(key string)
```

Update `NewSocksServer`:

```go
func NewSocksServer(opt *common.Options, handler *Proxy) *SocksServer {
	return &SocksServer{
		opt:  opt,
		dial: func(network, addr, key string) (net.Conn, error) { return handler.dialViaSocksPool(network, addr, key) },
		rotate: func(key string) (string, error) {
			if opt.SocksSticky != nil && key != "" {
				return opt.SocksSticky.Get(key)
			}
			return opt.SocksProxyManager.Rotate(opt.SocksMethod)
		},
		drop: func(key string) {
			if opt.SocksSticky != nil {
				opt.SocksSticky.Drop(key)
			}
		},
	}
}
```

Update `handle` to thread the key:

```go
	cmd, target, sessionKey, err := s.negotiate(conn)
	if err != nil {
		log.Debugf("%s SOCKS5 handshake: %s", conn.RemoteAddr(), err)
		return
	}

	if cmd == socksCmdUDPAssociate {
		s.handleUDPAssociate(conn, sessionKey)
		return
	}

	upstream, err := s.dial("tcp", target, sessionKey)
```

Rewrite the method-selection portion of `negotiate` (keep the request-reading tail identical) and change its signature to return `sessionKey`:

```go
func (s *SocksServer) negotiate(conn net.Conn) (byte, string, string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", "", err
	}
	if header[0] != socksVersion5 {
		return 0, "", "", fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, "", "", err
	}

	// Prefer username/password (0x02) when offered so the username can serve as
	// the sticky session key; fall back to no-auth (0x00). cloakbrowser's
	// Chromium offers ONLY 0x02 when per-context creds are set.
	selected := byte(socksMethodNoAccept)
	switch {
	case containsByte(methods, socksMethodUserPass):
		selected = socksMethodUserPass
	case containsByte(methods, socksMethodNoAuth):
		selected = socksMethodNoAuth
	}
	if selected == socksMethodNoAccept {
		_, _ = conn.Write([]byte{socksVersion5, socksMethodNoAccept})
		return 0, "", "", errors.New("client offered no acceptable auth method")
	}
	if _, err := conn.Write([]byte{socksVersion5, selected}); err != nil {
		return 0, "", "", err
	}

	var sessionKey string
	if selected == socksMethodUserPass {
		user, err := readUserPassAuth(conn)
		if err != nil {
			return 0, "", "", err
		}
		sessionKey = user
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return 0, "", "", err
	}
	if req[0] != socksVersion5 {
		return 0, "", "", fmt.Errorf("unsupported SOCKS version %d", req[0])
	}
	if req[1] != socksCmdConnect && req[1] != socksCmdUDPAssociate {
		_ = reply(conn, socksReplyCmdNoSupp)
		return 0, "", "", fmt.Errorf("unsupported command %d", req[1])
	}

	host, err := readHost(conn, req[3])
	if err != nil {
		_ = reply(conn, socksReplyGeneralErr)
		return 0, "", "", err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return 0, "", "", err
	}

	return req[1], net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf)))), sessionKey, nil
}

// readUserPassAuth runs the RFC1929 username/password sub-negotiation, returning
// the username (the session key). The password is read but not validated — it is
// only a routing tag; the upstream pool is IP-whitelisted. A success reply is
// always sent.
func readUserPassAuth(conn net.Conn) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != socksAuthVersion {
		_, _ = conn.Write([]byte{socksAuthVersion, socksAuthFailure})
		return "", fmt.Errorf("unsupported auth version %d", head[0])
	}

	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return "", err
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return "", err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return "", err
	}

	if _, err := conn.Write([]byte{socksAuthVersion, socksAuthSuccess}); err != nil {
		return "", err
	}

	return string(user), nil
}
```

- [ ] **Step 5: Run, verify pass** — `go test ./internal/server/ -run 'TestSocksServer' -v` → all PASS (round-trip, rejects-bind, new user/pass key test).
- [ ] **Step 6: Commit** — `git add internal/server/socks.go internal/server/socks_test.go internal/server/udp_associate_test.go && git commit -m "feat(socks): RFC1929 username as sticky session key"`

---

### Task 5: SOCKS sticky dial (TCP + UDP ASSOCIATE)

**Files:**
- Modify: `internal/server/socks.go:233` (`dialViaSocksPool`)
- Modify: `internal/server/udp_associate.go` (`handleUDPAssociate`, `dialUpstreamUDPAssociate`)

**Interfaces:**
- Consumes: `Options.SocksSticky`, `SocksServer.rotate func(key string)`, `SocksServer.drop`.
- Produces: `func (p *Proxy) dialViaSocksPool(network, addr, key string) (net.Conn, error)`, `func (s *SocksServer) handleUDPAssociate(clientCtrl net.Conn, key string)`, `func (s *SocksServer) dialUpstreamUDPAssociate(key string) (net.Conn, *net.UDPAddr, error)`.

- [ ] **Step 1: Rewrite `dialViaSocksPool`** to be key-aware (TCP path):

```go
func (p *Proxy) dialViaSocksPool(network, addr, key string) (net.Conn, error) {
	attempts := p.Options.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	sticky := p.Options.SocksSticky != nil && key != ""

	var lastErr error
	for i := 0; i < attempts; i++ {
		var proxyAddr string
		var err error
		if sticky {
			proxyAddr, err = p.Options.SocksSticky.Get(key)
		} else {
			proxyAddr, err = p.Options.SocksProxyManager.Rotate(p.Options.SocksMethod)
		}
		if err != nil {
			return nil, err
		}

		conn, err := p.dialUpstream(proxyAddr, network, addr)
		if err == nil {
			log.Debugf("SOCKS5 CONNECT %s via %s", addr, proxyAddr)
			return conn, nil
		}
		lastErr = err
		log.Debugf("SOCKS5 CONNECT %s via %s failed: %s", addr, proxyAddr, err)

		if sticky {
			p.Options.SocksSticky.Drop(key)
		}
		if p.Options.RemoveOnErr {
			if rmErr := p.Options.SocksProxyManager.RemoveProxy(proxyAddr); rmErr != nil {
				log.Debug(rmErr)
			}
		}
		if !p.Options.RotateOnErr {
			break
		}
		if p.Options.MaxErrors >= 0 && i+1 >= p.Options.MaxErrors {
			break
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("connect to %s failed: exhausted upstream attempts", addr)
	}

	return nil, lastErr
}
```

- [ ] **Step 2: Thread the key through UDP ASSOCIATE** in `internal/server/udp_associate.go`. Change `handleUDPAssociate` signature and its upstream call, and drop the pin on failure:

```go
func (s *SocksServer) handleUDPAssociate(clientCtrl net.Conn, key string) {
	bindIP := listenIP(clientCtrl.LocalAddr())

	clientRelay, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		log.Errorf("%s SOCKS5 UDP: open client relay: %s", clientCtrl.RemoteAddr(), err)
		_ = reply(clientCtrl, socksReplyGeneralErr)
		return
	}
	defer clientRelay.Close()

	upstreamCtrl, upstreamRelayAddr, err := s.dialUpstreamUDPAssociate(key)
	if err != nil {
		if s.drop != nil {
			s.drop(key)
		}
		log.Debugf("%s SOCKS5 UDP associate: %s", clientCtrl.RemoteAddr(), err)
		_ = reply(clientCtrl, socksReplyGeneralErr)
		return
	}
	defer upstreamCtrl.Close()
	// ... rest unchanged ...
```

And change `dialUpstreamUDPAssociate` to take the key and use the key-aware rotate:

```go
func (s *SocksServer) dialUpstreamUDPAssociate(key string) (net.Conn, *net.UDPAddr, error) {
	proxyAddr, err := s.rotate(key)
	if err != nil {
		return nil, nil, err
	}
	// ... rest unchanged ...
```

- [ ] **Step 3: Run full server tests** — `go test ./internal/server/ -v` → all PASS (existing UDP round-trip test still green; its `rotate` closure now takes `key` and ignores it).
- [ ] **Step 4: Commit** — `git add internal/server/socks.go internal/server/udp_associate.go && git commit -m "feat(socks): pin TCP + UDP ASSOCIATE to session upstream"`

---

### Task 6: HTTP sticky (Proxy-Authorization username)

**Files:**
- Modify: `internal/server/handler.go` (`onRequest`, `connectDial`, new `proxyAuthUser`, new `pickProxy`)
- Test: `internal/server/handler_test.go` (add two tests)

**Interfaces:**
- Produces: `func proxyAuthUser(req *http.Request) string`, `func (p *Proxy) pickProxy(key string) string`.

- [ ] **Step 1: Add failing tests** to `internal/server/handler_test.go`:

```go
func TestProxyAuthUser(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://x/", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("sess-42:pw")))
	if got := proxyAuthUser(req); got != "sess-42" {
		t.Fatalf("proxyAuthUser = %q, want sess-42", got)
	}

	bare, _ := http.NewRequest("GET", "http://x/", nil)
	if got := proxyAuthUser(bare); got != "" {
		t.Fatalf("no-auth proxyAuthUser = %q, want empty", got)
	}
}

func TestPickProxyStickyReuse(t *testing.T) {
	f, err := os.CreateTemp("", "mubeng-http-sticky-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString("http://a:1\nhttp://b:2\nhttp://c:3\n")
	f.Close()
	pm, err := proxymanager.New(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	sticky := proxymanager.NewSticky(pm, "random", time.Minute)
	defer sticky.Close()

	p := &Proxy{Options: &common.Options{ProxyManager: pm, Method: "random", HTTPSticky: sticky, Rotate: 1}}

	first := p.pickProxy("alice")
	for i := 0; i < 10; i++ {
		if got := p.pickProxy("alice"); got != first {
			t.Fatalf("sticky pick drifted: %q != %q", got, first)
		}
	}
	if p.pickProxy("") == "" {
		// empty key must still return a proxy (rotate path)
		t.Fatalf("empty-key pick returned no proxy")
	}
}
```

Add `"encoding/base64"` and `"time"` to the test imports if not present (`os`, `common`, `proxymanager` already imported).

- [ ] **Step 2: Run, verify fail** — `go test ./internal/server/ -run 'TestProxyAuthUser|TestPickProxyStickyReuse' -v` → FAIL (undefined: proxyAuthUser / pickProxy).

- [ ] **Step 3: Implement** in `internal/server/handler.go`. Add helpers:

```go
// proxyAuthUser extracts the username from a Basic Proxy-Authorization header,
// which serves as the HTTP sticky session key. Returns "" when absent or
// malformed.
func proxyAuthUser(req *http.Request) string {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return ""
	}
	dec, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	creds := string(dec)
	if i := strings.IndexByte(creds, ':'); i >= 0 {
		return creds[:i]
	}
	return creds
}

// pickProxy selects the upstream for a request. With sticky enabled and a
// non-empty key it returns the session-pinned upstream; otherwise it falls back
// to the counter-based rotateProxy path.
func (p *Proxy) pickProxy(key string) string {
	if p.Options.HTTPSticky != nil && key != "" {
		proxy, err := p.Options.HTTPSticky.Get(key)
		if err != nil {
			log.Fatalf("Could not pin proxy IP: %s", err)
		}
		return proxy
	}
	return p.rotateProxy()
}
```

In `onRequest`, capture the key once (before the goroutine) and use `pickProxy` + drop-on-error. Replace `proxy := p.rotateProxy()` (line ~60) with `proxy := p.pickProxy(sessionKey)`, where `sessionKey := proxyAuthUser(req)` is computed just before `go func(r *http.Request) {`. In the `RemoveOnErr` failure branch (after `p.removeProxy(proxy)`), add:

```go
					if p.Options.HTTPSticky != nil && sessionKey != "" {
						p.Options.HTTPSticky.Drop(sessionKey)
					}
```

(place it right after the `if p.Options.RemoveOnErr { ... }` block so the pin drops on every retriable error, not only when RemoveOnErr is set).

In `connectDial`, use the key from the CONNECT request:

```go
func (p *Proxy) connectDial(req *http.Request, network, addr string) (net.Conn, error) {
	attempts := p.Options.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	sessionKey := proxyAuthUser(req)

	var lastErr error
	for i := 0; i < attempts; i++ {
		proxyAddr := p.pickProxy(sessionKey)
		conn, err := p.dialUpstream(proxyAddr, network, addr)
		if err == nil {
			log.Debugf("%s CONNECT %s via %s", req.RemoteAddr, addr, proxyAddr)
			return conn, nil
		}
		lastErr = err
		log.Debugf("%s CONNECT %s via %s failed: %s", req.RemoteAddr, addr, proxyAddr, err)

		if p.Options.HTTPSticky != nil && sessionKey != "" {
			p.Options.HTTPSticky.Drop(sessionKey)
		}
		if p.Options.RemoveOnErr {
			p.removeProxy(proxyAddr)
		}
		if !p.Options.RotateOnErr {
			break
		}
		if p.Options.MaxErrors >= 0 && i+1 >= p.Options.MaxErrors {
			break
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("connect to %s failed: exhausted upstream attempts", addr)
	}
	return nil, lastErr
}
```

Ensure `encoding/base64` and `strings` are imported in `handler.go` (both already are).

- [ ] **Step 4: Run, verify pass** — `go test ./internal/server/ -run 'TestProxyAuthUser|TestPickProxyStickyReuse' -v` → PASS. Then `go test ./internal/server/ -v` (regression) → PASS.
- [ ] **Step 5: Commit** — `git add internal/server/handler.go internal/server/handler_test.go && git commit -m "feat(http): Proxy-Authorization username as sticky session key"`

---

### Task 7: Server wiring — construct stores, metrics callback, shutdown

**Files:**
- Modify: `internal/server/server.go`

**Interfaces:**
- Consumes: `proxymanager.NewSticky`, `metrics.StickyPins`, `Options.Sticky/StickyTTL/HTTPSticky/SocksSticky`.

- [ ] **Step 1: Add sticky construction** in `server.go` `Run`, immediately after the metrics block (after the `if opt.Metrics != "" { ... }` block, before `log.Infof("%d proxies loaded", ...)`):

```go
	if opt.Sticky {
		opt.HTTPSticky = proxymanager.NewSticky(opt.ProxyManager, opt.Method, opt.StickyTTL)
		defer opt.HTTPSticky.Close()

		if opt.SocksProxyManager != nil {
			opt.SocksSticky = proxymanager.NewSticky(opt.SocksProxyManager, opt.SocksMethod, opt.StickyTTL)
			defer opt.SocksSticky.Close()
		}

		if metricsEnabled {
			opt.HTTPSticky.SetOnChange(func(n int) {
				metrics.StickyPins.WithLabelValues("http").Set(float64(n))
			})
			if opt.SocksSticky != nil {
				opt.SocksSticky.SetOnChange(func(n int) {
					metrics.StickyPins.WithLabelValues("socks").Set(float64(n))
				})
			}
		}

		log.Infof("Sticky sessions enabled (TTL %s)", opt.StickyTTL)
	}
```

Add `"github.com/mubeng/mubeng/internal/proxymanager"` to the imports (metrics is already imported).

- [ ] **Step 2: Build + full test suite** — `go build ./...` then `go test ./...` → all PASS.
- [ ] **Step 3: Commit** — `git add internal/server/server.go && git commit -m "feat(server): wire sticky stores, metrics, shutdown"`

---

### Task 8: Docs — usage text

**Files:**
- Modify: `common/vars.go` (Usage string)
- Modify: `README.md` (flag table)

- [ ] **Step 1: Add usage lines** in `common/vars.go`, right after the `--no-mitm` block (after line 63):

```
        --sticky                     Pin one upstream exit IP per session key
                                     (SOCKS RFC1929 / HTTP Proxy-Authorization
                                     username). Default off. Not usable with -A.
        --sticky-ttl <DUR>           Idle TTL for sticky pins (default: 10m)
```

- [ ] **Step 2: Add README rows** to the flag table near the `--rotate-on-error` row (`README.md` ~line 147):

```
|     --sticky                    | Pin one upstream exit IP per session key (username). Off by default. |
|     --sticky-ttl `<DUR>`        | Idle TTL for sticky pins (default: 10m).                     |
```

- [ ] **Step 3: Commit** — `git add common/vars.go README.md && git commit -m "docs: document -sticky/-sticky-ttl"`

---

## Self-Review

- **Spec coverage:** Session key SOCKS (Task 4) + HTTP (Task 6); Sticky store w/ TTL, Drop, janitor, Len, onChange (Task 1); two stores on Options + construction (Tasks 2, 7); threading TCP/UDP/HTTP (Tasks 5, 6); CLI flags + `-A` gate (Task 2); metric (Tasks 3, 7); preserved invariants (retry/error semantics kept verbatim in Tasks 5–6); docs (Task 8). Out-of-scope items (ProxyRack params, persistence, MITM HTTPS) intentionally untouched.
- **Placeholders:** none — every step has concrete code/commands.
- **Type consistency:** `Get/Drop/Len/Close/SetOnChange/NewSticky` signatures identical across Tasks 1/5/6/7; `dial(network,addr,key)`, `rotate(key)`, `drop(key)`, `negotiate → (byte,string,string,error)`, `handleUDPAssociate(conn,key)`, `dialUpstreamUDPAssociate(key)` consistent across Tasks 4/5; `proxyAuthUser`/`pickProxy` consistent in Task 6.
